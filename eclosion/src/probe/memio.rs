// 目标进程内存读取与 maps 解析。
// 双通道互证:process_vm_readv(主)与 /proc/pid/mem pread(备)。
// root + CAP_SYS_PTRACE 下 process_vm_readv 通过 PTRACE_MODE_ATTACH_REALCREDS
// 检查而无需真正附着——目标 TracerPid 保持 0,零痕迹(探针会前后回读验证)。
use crate::{emit, jn, js};
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone)]
pub struct MapEnt { pub start: u64, pub end: u64, pub perm: String, pub path: String }

pub fn read_maps(pid: i32) -> Vec<MapEnt> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    text.lines().filter_map(|l| {
        let mut parts = l.split_whitespace();
        let range = parts.next()?;
        let (a, b) = range.split_once('-')?;
        let perm = parts.next()?.to_string();
        let path = if l.split_whitespace().count() >= 6 {
            l.split_whitespace().nth(5).unwrap_or("").to_string()
        } else { String::new() };
        Some(MapEnt {
            start: u64::from_str_radix(a, 16).ok()?,
            end: u64::from_str_radix(b, 16).ok()?,
            perm,
            path,
        })
    }).collect()
}

pub struct Reader { pub pid: i32 }

impl Reader {
    pub fn new(pid: i32) -> Reader { Reader { pid } }

    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: len };
        let remote = libc::iovec { iov_base: addr as *mut _, iov_len: len };
        let n = unsafe {
            libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0)
        };
        if n == len as isize { Some(buf) } else { self.read_via_memfile(addr, len) }
    }

    fn read_via_memfile(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut f = std::fs::File::open(format!("/proc/{}/mem", self.pid)).ok()?;
        f.seek(SeekFrom::Start(addr)).ok()?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    pub fn u64_at(&self, addr: u64) -> Option<u64> {
        self.read(addr, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u32_at(&self, addr: u64) -> Option<u32> {
        self.read(addr, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    // libc++ std::string 双布局解析(SSO 与长串)
    pub fn cxx_string_at(&self, addr: u64) -> Option<String> {
        let b = self.read(addr, 24)?;
        let w0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let (ptr, len) = if w0 & 1 == 0 {
            (addr + 1, (w0 >> 1) as usize) // 短串内联
        } else {
            let cap = w0 >> 1;
            let len = u64::from_le_bytes(b[8..16].try_into().unwrap()) as usize;
            let ptr = u64::from_le_bytes(b[16..24].try_into().unwrap());
            if len == 0 || len > 4096 || (cap as usize) < len { return None; }
            (ptr, len)
        };
        if len == 0 || len > 4096 { return None; }
        let bytes = self.read(ptr, len)?;
        if !bytes.iter().all(|&c| (0x20..0x7f).contains(&c)) { return None; }
        String::from_utf8(bytes).ok()
    }

    pub fn is_readable(&self, addr: u64) -> bool {
        self.read(addr, 1).is_some()
    }
}

pub fn tracer_pid(pid: i32) -> i64 {
    std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default()
        .lines().find(|l| l.starts_with("TracerPid:"))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(-1)
}

// 双通道互证:抽几个地址两路各读一次,字节必须一致
pub fn cross_check(r: &Reader, samples: &[u64]) {
    let mut f = match std::fs::File::open(format!("/proc/{}/mem", r.pid)) {
        Ok(f) => f,
        Err(e) => { emit(&[("k", js("mem_xcheck")), ("ok", jn(0u8)), ("err", js(&e.to_string()))]); return; }
    };
    let mut all_ok = true;
    for &a in samples {
        let via_vm = r.read(a, 64);
        let mut buf = vec![0u8; 64];
        let via_mem = f.seek(SeekFrom::Start(a)).and_then(|_| f.read_exact(&mut buf)).ok().map(|_| buf.clone());
        match (via_vm, via_mem) {
            (Some(x), Some(y)) => if x != y { all_ok = false; }
            _ => {}
        }
    }
    emit(&[("k", js("mem_xcheck")), ("ok", jn(all_ok as u8)), ("samples", jn(samples.len()))]);
}

pub fn find_pid_by_pkg(pkg: &str) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(pid) = name.parse::<i32>() {
                if let Ok(cmd) = std::fs::read_to_string(format!("/proc/{pid}/cmdline")) {
                    let cmd = cmd.trim_end_matches('\0');
                    if cmd == pkg { out.push(pid); }
                }
            }
        }
    }
    out
}
