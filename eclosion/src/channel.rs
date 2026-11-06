// 读通道抽象:真驱动(syscall)/ 模拟文件(file)双实现。
// 内核读写作业路径唯一(裁定:无降级无备选)——通道只换"读原语",不降级为 ptrace/注入。
// 模拟通道仅服务桌面自走通(立项书 §8 出口:假驱动 profile + 假内存图),设备上禁用。

use crate::probe::memio::MapEnt;
use crate::profile::{DriverProfile, Layout, Transport};
use std::io::{Read, Seek, SeekFrom};

pub trait Channel: Send + Sync {
    /// 读目标进程 [addr, addr+len);成功以字节为准(ABI 注:返回值不作数,由调用方校验内容)
    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, String>;
    /// 目标进程 maps 视图(真机:/proc/<pid>/maps;模拟:profile 给的 maps 文本)
    fn maps(&self, pid: u32) -> Result<Vec<MapEnt>, String>;
    /// 通道自检(握手):对自体金丝雀做一次真实读并逐字节比对
    fn handshake(&self) -> Result<(), String>;
    /// 能力通道(回读实际生效,写 manifest;不是请求值)
    fn channels(&self) -> Vec<String>;
    /// (name, version) 回读——manifest.driver 事实字段
    fn driver_id(&self) -> (String, String);
}

pub fn build_channel(p: &DriverProfile) -> Result<Box<dyn Channel>, String> {
    match &p.transport {
        Transport::Syscall { nr, magic_arg0, cmd_pos } => Ok(Box::new(SyscallChannel {
            nr: *nr,
            magic: *magic_arg0,
            cmd_pos: *cmd_pos,
            read: p.ops.read.as_ref().map(|o| (o.cmd, o.layout)),
            mod_base: p.ops.mod_base.as_ref().map(|o| (o.cmd, o.layout)),
            name: p.name.clone(),
            version: p.version.clone(),
            channels: p.channels(),
        })),
        Transport::File { image, maps, pid } => {
            let map_list = parse_maps_text(&std::fs::read_to_string(maps).map_err(|e| format!("模拟 maps 读取失败 {maps}: {e}"))?);
            Ok(Box::new(FileChannel {
                image_path: image.clone(),
                maps: map_list,
                pid: *pid,
                name: p.name.clone(),
                version: p.version.clone(),
                channels: p.channels(),
            }))
        }
    }
}

/// maps 文本解析(/proc/<pid>/maps 同款格式)
pub fn parse_maps_text(text: &str) -> Vec<MapEnt> {
    text.lines().filter_map(|l| {
        let mut parts = l.split_whitespace();
        let range = parts.next()?;
        let (a, b) = range.split_once('-')?;
        let perm = parts.next()?.to_string();
        let path = l.split_whitespace().nth(5).unwrap_or("").to_string();
        Some(MapEnt {
            start: u64::from_str_radix(a, 16).ok()?,
            end: u64::from_str_radix(b, 16).ok()?,
            perm,
            path,
        })
    }).collect()
}

// ─── 真驱动通道(死 syscall 钩;请求布局由 profile 选定) ───

struct SyscallChannel {
    nr: u16,
    magic: u64,
    cmd_pos: u8,
    read: Option<(u32, Layout)>,
    #[allow(dead_code)] // 模块基址能力在册(profile ops),采集路径暂不消费
    mod_base: Option<(u32, Layout)>,
    name: String,
    version: String,
    channels: Vec<String>,
}

impl SyscallChannel {
    fn raw(&self, req_ptr: u64, cmd: u32) -> i64 {
        // cmd_pos: cmd 落在第几个参数(0 起);ditpro 实证 = 第 2 参(syscall(18, 0x268, req, cmd))
        let (a0, a1, a2) = match self.cmd_pos {
            0 => (cmd as u64, req_ptr, 0),
            1 => (self.magic, cmd as u64, 0),
            _ => (self.magic, req_ptr, cmd as u64),
        };
        unsafe { libc::syscall(self.nr as libc::c_long, a0, a1, a2) as i64 }
    }
}

static CANARY: &[u8] = b"\xe7\xbe\xbd\xe5\x8c\x96"; // "羽化"——自检金丝雀

impl Channel for SyscallChannel {
    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        let (cmd, layout) = self.read.ok_or("profile 无 read op")?;
        match layout {
            Layout::Read40V1 => {
                #[repr(C)]
                struct Req { pid: u32, _p0: u32, addr: u64, buf: u64, size: u64, flags: u32, _p1: u32 }
                let mut buf = vec![0u8; len];
                let req = Req { pid, _p0: 0, addr, buf: buf.as_mut_ptr() as u64, size: len as u64, flags: 0, _p1: 0 };
                let r = self.raw(&req as *const Req as u64, cmd);
                if r == 0 { Ok(buf) } else { Err(format!("驱动读失败 ret={r}")) }
            }
            _ => Err(format!("read 布局 {layout:?} 未实现")),
        }
    }

    fn maps(&self, pid: u32) -> Result<Vec<MapEnt>, String> {
        Ok(crate::probe::memio::read_maps(pid as i32))
    }

    fn handshake(&self) -> Result<(), String> {
        let got = self.read(std::process::id(), CANARY.as_ptr() as u64, CANARY.len())?;
        if got == CANARY { Ok(()) } else { Err("握手失败:自体金丝雀读回字节不符".into()) }
    }

    fn channels(&self) -> Vec<String> { self.channels.clone() }
    fn driver_id(&self) -> (String, String) { (self.name.clone(), self.version.clone()) }
}

// ─── 模拟通道(桌面自走通):内存映像文件 + maps 文本 ───

struct FileChannel {
    image_path: String,
    maps: Vec<MapEnt>,
    #[allow(dead_code)] // 假目标 pid 由引擎侧 pid_hint 消费;通道本体忽略 pid
    pid: u32,
    name: String,
    version: String,
    channels: Vec<String>,
}

impl Channel for FileChannel {
    fn read(&self, _pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        // 平坦映像约定:最低图起始 VA = 文件偏移 0,文件偏移 = addr - min(map.start)
        let base = self.maps.iter().map(|m| m.start).min().ok_or("模拟通道 maps 为空")?;
        let in_any = self.maps.iter().any(|m| m.start <= addr && addr + len as u64 <= m.end);
        if !in_any { return Err(format!("模拟读越界: 0x{addr:x}+{len}")); }
        let mut f = std::fs::File::open(&self.image_path).map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(addr - base)).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).map_err(|e| format!("模拟读失败: {e}"))?;
        Ok(buf)
    }

    fn maps(&self, _pid: u32) -> Result<Vec<MapEnt>, String> { Ok(self.maps.clone()) }

    fn handshake(&self) -> Result<(), String> {
        // 模拟通道自检:maps 非空 + 映像可读
        if self.maps.is_empty() { return Err("模拟通道 maps 为空".into()); }
        std::fs::File::open(&self.image_path).map_err(|e| format!("模拟映像不可读: {e}"))?;
        Ok(())
    }

    fn channels(&self) -> Vec<String> { self.channels.clone() }
    fn driver_id(&self) -> (String, String) { (self.name.clone(), self.version.clone()) }
}
