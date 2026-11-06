// 探针#13/#14/#15:内核驱动读通道核验。
// 命名裁定#31:驱动形态无关——子命令、参数与事件名一律用中性 drv,不绑定任何
// 具体驱动类型(KPM/.ko 等皆可);具体驱动的 ABI 只以 abi 字段值如实上报。
//
// 实测历程:2026-11-06 基线确认死调用 18/60 被钩(返回 EINVAL/ENODEV ≠ ENOSYS),
// 而旧握手猜测矩阵全灭;遂对测试驱动(ditpro-kpm-read/write v1.4.2,ELF 符号完好)
// 做静态逆向,钉死其真实 ABI 如下:
//   触达   syscall(18, 0x268, req, cmd)     18=lookup_dcookie(fp_hook_syscalln,3 参)
//   0x400 读  req[40B]: pid:u32@+0x00 | addr:u64@+0x08 | buf:u64@+0x10
//                       | size:u64@+0x18 | flags:u32@+0x20
//             返回 1=成功 0=失败;数据 copy_to_user 进 buf
//   0x100 模块基址 req[24B]: pid:u32@+0x00 | name_ptr:u64@+0x08 | base:u64@+0x10(回写)
//   另有 0x401 批量读 / 0x50 查 pid / 0x200 写 / 0x40,0x41 进程隐藏
// 安全:本探针只触碰 0x400/0x100 读类命令;写与隐藏永不测试;
//       每次系统调用都在 fork 出的子进程里执行,子进程崩了父进程照常出报告。
use super::memio::{find_pid_by_pkg, read_maps, Reader};
use crate::{emit, jh, jn, js};

const NR_DCOOKIE: u64 = 18; // lookup_dcookie(asm-generic 号)
const NR_QUOTACTL: u64 = 60; // quotactl(该驱动同时钩此号做触摸模拟,与采集无关)
const MAGIC_FD: u64 = 0x268; // ditpro arg0 魔数
const CMD_READ: u64 = 0x400;
const CMD_MODBASE: u64 = 0x100;
const ABI_TAG: &str = "ditpro-kpm-rw-1.4.2";

#[repr(C)]
struct ReadReq {
    pid: u32,
    _pad0: u32,
    addr: u64,  // 目标虚拟地址
    buf: u64,   // 用户态接收缓冲
    size: u64,
    flags: u32, // 读模式,默认 0
    _pad1: u32,
}

#[repr(C)]
struct ModBaseReq {
    pid: u32,
    _pad0: u32,
    name_ptr: u64, // 指向 NUL 结尾的模块名(如 "libc.so")
    base: u64,     // 内核回写
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn report_child_died(tag: &str, sig: i32) {
    emit(&[("k", js("drv_child_died")), ("step", js(tag)), ("signal", jn(sig))]);
}

fn guarded<F: FnOnce()>(tag: &str, f: F) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        std::io::Write::flush(&mut std::io::stdout()).ok();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFSIGNALED(st) {
        report_child_died(tag, libc::WTERMSIG(st));
    }
}

fn raw_sys(nr: u64, a1: u64, a2: u64, a3: u64) -> (i64, i32) {
    let r = unsafe { libc::syscall(nr as libc::c_long, a1, a2, a3) };
    let e = if r == -1 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    (r as i64, e)
}

// 经驱动读 size 字节;返回 (ret, errno, 读到的字节)
fn drv_read(pid: u32, addr: u64, size: u64, flags: u32) -> (i64, i32, Vec<u8>) {
    let mut out = vec![0u8; size as usize];
    let req = ReadReq {
        pid, _pad0: 0, addr,
        buf: out.as_mut_ptr() as u64,
        size, flags, _pad1: 0,
    };
    let (r, e) = raw_sys(NR_DCOOKIE, MAGIC_FD, &req as *const ReadReq as u64, CMD_READ);
    (r, e, out)
}

pub fn run(pkg: Option<&str>) {
    emit(&[("k", js("drv_begin"))]);

    // 步骤 0(#13):死 syscall 基线——通用在场探测,与具体驱动无关。
    // ENOSYS(38) = 没人钩;EINVAL(22)/ENODEV(19) 等 = 钩子在。
    for nr in [NR_DCOOKIE, NR_QUOTACTL] {
        let tag = format!("baseline_{nr}");
        guarded(&tag, move || {
            let (r, e) = raw_sys(nr, 0, 0, 0);
            emit(&[("k", js("drv_baseline")), ("nr", jn(nr)),
                   ("ret", jn(r)), ("errno", jn(e)),
                   ("hooked_hint", jn((e != 38) as u8))]);
        });
    }

    // 步骤 1(#14):ABI 自读自证——从自己进程读一段已知内容,端到端闭环。
    // 不依赖任何目标进程:能读回自己的 canary 即证明触达链路与结构布局全对。
    let canary: [u8; 16] = [0xe4, 0xbd, 0xa0, 0xe7, 0xbe, 0xbd, 0xe5, 0x8c,
                            0x96, 0x00, 0x11, 0x06, 0x5a, 0xa5, 0xde, 0xad];
    for flags in [0u32, 1] {
        let tag = format!("self_read_f{flags}");
        guarded(&tag, move || {
            let mypid = unsafe { libc::getpid() } as u32;
            let (r, e, out) = drv_read(mypid, canary.as_ptr() as u64, 16, flags);
            let matched = out == canary;
            emit(&[("k", js("drv_self_read")), ("abi", js(ABI_TAG)),
                   ("flags", jn(flags)),
                   ("ret", jn(r)), ("errno", jn(e)),
                   ("bytes_match", jn(matched as u8)),
                   ("out_head", js(&hex(&out)))]);
        });
    }

    // 步骤 2(#15):自进程模块基址——挑一个自身已映射的 .so 做验证。
    // (musl 静态构建无任何映射库,此步自动跳过并说明)
    let my_maps = read_maps(unsafe { libc::getpid() });
    let lib = my_maps.iter().find(|m| {
        m.path.ends_with(".so") && m.perm.starts_with('r')
    }).cloned();
    match lib {
        Some(ent) => {
            let name = ent.path.rsplit('/').next().unwrap_or("").to_string();
            guarded("modbase_self", move || {
                let cname = std::ffi::CString::new(name.clone()).unwrap();
                let mut req = ModBaseReq {
                    pid: unsafe { libc::getpid() } as u32, _pad0: 0,
                    name_ptr: cname.as_ptr() as u64, base: 0,
                };
                let (r, e) = raw_sys(NR_DCOOKIE, MAGIC_FD,
                                     &mut req as *mut ModBaseReq as u64, CMD_MODBASE);
                emit(&[("k", js("drv_modbase")), ("abi", js(ABI_TAG)),
                       ("lib", js(&name)),
                       ("ret", jn(r)), ("errno", jn(e)),
                       ("base", jh(req.base)),
                       ("maps_floor", jh(ent.start)),
                       ("base_le_maps_floor", jn((req.base > 0 && req.base <= ent.start) as u8))]);
            });
        }
        None => emit(&[("k", js("drv_modbase_skip")),
                       ("reason", js("no file-backed .so in self maps (static build)"))]),
    }

    // 步骤 3(#13 交叉):给了包名就做一次跨进程读——读目标 libart.so 头 16B,
    // 必须看到 ELF 魔数,且与 process_vm_readv 双通道一致。
    if let Some(pkg) = pkg {
        let pids = find_pid_by_pkg(pkg);
        if pids.is_empty() {
            emit(&[("k", js("drv_target_error")), ("detail", js("package not running")), ("pkg", js(pkg))]);
        } else {
            let pid = pids[0];
            let maps = read_maps(pid);
            let art = maps.iter().find(|m| m.path.ends_with("/libart.so")).cloned();
            match art {
                Some(ent) => {
                    let base = ent.start;
                    guarded("target_read", move || {
                        let (r, e, out) = drv_read(pid as u32, base, 16, 0);
                        let is_elf = out[..4] == [0x7f, b'E', b'L', b'F'];
                        emit(&[("k", js("drv_target_read")), ("abi", js(ABI_TAG)),
                               ("pid", jn(pid)), ("libart_base", jh(base)),
                               ("ret", jn(r)), ("errno", jn(e)),
                               ("elf_magic", jn(is_elf as u8)),
                               ("out_head", js(&hex(&out)))]);
                    });
                    // 双通道互证:同一地址 process_vm_readv 再读一遍
                    let via_vm = Reader::new(pid).read(base, 16);
                    match via_vm {
                        Some(v) => emit(&[("k", js("drv_xcheck")),
                                          ("addr", jh(base)),
                                          ("vmread_head", js(&hex(&v)))]),
                        None => emit(&[("k", js("drv_xcheck")),
                                       ("addr", jh(base)),
                                       ("err", js("process_vm_readv failed"))]),
                    }
                }
                None => emit(&[("k", js("drv_target_error")),
                               ("detail", js("libart.so not mapped in target")), ("pkg", js(pkg))]),
            }
        }
    }

    emit(&[("k", js("drv_end"))]);
}
