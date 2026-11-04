// 探针#13/#14/#15:ditPro KPM 通道核验。
// 存档事实(SKILL 补丁链):钩 lookup_dcookie(18)/quotactl(60) 双死 syscall,
// "nomi" 握手 + 指纹令牌(reply 128B),cmd@+0x280,args@+0x250..+0x270,
// 0x400 读/0x401 批量读/0x50 查 pid/0x100 模块基址;残余 0x10/0x920。
// 未钉死处(调用约定、参数槽序、指纹语义)由本探针矩阵实测。
// 安全:只测读/查询类;写(0x200)与隐藏(0x40/41)不测;每次调用在 fork 出的
// 子进程里执行,子进程崩了父进程照常出报告。
use crate::{emit, jh, jn, js};

const REQ_LEN: usize = 0x400;
const OFF_ARGS: usize = 0x250;
const OFF_CMD: usize = 0x280;
const SYSCALLS: [u64; 2] = [18, 60]; // lookup_dcookie / quotactl(asm-generic 号)

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn report_child_died(tag: &str, sig: i32) {
    emit(&[("k", js("kpm_child_died")), ("step", js(tag)), ("signal", jn(sig))]);
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

fn raw_sys(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> (i64, i32) {
    let r = unsafe { libc::syscall(nr as libc::c_long, a1, a2, a3, a4, a5, a6) };
    let e = if r == -1 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    (r as i64, e)
}

pub fn run() {
    emit(&[("k", js("kpm_begin"))]);

    // 步骤 0:死 syscall 基线——ENOSYS(38) 说明没人钩;别的返回值 = 钩子在
    for nr in SYSCALLS {
        let tag = format!("baseline_{nr}");
        guarded(&tag, move || {
            let (r, e) = raw_sys(nr, 0, 0, 0, 0, 0, 0);
            emit(&[("k", js("kpm_baseline")), ("nr", jn(nr)),
                   ("ret", jn(r)), ("errno", jn(e)),
                   ("hooked_hint", jn((e != 38) as u8))]);
        });
    }

    // 步骤 1(#13):握手矩阵——三种调用约定 × 两个 syscall 号
    for nr in SYSCALLS {
        for style in ["A", "B", "C"] {
            let tag = format!("hs_{nr}_{style}");
            let style = style.to_string();
            guarded(&tag, move || {
                let mut buf = vec![0u8; REQ_LEN];
                let style_c = style.clone();
                let (r, e) = match style_c.as_str() {
                    // A: 单参 = 请求buf,"nomi" 在 buf+0
                    "A" => {
                        buf[0..4].copy_from_slice(b"nomi");
                        raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0)
                    }
                    // B: 单参 = 请求buf,"nomi" 在 args 区(+0x250)
                    "B" => {
                        buf[OFF_ARGS..OFF_ARGS + 4].copy_from_slice(b"nomi");
                        raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0)
                    }
                    // C: 双参 = magic 指针 + buf 指针
                    _ => {
                        let magic = b"nomi\0";
                        raw_sys(nr, magic.as_ptr() as u64, buf.as_mut_ptr() as u64, 0, 0, 0, 0)
                    }
                };
                let changed = buf.iter().filter(|&&b| b != 0).count();
                emit(&[("k", js("kpm_handshake")), ("nr", jn(nr)), ("style", js(&style)),
                       ("ret", jn(r)), ("errno", jn(e)),
                       ("buf_nonzero", jn(changed)),
                       ("buf_head", js(&hex(&buf[..128])))]);
            });
        }
    }

    // 步骤 2(#13 续):pid-of 自证(0x50 查自己)
    for nr in SYSCALLS {
        let tag = format!("pidof_{nr}");
        guarded(&tag, move || {
            let mut buf = vec![0u8; REQ_LEN];
            buf[OFF_CMD..OFF_CMD + 8].copy_from_slice(&0x50u64.to_le_bytes());
            let name = b"eclosion-probe\0";
            buf[OFF_ARGS..OFF_ARGS + name.len()].copy_from_slice(name);
            let (r, e) = raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
            emit(&[("k", js("kpm_pidof")), ("nr", jn(nr)),
                   ("ret", jn(r)), ("errno", jn(e)),
                   ("mypid", jn(unsafe { libc::getpid() })),
                   ("buf_head", js(&hex(&buf[..64]))),
                   ("ret_as_pid_match", jn((r == unsafe { libc::getpid() } as i64) as u8))]);
        });
    }

    // 步骤 3(#13 续):0x400 自读自证——四种参数槽序矩阵
    for nr in SYSCALLS {
        for layout in 0..4u8 {
            let tag = format!("read_{nr}_l{layout}");
            guarded(&tag, move || {
                // 标记页:自己进程里放一串已知字节
                let marker: [u8; 4096] = std::array::from_fn(|i| (i as u8) ^ 0x5a);
                let maddr = marker.as_ptr() as u64;
                let mypid = unsafe { libc::getpid() } as u64;
                let mut buf = vec![0u8; REQ_LEN + 4096];
                let out_off = REQ_LEN; // 读出数据放请求 buf 后面一页
                let out_addr = unsafe { buf.as_mut_ptr().add(out_off) } as u64;
                let args: [u64; 4] = match layout {
                    0 => [mypid, maddr, out_addr, 4096],
                    1 => [maddr, out_addr, 4096, mypid],
                    2 => [mypid, maddr, 4096, out_addr],
                    _ => [maddr, 4096, out_addr, mypid],
                };
                for (i, a) in args.iter().enumerate() {
                    buf[OFF_ARGS + i * 8..OFF_ARGS + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
                }
                buf[OFF_CMD..OFF_CMD + 8].copy_from_slice(&0x400u64.to_le_bytes());
                let (r, e) = raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
                let matched = buf[out_off..out_off + 4096] == marker[..];
                emit(&[("k", js("kpm_read")), ("nr", jn(nr)), ("layout", jn(layout)),
                       ("ret", jn(r)), ("errno", jn(e)),
                       ("bytes_match", jn(matched as u8)),
                       ("out_head", js(&hex(&buf[out_off..out_off + 32])))]);
            });
        }
    }

    // 步骤 4(#14):0x401 批量读——两种条目布局
    for nr in SYSCALLS {
        for style in 0..2u8 {
            let tag = format!("batch_{nr}_s{style}");
            guarded(&tag, move || {
                let marker: [u8; 4096] = std::array::from_fn(|i| (i as u8) ^ 0xa5);
                let maddr = marker.as_ptr() as u64;
                let mypid = unsafe { libc::getpid() } as u64;
                let mut buf = vec![0u8; REQ_LEN + 8192];
                let out_addr = unsafe { buf.as_mut_ptr().add(REQ_LEN) } as u64;
                // 条目数组塞在 buf 尾部:{addr,len}×3
                let arr_off = REQ_LEN + 4096;
                for i in 0..3u64 {
                    let ent = arr_off + i as usize * 16;
                    buf[ent..ent + 8].copy_from_slice(&(maddr + i * 1024).to_le_bytes());
                    buf[ent + 8..ent + 16].copy_from_slice(&1024u64.to_le_bytes());
                }
                let arr_addr = unsafe { buf.as_mut_ptr().add(arr_off) } as u64;
                let args: [u64; 4] = if style == 0 {
                    [mypid, arr_addr, out_addr, 3]
                } else {
                    [arr_addr, out_addr, 3, mypid]
                };
                for (i, a) in args.iter().enumerate() {
                    buf[OFF_ARGS + i * 8..OFF_ARGS + i * 8 + 8].copy_from_slice(&a.to_le_bytes());
                }
                buf[OFF_CMD..OFF_CMD + 8].copy_from_slice(&0x401u64.to_le_bytes());
                let (r, e) = raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
                let ok0 = buf[REQ_LEN..REQ_LEN + 1024] == marker[0..1024];
                let ok1 = buf[REQ_LEN + 1024..REQ_LEN + 2048] == marker[1024..2048];
                emit(&[("k", js("kpm_batch")), ("nr", jn(nr)), ("style", jn(style)),
                       ("ret", jn(r)), ("errno", jn(e)),
                       ("chunk0_match", jn(ok0 as u8)), ("chunk1_match", jn(ok1 as u8))]);
            });
        }
    }

    // 步骤 5(#15):残余 opcode 0x10 / 0x920——零参查询,只观察
    for nr in SYSCALLS {
        for op in [0x10u64, 0x920] {
            let tag = format!("residual_{nr}_{op:x}");
            guarded(&tag, move || {
                let mut buf = vec![0u8; REQ_LEN];
                buf[OFF_CMD..OFF_CMD + 8].copy_from_slice(&op.to_le_bytes());
                let (r, e) = raw_sys(nr, buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
                let changed = buf.iter().filter(|&&b| b != 0).count();
                emit(&[("k", js("kpm_residual")), ("nr", jn(nr)), ("op", jh(op)),
                       ("ret", jn(r)), ("errno", jn(e)),
                       ("buf_nonzero", jn(changed)),
                       ("buf_head", js(&hex(&buf[..64])))]);
            });
        }
    }

    emit(&[("k", js("kpm_end"))]);
}
