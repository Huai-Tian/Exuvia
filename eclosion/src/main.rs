// 羽化(eclosion)——Exuvia 脱壳功能的动态手段执行端。
// 零内置策略的纯执行引擎:策略全部来自工单(SKILL §10 契约三件套耦合)。
//
// 0.2.0 骨架内容:
// - run/stop/status 守护三动词(第 3 段:E2EE 会话层 + 工单管线 + 驱动 profile 对接)
// - probe 动词:第 1 段设备探针(#11–#15,保留作设备体检工具)
use eclosion::daemon::{self, DaemonConfig};
use eclosion::probe;
use std::path::PathBuf;
use std::process::exit;

fn usage() -> ! {
    eprintln!("羽化 exuvia-eclosion v0.2.0 —— 零策略纯执行引擎(只读、零注入)");
    eprintln!("用法:");
    eprintln!("  exuvia-eclosion run --host <主机:端口> [--profile <文件>] [--state-root <目录>] [--apk-root <目录>] [--no-harden]");
    eprintln!("      守护启动(反向拨号主机;配对秘密经环境变量 ECLOSION_SECRET 出示——argv 会进 /proc cmdline,不走)");
    eprintln!("  exuvia-eclosion stop [--state-root <目录>] [--dir <状态目录>]    守护停止");
    eprintln!("  exuvia-eclosion status [--state-root <目录>] [--dir <状态目录>]  守护状态");
    eprintln!("  exuvia-eclosion probe <env|art|drv|all> [--pkg <包名>] [--out <文件>]   第 1 段设备探针");
    exit(2);
}

fn default_state_root() -> PathBuf {
    let dev = PathBuf::from("/data/local/tmp");
    if dev.exists() && std::fs::metadata(&dev).map(|m| !m.permissions().readonly()).unwrap_or(false) {
        let test = dev.join(".eclosion-probe");
        if std::fs::write(&test, b"").is_ok() {
            std::fs::remove_file(&test).ok();
            return dev;
        }
    }
    std::env::var("TMPDIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); }
    match args[1].as_str() {
        "run" => {
            let mut host: Option<String> = None;
            let mut profile: Option<PathBuf> = None;
            let mut state_root = default_state_root();
            let mut apk_root = PathBuf::from("/data/app");
            let mut harden = true;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--host" if i + 1 < args.len() => { host = Some(args[i + 1].clone()); i += 2; }
                    "--profile" if i + 1 < args.len() => { profile = Some(PathBuf::from(&args[i + 1])); i += 2; }
                    "--state-root" if i + 1 < args.len() => { state_root = PathBuf::from(&args[i + 1]); i += 2; }
                    "--apk-root" if i + 1 < args.len() => { apk_root = PathBuf::from(&args[i + 1]); i += 2; }
                    "--no-harden" => { harden = false; i += 1; }
                    _ => usage(),
                }
            }
            let Some(host) = host else {
                eprintln!("run 缺 --host <主机:端口>(反向拨号目标)");
                exit(2);
            };
            let cfg = DaemonConfig { state_root, apk_root, profile_path: profile, host, harden };
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => { eprintln!("运行时创建失败: {e}"); exit(1); }
            };
            match rt.block_on(daemon::run(cfg)) {
                Ok(()) => eprintln!("[eclosion] 已退出"),
                Err(e) => { eprintln!("[eclosion] 响亮拒绝: {e}"); exit(1); }
            }
        }
        "stop" | "status" => {
            let mut state_root = default_state_root();
            let mut dir: Option<PathBuf> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--state-root" if i + 1 < args.len() => { state_root = PathBuf::from(&args[i + 1]); i += 2; }
                    "--dir" if i + 1 < args.len() => { dir = Some(PathBuf::from(&args[i + 1])); i += 2; }
                    _ => usage(),
                }
            }
            let r = if args[1] == "stop" {
                daemon::stop(&state_root, dir.as_deref())
            } else {
                daemon::status(&state_root, dir.as_deref())
            };
            match r {
                Ok(s) => println!("{s}"),
                Err(e) => { eprintln!("{e}"); exit(1); }
            }
        }
        "probe" => probe::dispatch(&args[2..]),
        _ => usage(),
    }
}
