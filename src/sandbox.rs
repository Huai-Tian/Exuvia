//! 沙箱执行器：proposal 产物在不可信环境执行，判定权永在 Rust（三防线）。
//! ① 隔离注入：`python3 -I` + env_clear + 最小环境 +（Linux）rlimit：CPU 10s / AS 512MB / NOFILE 64
//! ② 判定权不外包：runner 只执行（加载 entry、喂 .in、吐原始输出），对比与判定在 gate.rs（Rust）
//! ③ 文本级 import 白名单：挡误用为主；恶意绕过由 OS 隔离 + 纯函数约定 + 不可信输出兜底（判定在 Rust）。
//! runner 以字符串资源内嵌，stdin 喂给 python3，零落盘。
//! Windows 路径：本骨架先无 rlimit（Job Object 留 release 工程期），软超时兜底——注释明示，勿删 TODO。

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const SOFT_TIMEOUT: Duration = Duration::from_secs(5);

/// 文本级 import 白名单（初值；fence 挣得 import_whitelist 字段后接管配置）
pub const IMPORT_WHITELIST: [&str; 8] = [
    "json", "sys", "base64", "binascii", "struct", "hashlib", "hmac", "zlib",
];

/// 内嵌胶水 runner：零落盘（脚本经 `-c` 参数注入，不写盘）；元数据走 argv，
/// 输入走 stdin（字节流），输出 = stdout raw 字节。判定永远在调用方（Rust）。
const RUNNER: &str = r#"
import sys, json, importlib.util
meta = json.loads(sys.argv[1])
spec = importlib.util.spec_from_file_location("exuvia_prop", meta["artifact"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sys.stdout.buffer.write(getattr(mod, meta["entry"])(sys.stdin.buffer.read()))
"#;

#[derive(Debug)]
pub enum SandboxError {
    ImportBlocked(String),
    Spawn(String),
    Timeout,
    NonZeroExit(i32),
    Io(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::ImportBlocked(m) => write!(f, "import not in whitelist: {m}"),
            SandboxError::Spawn(e) => write!(f, "spawn python3 failed: {e}"),
            SandboxError::Timeout => write!(f, "sandbox soft timeout (>{}s)", SOFT_TIMEOUT.as_secs()),
            SandboxError::NonZeroExit(c) => write!(f, "artifact exited non-zero: {c}"),
            SandboxError::Io(e) => write!(f, "sandbox io: {e}"),
        }
    }
}

/// 文本级 import 检查（防线之一，非全部——见模块注释）
pub fn check_imports(artifact_src: &str) -> Result<(), SandboxError> {
    for line in artifact_src.lines() {
        let t = line.trim();
        let (module, _) = if let Some(rest) = t.strip_prefix("import ") {
            (rest.split_whitespace().next().unwrap_or("").to_string(), ())
        } else if let Some(rest) = t.strip_prefix("from ") {
            (rest.split_whitespace().next().unwrap_or("").to_string(), ())
        } else {
            continue;
        };
        let root = module.split('.').next().unwrap_or("");
        if !IMPORT_WHITELIST.contains(&root) {
            return Err(SandboxError::ImportBlocked(root.to_string()));
        }
    }
    Ok(())
}

/// 在沙箱中执行 entry(input) -> bytes。返回原始输出——对比与判定由调用方（Rust）完成。
pub fn run_artifact(artifact_path: &str, entry: &str, input: &[u8]) -> Result<Vec<u8>, SandboxError> {
    let mut cmd = Command::new("python3");
    let meta = format!(r#"{{"artifact":{artifact_path:?},"entry":{entry:?}}}"#);
    cmd.arg("-I").arg("-c").arg(RUNNER).arg(&meta);
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // 资源熔断（尽力设置，失败不阻断）：CPU 10s 硬熔断、地址空间 512MB、fd 64
        unsafe fn lim(res: u32, val: libc::rlim_t) {
            let rl = libc::rlimit { rlim_cur: val, rlim_max: val };
            unsafe { libc::setrlimit(res, &rl) };
        }
        unsafe {
            cmd.pre_exec(|| {
                lim(libc::RLIMIT_CPU, 10);
                lim(libc::RLIMIT_AS, 512 * 1024 * 1024);
                lim(libc::RLIMIT_NOFILE, 64);
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn().map_err(|e| SandboxError::Spawn(e.to_string()))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    // stdin 只承担输入数据流；meta 已在 argv，runner 脚本在 -c 参数——全程零落盘
    stdin
        .write_all(input)
        .map_err(|e| SandboxError::Io(e.to_string()))?;
    drop(stdin);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = child.wait_with_output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(SOFT_TIMEOUT) {
        Ok(Ok(output)) if output.status.success() => Ok(output.stdout),
        Ok(Ok(output)) => Err(SandboxError::NonZeroExit(output.status.code().unwrap_or(-1))),
        Ok(Err(e)) => Err(SandboxError::Io(e.to_string())),
        // 软超时：工作线程 detach；CPU rlimit（10s）是硬熔断，进程必死，无泄漏
        Err(_) => Err(SandboxError::Timeout),
    }
}
