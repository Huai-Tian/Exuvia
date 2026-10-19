//! 安装完整性校验（README_AGENT §5 退出码二分）。
//! installation-broken = 拒绝运行：python3 缺失/probe 失败、SKILL.md fence 不可提取或不可解析。
//! 退出码 2 为 DRAFT 值，维护者最终定码表前不得扩散依赖。

use crate::fence;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const BROKEN_EXIT: i32 = 2;

/// SKILL.md 定位顺序：$EXUVIA_SKILL_MD → CWD → 二进制旁。与 jadx/ghidra 探测同精神：环境 → 显式 → 默认。
pub fn find_skill_md() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EXUVIA_SKILL_MD") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    for cand in ["./SKILL.md"] {
        if Path::new(cand).is_file() {
            return Some(PathBuf::from(cand));
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("SKILL.md")))
        .filter(|p| p.is_file())
}

/// python3 probe：stdin 喂已知输入，隔离模式执行，校验输出。
/// 校验的是"存在一个真实的、`-I` 可用的解释器"（顺带挡掉 Windows 的假 python.exe）。
/// 版本范围检查待 fence 长出 requires-python 字段后接入（三次法则：字段未挣得，检查不预置）。
pub fn python_probe() -> Result<String, String> {
    let mut child = Command::new("python3")
        .arg("-I")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("python3 not available: {e}"))?;
    let probe = b"print('exuvia-probe-ok')\n";
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(probe)
        .map_err(|e| format!("probe stdin failed: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("probe wait failed: {e}"))?;
    if !out.status.success() {
        return Err("python3 probe exited non-zero".into());
    }
    let first = String::from_utf8_lossy(&out.stdout);
    let first = first.lines().next().unwrap_or_default().trim();
    if first != "exuvia-probe-ok" {
        return Err(format!("python3 probe output mismatch: {first:?}"));
    }
    Ok(first.to_string())
}

/// 全量校验：SKILL.md 存在 + fence 可提取可解析（或 --profile 覆盖文件可解析）+ python3 probe 通过。
/// --profile = 判断外置通道（CLI 契约）：TOML 解析失败 = 判断源损坏 = installation-broken。
/// fence 字段的消费者按 x3 挣得后逐个接线；当前通道就位即止。
pub fn check(profile: Option<&Path>) -> Result<(), String> {
    if let Some(p) = profile {
        let raw = std::fs::read_to_string(p).map_err(|e| format!("--profile {} unreadable: {e}", p.display()))?;
        toml::from_str::<toml::Value>(&raw)
            .map_err(|e| format!("--profile TOML parse error: {e} (from {})", p.display()))?;
    }
    let path = find_skill_md().ok_or("SKILL.md not found (installation-broken)")?;
    let md = std::fs::read_to_string(&path).map_err(|e| format!("SKILL.md unreadable: {e}"))?;
    fence::parse(&md).map_err(|e| format!("{e} (from {})", path.display()))?;
    python_probe()?;
    Ok(())
}
