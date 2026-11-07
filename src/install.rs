//! 安装完整性校验（README_AGENT §5 退出码二分）。
//! installation-broken = 拒绝运行：python 解释器缺失/探针失败（python3 → python → py -3 序）、SKILL.md fence 不可提取或不可解析。
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

/// 系统 Python 启动器描述符：程序名 + 前导参数（py 启动器需要 "-3" 选版）。
pub struct PythonLauncher {
    prog: &'static str,
    pre: &'static [&'static str],
}

impl PythonLauncher {
    /// 预置好启动参数的 Command（调用方继续追加脚本/-I 等参数）。
    pub fn command(&self) -> Command {
        let mut c = Command::new(self.prog);
        c.args(self.pre);
        c
    }
    /// 展示名（错误消息与日志用）。
    pub fn name(&self) -> String {
        match self.pre.is_empty() {
            true => self.prog.to_string(),
            false => format!("{} {}", self.prog, self.pre.join(" ")),
        }
    }
}

/// 候选序：python3 → python → py -3（Windows 启动器）→ 常见 Unix 绝对路径。
/// Windows python.org 发行版默认只有 python.exe / py.exe，商店占位 python3.exe
/// 会被探针拒认后越过——硬编码单名 "python3" 在 Windows 上等于断言装坏。
fn python_candidates() -> Vec<PythonLauncher> {
    vec![
        PythonLauncher { prog: "python3", pre: &[] },
        PythonLauncher { prog: "python", pre: &[] },
        PythonLauncher { prog: "py", pre: &["-3"] },
        PythonLauncher { prog: "/usr/bin/python3", pre: &[] },
        PythonLauncher { prog: "/usr/local/bin/python3", pre: &[] },
    ]
}

/// 单候选探针：stdin 喂已知输入，隔离模式执行，校验输出精确匹配。
/// 校验的是"存在一个真实的、`-I` 可用的解释器"（顺带挡掉 Windows 商店占位 python）。
/// 版本范围检查待 fence 长出 requires-python 字段后接入（三次法则：字段未挣得，检查不预置）。
fn probe_one(launcher: &PythonLauncher) -> Result<(), String> {
    let mut child = launcher
        .command()
        .arg("-I")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("not available: {e}"))?;
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
        return Err("probe exited non-zero".into());
    }
    let first = String::from_utf8_lossy(&out.stdout);
    let first = first.lines().next().unwrap_or_default().trim();
    if first != "exuvia-probe-ok" {
        return Err(format!("probe output mismatch: {first:?}"));
    }
    Ok(())
}

/// 解析第一个通过探针的解释器。探针与运行时共用同一候选表——
/// 探针过了运行时却换个名字找 = 自检撒谎。
pub fn resolve_python() -> Option<PythonLauncher> {
    python_candidates().into_iter().find(|l| probe_one(l).is_ok())
}

/// python 探针：逐个候选实跑，返回通过的启动器名；全灭则带逐候选原因响亮拒绝。
pub fn python_probe() -> Result<String, String> {
    let mut errs = Vec::new();
    for l in python_candidates() {
        match probe_one(&l) {
            Ok(()) => return Ok(l.name()),
            Err(e) => errs.push(format!("{}: {e}", l.name())),
        }
    }
    Err(format!("no working python launcher [{}]", errs.join("; ")))
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
