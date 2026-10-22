//! Python 工具链嵌入：编译时 include_bytes!，运行时提取到临时目录。
//!
//! 单二进制携带全部 Python 源码；系统 python3 是前提假设（README_AGENT §0）。
//! 提取策略：首次调用时展开到 <temp>/exuvia-repair/<hash>/，同版本幂等。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// 嵌入的 Python 工具链文件表：(目标文件名, 源文件内容)。
/// 内容在编译时嵌入；文件名保持与 trackb/ 原名一致（import 依赖）。
const PY_FILES: &[(&str, &[u8])] = &[
    ("axmltool.py", include_bytes!("../../trackb/axmltool.py")),
    ("dexclean.py", include_bytes!("../../trackb/dexclean.py")),
    ("dexdoctor.py", include_bytes!("../../trackb/dexdoctor.py")),
    ("deweave.py", include_bytes!("../../trackb/deweave.py")),
    ("repair.py", include_bytes!("../../trackb/repair.py")),
    ("repair_all.py", include_bytes!("../../trackb/repair_all.py")),
    ("sign2.py", include_bytes!("../../trackb/sign2.py")),
    // 空壳填体四步链（族 2 dex2c：locate → trace → synth → assemble）——
    // hollowfill.py 编排，jnitrace.py 经 importlib 同目录装载 so_emulator.py
    ("hollowfill.py", include_bytes!("../../trackb/hollowfill.py")),
    ("jnitrace.py", include_bytes!("../../trackb/jnitrace.py")),
    ("trace2smali.py", include_bytes!("../../trackb/trace2smali.py")),
    ("so_emulator.py", include_bytes!("../../trackb/so_emulator.py")),
];

/// 工具链整体 SHA-256（版本指纹——内容变更自动换目录）。
fn toolchain_hash() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (_, bytes) in PY_FILES {
        h.update(bytes);
    }
    let digest = h.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex[..16].to_string()
}

/// 提取 Python 工具链到临时目录。幂等：同版本已存在时跳过。
/// 返回工具链目录（包含所有 .py 文件）。
pub fn extract_tools() -> Result<PathBuf, io::Error> {
    let hash = toolchain_hash();
    let dir = std::env::temp_dir().join("exuvia-repair").join(&hash);

    // 幂等：已存在且非空则跳过
    if dir.is_dir() {
        let marker = dir.join(".complete");
        if marker.exists() {
            return Ok(dir);
        }
    }

    fs::create_dir_all(&dir)?;
    for (name, content) in PY_FILES {
        let path = dir.join(name);
        fs::write(&path, content)?;
    }
    // dexclean 需要的辅助常量已嵌入各文件内；无外部数据文件
    fs::write(dir.join(".complete"), b"")?;
    Ok(dir)
}

/// 系统可用的 python3 解释器路径。
pub fn find_python3() -> Result<PathBuf, String> {
    let candidates = ["python3", "/usr/bin/python3", "/usr/local/bin/python3"];
    for c in candidates {
        if let Ok(out) = std::process::Command::new(c).arg("--version").output() {
            if out.status.success() {
                return Ok(PathBuf::from(c));
            }
        }
    }
    Err("python3 not found in PATH or common locations".into())
}

/// 执行一个 Python 脚本并返回 (stdout, stderr)。
pub fn run_py(
    tools_dir: &Path,
    script: &str,
    args: &[&str],
) -> Result<(String, String), String> {
    let python = find_python3()?;
    let script_path = tools_dir.join(script);

    let output = std::process::Command::new(python)
        .arg(&script_path)
        .args(args)
        .current_dir(tools_dir)
        .output()
        .map_err(|e| format!("spawn python3 {} {}: {}", script, e, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        // 结构化错误走 stdout（hollowfill 等工具的 JSON 错误面）——stderr 为空
        // 时把 stdout 尾巴带上，调用方拿到的不再是裸退出码
        let tail = if stderr.trim().is_empty() && !stdout.trim().is_empty() {
            format!("\nstdout: {}", stdout.trim())
        } else {
            String::new()
        };
        return Err(format!(
            "python3 {} failed (exit={}):\n{}{}",
            script,
            output.status.code().unwrap_or(-1),
            stderr,
            tail
        ));
    }

    Ok((stdout, stderr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embed_and_extract() {
        let dir = extract_tools().expect("extract");
        assert!(dir.join("repair_all.py").exists());
        assert!(dir.join("sign2.py").exists());
        assert!(dir.join("dexdoctor.py").exists());
        // 幂等
        let dir2 = extract_tools().expect("extract 2");
        assert_eq!(dir, dir2);
    }

    #[test]
    fn test_python3_available() {
        // CI 环境可能没有 python3；仅在有 python3 的环境验证
        if find_python3().is_ok() {
            let dir = extract_tools().expect("extract");
            // dexdoctor.py --help 有 argparse 支持，返回 0
            let (_, stderr) = run_py(&dir, "dexdoctor.py", &["--help"]).expect("run");
            // argparse 的 help 输出在 stdout；失败信息在 stderr
            assert!(stderr.is_empty(), "dexdoctor --help should not fail: {}", stderr);
        }
    }
}
