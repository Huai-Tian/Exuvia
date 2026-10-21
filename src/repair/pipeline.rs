//! 修复管线编排：doctor → clean → deweave → [repack] → [restore] → surgery
//!                     → zipalign → sign v2。
//!
//! 这是 repair_all.py 的 Rust 编排层——Python 工具链做重活，Rust 负责生命周期
//! 和 CLI 接口。每步的输出行被结构化收集到 RepairResult 中。

use std::path::{Path, PathBuf};
use super::embed;

/// 相对路径 → 绝对路径（Python 脚本在临时目录运行，需要绝对路径找到用户文件）。
fn abs(p: &Path) -> String {
    if p.is_absolute() {
        p.to_string_lossy().to_string()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(p)
            .to_string_lossy()
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct RepairArgs {
    /// 加固后的（壳）APK
    pub packed_apk: PathBuf,
    /// dump 出的 DEX 文件
    pub dumped_dex: PathBuf,
    /// 输出 APK 路径
    pub out_apk: PathBuf,
    /// 参照 DEX（原包，仅内部测试用，可选）
    pub reference_dex: Option<PathBuf>,
    /// 额外 dump 来源（第三方 dump / 脱壳阶段产物，互补还原被抽取方法）
    pub extra_dumps: Vec<PathBuf>,
    /// 签名密钥 PEM（可选，默认生成测试密钥）
    pub key_pem: Option<PathBuf>,
    /// 证书 DER（可选）
    pub cert_der: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct RepairResult {
    /// doctor 阶段的修复列表
    pub doctor_fixes: Vec<String>,
    /// deweave 阶段恢复的织入数
    pub deweave_restored: usize,
    /// restore 阶段从 dump/reference 来源搬运的方法体数
    pub restore_count: usize,
    /// stubsafe 阶段合成的契约等价方法体数（无来源兜底）
    pub stubsafe_count: usize,
    /// 手术移除的 wrapper Application 类名
    pub surgery_removed: Option<String>,
    /// 移除的壳资产条目数
    pub shell_assets_removed: usize,
    /// 4 字节对齐的条目数
    pub entries_aligned: usize,
    /// 签名后的 APK 大小
    pub final_size: usize,
    /// 每步的日志输出
    pub logs: Vec<String>,
    /// 成功/失败
    pub success: bool,
    pub error: Option<String>,
}

/// 执行完整修复管线。
pub fn run_repair(args: &RepairArgs) -> RepairResult {
    let mut result = RepairResult::default();
    let mut logs = Vec::new();

    // 0. 提取 Python 工具链
    let tools = match embed::extract_tools() {
        Ok(t) => t,
        Err(e) => {
            result.error = Some(format!("extract tools: {}", e));
            return result;
        }
    };
    logs.push("[tools] python toolchain extracted".to_string());

    // 1. 修复 DEX 的校验和和病理（dexdoctor.py --fix）
    let dex_fixed_path = args.dumped_dex.with_extension("doctor.dex");
    let (out, err) = match embed::run_py(
        &tools,
        "dexdoctor.py",
        &[
            &abs(&args.dumped_dex),
            "--fix",
            "-o",
            &abs(&dex_fixed_path),
        ],
    ) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(format!("dexdoctor: {}", e));
            result.logs = logs;
            return result;
        }
    };
    for line in out.lines() {
        if line.contains("FIXED") {
            result.doctor_fixes.push(line.trim().to_string());
        }
        logs.push(format!("[doctor] {}", line));
    }
    if !err.is_empty() {
        logs.push(format!("[doctor:stderr] {}", err.trim()));
    }

    // 2. 织入恢复 + 修复管线（repair_all.py 一条命令）
    // repair_all.py 内部做: doctor → clean → deweave → [repack] → [restore]
    //                        → surgery → zipalign → sign
    // 我们只需要调用它并传递正确的参数
    let mut cmd_args: Vec<String> = vec![
        abs(&args.packed_apk),
        abs(&dex_fixed_path),
        "-o".to_string(),
        abs(&args.out_apk),
    ];

    if let Some(ref reference) = args.reference_dex {
        cmd_args.push("--reference".to_string());
        cmd_args.push(abs(reference));
    }
    for dump in &args.extra_dumps {
        cmd_args.push("--dump".to_string());
        cmd_args.push(abs(dump));
    }

    let arg_refs: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
    let (out, err) = match embed::run_py(&tools, "repair_all.py", &arg_refs) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(format!("repair_all: {}", e));
            result.logs = logs;
            return result;
        }
    };

    // 解析 repair_all.py 的输出行
    for line in out.lines() {
        let l = line.trim();
        if l.contains("woven sites restored") {
            if let Some(n) = l.split(':').nth(1).and_then(|s| s.split('(').next())
                .and_then(|s| s.trim().parse::<usize>().ok()) {
                result.deweave_restored = n;
            }
        } else if l.contains("methods merged") {
            // "…restore: N methods merged from reference" — N sits right
            // before "methods" (the [restore:dump] prefix adds colons, so
            // splitting on ':' is unreliable)
            if let Some(pos) = l.find(" methods merged") {
                let digits: String = l[..pos]
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                if let Ok(n) = digits.parse::<usize>() {
                    result.restore_count = n;
                }
            }
        } else if l.contains("method(s) synthesized") {
            // "stubsafe: N method(s) synthesized, M native kept"
            if let Some(pos) = l.find(" method(s) synthesized") {
                let digits: String = l[..pos]
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                if let Ok(n) = digits.parse::<usize>() {
                    result.stubsafe_count = n;
                }
            }
        } else if l.contains("removed android:name") {
            result.surgery_removed = Some(
                l.split('"').nth(1).unwrap_or_default().to_string(),
            );
        } else if l.contains("shell assets removed") {
            // 从 "5" 或 "5 (all entries..." 提取数字
            if let Some(n) = l.split(':').nth(1).and_then(|s| s.split('(').next())
                .and_then(|s| s.trim().parse::<usize>().ok()) {
                result.shell_assets_removed = n;
            }
        } else if l.contains("4-byte aligned") {
            // zipalign 输出
        } else if l.contains("v2 signed") {
            // 签名输出
        }
        logs.push(format!("{}", l));
    }
    if !err.is_empty() {
        logs.push(format!("[stderr] {}", err.trim()));
    }

    // 3. 清理中间文件
    let _ = std::fs::remove_file(&dex_fixed_path);

    // 4. 验证输出
    if args.out_apk.exists() {
        result.final_size = std::fs::metadata(&args.out_apk)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        result.success = result.final_size > 0;
    } else {
        result.error = Some("output APK not created".into());
    }

    result.logs = logs;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_args_default() {
        let args = RepairArgs {
            packed_apk: PathBuf::from("/tmp/test.apk"),
            dumped_dex: PathBuf::from("/tmp/test.dex"),
            out_apk: PathBuf::from("/tmp/out.apk"),
            reference_dex: None,
            extra_dumps: vec![],
            key_pem: None,
            cert_der: None,
        };
        assert_eq!(args.packed_apk, Path::new("/tmp/test.apk"));
        assert!(args.reference_dex.is_none());
        assert!(args.extra_dumps.is_empty());
    }
}
