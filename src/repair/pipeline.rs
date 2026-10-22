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
    /// 直挂成品 dex（原样追加为 classes2..N，不重序列化，可多个、保序）。
    /// 与 repair_all.py 的 --extra-dex 同义：脱壳阶段闸门产物等不可再序列化的
    /// 成品 dex 走这里——--dump 只作 restore 来源、永不进成品包，两条通道不可互换。
    pub extra_dex: Vec<PathBuf>,
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

/// 组装 repair_all.py 的完整参数表（独立函数：通道语义可被单测钉死）。
/// 三条 dex 通道各司其职，不可互换：
///   - 位置参数（doctor 产物）       —— 分诊后重打包为 classes.dex
///   - --dump（restore 来源，可多个）—— 只读、永不进成品
///   - --extra-dex（直挂，可多个）   —— 原样追加为 classes2..N，不重序列化
fn repair_all_args(args: &RepairArgs, dex_fixed: &Path) -> Vec<String> {
    let mut cmd_args: Vec<String> = vec![
        abs(&args.packed_apk),
        abs(dex_fixed),
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
    for dex in &args.extra_dex {
        cmd_args.push("--extra-dex".to_string());
        cmd_args.push(abs(dex));
    }
    cmd_args
}

/// 提取「marker: <数字>」里的计数——marker 后跳空白、连续取数字。
/// 比 split(':') 健壮：输出行可能在数字后续接别的键值段
/// （repair_all.py 的 "shell assets removed: 4; shipped dexes: …" 同行多段格式）。
fn counter_after(l: &str, marker: &str) -> Option<usize> {
    let pos = l.find(marker)? + marker.len();
    let digits: String = l[pos..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<usize>().ok()
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
    let cmd_args = repair_all_args(args, &dex_fixed_path);

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
            // "shell assets removed: 4; shipped dexes: … (all entries…)" ——
            // 数字后同行还有别的段，split(':') 取段会带出分号残渣
            if let Some(n) = counter_after(l, "shell assets removed:") {
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
            extra_dex: vec![],
            key_pem: None,
            cert_der: None,
        };
        assert_eq!(args.packed_apk, Path::new("/tmp/test.apk"));
        assert!(args.reference_dex.is_none());
        assert!(args.extra_dumps.is_empty());
        assert!(args.extra_dex.is_empty());
    }

    #[test]
    fn test_repair_all_args_ship_channels() {
        // 通道语义回归（tosks 教训）：--dump 只作 restore 来源、不进成品；
        // 唯一携带 MainActivity 的子 dex 若被塞进 --dump，重打包出的 APK 会
        // 静默丢失整个 classes2.dex。直挂成品必须走 --extra-dex。
        let args = RepairArgs {
            packed_apk: PathBuf::from("/x/packed.apk"),
            dumped_dex: PathBuf::from("/x/main.dex"),
            out_apk: PathBuf::from("/x/out.apk"),
            reference_dex: None,
            extra_dumps: vec![PathBuf::from("/x/src_only.dex")],
            extra_dex: vec![PathBuf::from("/x/sub1.dex"), PathBuf::from("/x/sub2.dex")],
            key_pem: None,
            cert_der: None,
        };
        let cmd = repair_all_args(&args, Path::new("/x/main.doctor.dex"));
        // --dump / --extra-dex 各自恰好出现一次调用、值正确且保序
        let dump_pos: Vec<usize> = cmd.iter().enumerate()
            .filter(|(_, a)| *a == "--dump").map(|(i, _)| i).collect();
        let extra_pos: Vec<usize> = cmd.iter().enumerate()
            .filter(|(_, a)| *a == "--extra-dex").map(|(i, _)| i).collect();
        assert_eq!(dump_pos.len(), 1);
        assert_eq!(extra_pos.len(), 2);
        assert_eq!(cmd[dump_pos[0] + 1], "/x/src_only.dex");
        assert_eq!(cmd[extra_pos[0] + 1], "/x/sub1.dex");
        assert_eq!(cmd[extra_pos[1] + 1], "/x/sub2.dex");
        assert!(extra_pos[0] < extra_pos[1]);
        // 位置参数仍是「壳 APK + doctor 产物」两件，直挂 dex 绝不混入位置参数
        assert_eq!(&cmd[..4], ["/x/packed.apk", "/x/main.doctor.dex", "-o", "/x/out.apk"]);
    }

    #[test]
    fn test_counter_after_marker_tolerates_trailing_segments() {
        // repair_all.py 现行格式：数字后同行接 "; shipped dexes: … (…)"。
        // 旧实现 split(':') 取第二段得到 "4; shipped dexes"，parse 失败静默归零——
        // 日志写 4、JSON 报 0（tosks 回归实测抓到的不一致）。
        let l = "[repair] shell assets removed: 4; shipped dexes: classes.dex, classes2.dex (all entries 4-byte aligned)";
        assert_eq!(counter_after(l, "shell assets removed:"), Some(4));
        // 旧格式兼容："5" / "5 (all entries…)"
        assert_eq!(counter_after("[repair] shell assets removed: 5", "shell assets removed:"), Some(5));
        assert_eq!(counter_after("[repair] shell assets removed: 7 (all entries 4-byte aligned)", "shell assets removed:"), Some(7));
        // 无 marker / 无数字 → None，不误判
        assert_eq!(counter_after("[repair] nothing here", "shell assets removed:"), None);
        assert_eq!(counter_after("[repair] shell assets removed: none", "shell assets removed:"), None);
    }
}
