//! 洋葱二次分析（`exuvia analyze --dex`）：解卡产物回注剖析器。
//! 产品定位的第二角色——不只是预分析器（首层欠账地图），也是分析器：
//! 每一层卡点关闭（recovered DEX 落地）→ 对产物再剖析 → 下一层欠账地图。
//! 加固的防御是分层的（壳层 → 字符串层 → 方法层 → VMP 层），欠账地图是逐层序列。
//!
//! 机械边界与 first_pass 一致：只做格式事实（方法表遍历 / ACC_NATIVE 清点 /
//! 熵测量），不做语义判断。符号定位不在此层（单 DEX 无 so 上下文——facts 如实标注）。

use crate::report::{DebtEntry, DebtFile, DebtKind, DebtStatus, MethodRef};
use crate::track_a::dex;
use crate::track_a::entropy::EntropyCounter;
use crate::version;

/// 对单个 DEX 文件剖析 → 落盘 `<out>/debt.json` + `<out>/REPORT.md`。
/// debt.json 与 first_pass 同一协议格式——同一消费端（next --goal / merge）直接可用，
/// 二次卡点走同一外包循环。
pub fn analyze_dex(dex_path: &std::path::Path, out_dir: &std::path::Path) -> Result<DebtFile, String> {
    let data = std::fs::read(dex_path).map_err(|e| format!("read {}: {e}", dex_path.display()))?;

    // 整文件熵（原始测量；与 asset 熵测量同款计数器）
    let mut ec = EntropyCounter::default();
    ec.update(&data);

    let mut facts_common = vec![
        format!("re-analysis of {}", dex_path.display()),
        format!("file size {} bytes, entropy {} bits/byte", data.len(), ec.bits_per_byte()),
        "single-DEX layer: no so context — symbol localization not applicable at this layer".to_string(),
    ];

    let mut entries: Vec<DebtEntry> = Vec::new();
    match dex::parse(&data) {
        Ok(methods) => {
            facts_common.push(format!("parse_ok: {} methods", methods.len()));
            // ACC_NATIVE 机械清点（与 first_pass 的 stub 判定同一条机械规则）
            for m in methods.iter().filter(|m| m.is_native) {
                entries.push(DebtEntry {
                    debt_id: format!("debt-{:04}", entries.len() + 1),
                    kind: DebtKind::MethodNativeStub,
                    method: Some(MethodRef { class: m.class.clone(), name: m.name.clone(), descriptor: m.descriptor.clone() }),
                    status: DebtStatus::BlockedSolvable,
                    facts: {
                        let mut f = facts_common.clone();
                        f.push("native stub — body outside DEX (access_flags ACC_NATIVE)".to_string());
                        f
                    },
                    evidence: vec![],
                    attempts: 0,
                });
            }
        }
        Err(e) => {
            // 解析失败即容器层卡点（与 first_pass 的坏 DEX 路径同款语义）
            facts_common.push(format!("dex parse failed: {e}"));
            entries.push(DebtEntry {
                debt_id: "debt-0001".to_string(),
                kind: DebtKind::EncryptedPayload,
                method: None,
                status: DebtStatus::BlockedSolvable,
                facts: facts_common,
                evidence: vec![],
                attempts: 0,
            });
        }
    }

    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
    let debt = DebtFile {
        schema: "exuvia.debt".to_string(),
        handoff_version: version::HANDOFF_VERSION,
        entries,
    };
    let json = serde_json::to_string_pretty(&debt).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(out_dir.join("debt.json"), &json).map_err(|e| format!("write debt.json: {e}"))?;

    // REPORT.md（人类可读导航；机械事实）
    let mut md = String::new();
    md.push_str("# Exuvia re-analysis handoff (single-DEX layer)\n\n");
    md.push_str("Onion loop: recovered DEX re-analyzed by the same mechanical rules.\n\n");
    md.push_str("## Debt map (next layer)\n\n");
    if debt.entries.is_empty() {
        md.push_str("No debt at this layer — clean DEX (no native stubs).\n");
    }
    for e in &debt.entries {
        let target = e.method.as_ref().map(|m| format!("{}.{}", m.class, m.name)).unwrap_or_else(|| "(payload container)".to_string());
        md.push_str(&format!("- `{}` {} `{}` ({} attempts)\n", e.debt_id, kind_str(e.kind), target, e.attempts));
    }
    std::fs::write(out_dir.join("REPORT.md"), &md).map_err(|e| format!("write REPORT.md: {e}"))?;
    Ok(debt)
}

fn kind_str(k: DebtKind) -> &'static str {
    match k {
        DebtKind::MethodNativeStub => "method-native-stub",
        DebtKind::EncryptedPayload => "encrypted-payload",
    }
}
