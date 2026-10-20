//! `exuvia next --goal`：goal 消费端——外包循环的第一环。
//! 语义定位在 goal 作者（§3 SKILL）；本模块只做机械筛选：
//! goal.targets × debt 条目 → 工作包（范围闸的数据源）。
//! 工具不排序、不评价（"最值得"由 debt 事实与下游判断，建议排序是后续增强）。

use crate::protocol::{Goal, Target};
use crate::report::{DebtEntry, DebtFile, WorkPackage};
use sha2::{Digest, Sha256};
use std::path::Path;

/// 构建 workpackage.json。
/// handoff_dir = 剖析包目录（含 debt.json）。
pub fn build(goal_path: &Path, handoff_dir: &Path) -> Result<WorkPackage, String> {
    let goal_bytes = std::fs::read(goal_path).map_err(|e| format!("read goal: {e}"))?;
    let goal_sha = format!(
        "sha256:{}",
        Sha256::digest(&goal_bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let goal: Goal = serde_json::from_slice(&goal_bytes).map_err(|e| format!("goal parse: {e}"))?;
    if goal.schema != "exuvia.goal" {
        return Err(format!("unexpected $schema: {} (want exuvia.goal)", goal.schema));
    }
    if goal.goal_version != crate::version::GOAL_VERSION {
        return Err(format!(
            "goal_version {} not supported (tool supports {})",
            goal.goal_version,
            crate::version::GOAL_VERSION
        ));
    }

    let debt_path = handoff_dir.join("debt.json");
    let debt_bytes = std::fs::read(&debt_path).map_err(|e| format!("read {}: {e}", debt_path.display()))?;
    let debt: DebtFile = serde_json::from_slice(&debt_bytes).map_err(|e| format!("debt parse: {e}"))?;
    if debt.handoff_version != crate::version::HANDOFF_VERSION {
        return Err(format!(
            "handoff_version {} not supported (tool supports {})",
            debt.handoff_version,
            crate::version::HANDOFF_VERSION
        ));
    }

    // 机械筛选。类目 = fence 中的查表：fence 现无任何类目定义，
    // 引用即诚实报错（不猜测、不静默忽略）。
    let mut picked: Vec<&DebtEntry> = Vec::new();
    for t in &goal.targets {
        match t {
            Target::Method { class, method } => {
                for e in &debt.entries {
                    if let Some(m) = &e.method {
                        if m.class == *class && m.name == *method && !picked.iter().any(|p| p.debt_id == e.debt_id) {
                            picked.push(e);
                        }
                    }
                }
            }
            Target::Category { profile } => {
                return Err(format!(
                    "category '{profile}' not defined in fence (fence has no categories yet — growth rules apply)"
                ));
            }
            // payload：匹配全部自动生成的 encrypted-payload 卡点（坏 DEX 机械事实）
            Target::Payload => {
                for e in &debt.entries {
                    if e.kind == crate::report::DebtKind::EncryptedPayload
                        && !picked.iter().any(|p| p.debt_id == e.debt_id)
                    {
                        picked.push(e);
                    }
                }
            }
        }
    }
    // debt_id 稳定序（debt.json 本身已稳定排序，此处防御性再排）
    picked.sort_by(|a, b| a.debt_id.cmp(&b.debt_id));

    let allowed_debt: Vec<String> = picked.iter().map(|e| e.debt_id.clone()).collect();
    let entries: Vec<DebtEntry> = picked.into_iter().cloned().collect();

    // guidance 注入：fence 族知识的全量注入（fence 条目按三次法则生长、天然少量；
    // 机械侧不做族匹配判断——下游 LLM 按卡点事实自行取舍，guidance 语义 = 可选参考知识）
    let guidance = fence_guidance();

    Ok(WorkPackage {
        schema: "exuvia.workpackage".to_string(),
        goal_sha256: goal_sha,
        handoff_version: crate::version::HANDOFF_VERSION,
        accepts_equivalent: goal.accepts_equivalent,
        tracks: goal.tracks.clone(),
        guidance,
        allowed_debt,
        entries,
    })
}

/// fence 全部族条目的 guidance 清单（工具机械全注入，匹配判断在下游智能侧）。
fn fence_guidance() -> Vec<String> {
    let Some(path) = crate::install::find_skill_md() else {
        return Vec::new();
    };
    let Ok(md) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(value) = crate::fence::parse(&md) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(families) = value.get("families").and_then(|f| f.as_table()) {
        for (_name, fam) in families {
            if let Some(list) = fam.get("guidance").and_then(|g| g.as_array()) {
                for g in list {
                    if let Some(s) = g.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}
