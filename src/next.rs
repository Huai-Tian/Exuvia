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

    // guidance 注入（两段）：
    // ① 工具包三要素——工作包的固定形态（产品定位：预分析器 + 工具包；切片是坐标，
    //    深挖靠工具在原始物上跑——实战校准：LLM 的高价值养料是原始物+工具+坐标，
    //    不是预切产物）
    // ② fence 族知识全量注入（三次法则生长；机械侧不做族匹配判断，取舍在下游）
    let mut guidance = toolkit_guidance();
    guidance.extend(fence_guidance());

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

/// 工作包固定形态四要素（产品定位的机械化：预分析器 + 分析器 + 工具包）。
/// 实战校准（第一战 11 轮 attempts 复盘）：下游 LLM 的高价值养料排序为
/// 原始物 + 可参数化工具 > 全量普查文本 > 预切切片——切片的真实价值是坐标。
/// 第四条 = 洋葱循环：解卡产物回注剖析器（packers layer their defenses）。
fn toolkit_guidance() -> Vec<String> {
    vec![
        "RAW: work on the original objects themselves (apk entries, native libraries — paths appear in facts and evidence references). Slices are coordinates, not the working set.".to_string(),
        "TOOLKIT: trackb/ ships with the product — disasm.py (full-arch disassembly streams, PT_DYNAMIC view survives stripped section headers), so_emulator.py (black-box execution with JNI/world semantics, --fs file bridge, --sig-file/--utf8-file feeding channels for signature-derived key chains, emutls contract emulation materializing TLS-built strings offline), sigx.py (APK signing-chain certificate extractor; feeds --sig-file), sm4recon.py (GB/T 32907 SM4: CFB decrypt/encrypt, material-lattice/zlib/dex full-offset scan, textbook rkexp), crypto_recon.py (entropy / ecb / aes / rc4 / hash / dxor recon), elfrecon.py (embedded-ELF recovery), dexcontainer.py (profile-driven tail-container dex rebuild, per-dex sha1+adler oracle), jnitrace.py (JNI-semantics tracer on the emulator world: --init runtime warm-up, --seed-dex clinit static-field seeding, --arms null-guard dual-arm enumeration), trace2smali.py (trace-to-smali synthesis, --sigs-dex descriptor import from hollow stubs), fidelity.py (dump-vs-reference fidelity report); the binary itself carries `exuvia hunt` (L2 parameter-space search: when facts establish the cipher family + key, it mechanically recovers the ciphertext segment coordinates — variant RC4 via --rc4-stride/--rc4-seed/--rc4-jbias; a hit hands you the decrypt inputs, a negative fact rules out the scanned parameter space). Tools answer your NEXT question; static artifacts only answer the designer's questions.".to_string(),
        "COORDINATES: evidence slices are entry coordinates. Deep work = tools over raw objects, starting from those coordinates.".to_string(),
        "RE-ANALYZE LOOP: when a claim settles and a recovered DEX lands (workspace/<debt_id>/recovered.dex), run `exuvia analyze --dex` over it — packers layer their defenses (shell → strings → methods → VMP); each settled debt reveals the next layer's debt map. The handoff map is a per-layer sequence, not a one-shot census.".to_string(),
    ]
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
