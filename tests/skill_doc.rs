//! 文档即测试：SKILL.md 的 fixture 与版本锚点是活契约。
//! 三向锚定：SKILL 示例 ↔ serde 类型 ↔ 版本常量。任一侧漂移，此测试即红。

use exuvia::protocol::{CollectorManifest, Goal, HygieneCatalog, Proposal, WorkOrder};
use exuvia::report::{DebtFile, EvidenceManifest, Report, WorkPackage};

fn skill_md() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("SKILL.md");
    std::fs::read_to_string(p).expect("SKILL.md readable")
}

/// 提取 SKILL.md 中全部 ```json 块（按出现顺序）。
fn json_blocks(md: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in md.lines() {
        let t = line.trim();
        if t == "```json" {
            inside = true;
            out.push(String::new());
        } else if inside && t == "```" {
            inside = false;
        } else if inside {
            out.last_mut().unwrap().push_str(line);
            out.last_mut().unwrap().push('\n');
        }
    }
    out
}

#[test]
fn fence_extracts_parses_and_has_first_family() {
    let md = skill_md();
    let raw = exuvia::fence::extract(&md).expect("fence found");
    let val: toml::Value = toml::from_str(&raw).expect("fence parses as TOML");
    // fence 生长（第一战挣得、维护者确认）：首条族知识在档——结构锁定，未知字段仍拒绝
    let fam = val
        .get("families")
        .and_then(|f| f.get("wholefile-encrypt"))
        .expect("first family entry earned from Battle 1");
    let guidance = fam
        .get("guidance")
        .and_then(|g| g.as_array())
        .expect("guidance array");
    assert!(guidance.len() >= 3, "inflate-boundary hook recipe is the family knowledge core");
    assert!(fam.get("description").is_some(), "family description present");
}

#[test]
fn skill_json_fixtures_parse_through_serde_types() {
    let blocks = json_blocks(&skill_md());
    assert!(blocks.len() >= 9, "expected goal + proposal + report + debt + workpackage + evidence + workorder + manifest + hygiene fixtures");
    let mut kinds = 0;
    for b in &blocks {
        let v: serde_json::Value = serde_json::from_str(b).expect("fixture is valid JSON");
        match v.get("$schema").and_then(|s| s.as_str()) {
            Some("exuvia.goal") => {
                let g: Goal = serde_json::from_str(b).expect("goal fixture matches Goal type (deny_unknown_fields)");
                assert_eq!(g.goal_version, exuvia::version::GOAL_VERSION);
                assert_eq!(g.schema, "exuvia.goal");
                kinds |= 1;
            }
            Some("exuvia.proposal") => {
                let p: Proposal = serde_json::from_str(b).expect("proposal fixture matches Proposal type (deny_unknown_fields)");
                assert_eq!(p.proposal_version, exuvia::version::PROPOSAL_VERSION);
                kinds |= 2;
            }
            Some("exuvia.report") => {
                let r: Report = serde_json::from_str(b).expect("report fixture matches Report type (deny_unknown_fields)");
                assert_eq!(r.handoff_version, exuvia::version::HANDOFF_VERSION);
                kinds |= 4;
            }
            Some("exuvia.debt") => {
                let d: DebtFile = serde_json::from_str(b).expect("debt fixture matches DebtFile type (deny_unknown_fields)");
                assert_eq!(d.handoff_version, exuvia::version::HANDOFF_VERSION);
                kinds |= 8;
            }
            Some("exuvia.workpackage") => {
                let w: WorkPackage = serde_json::from_str(b).expect("workpackage fixture matches WorkPackage type (deny_unknown_fields)");
                assert_eq!(w.handoff_version, exuvia::version::HANDOFF_VERSION);
                assert_eq!(w.allowed_debt.len(), w.entries.len());
                kinds |= 16;
            }
            Some("exuvia.evidence") => {
                let e: EvidenceManifest = serde_json::from_str(b).expect("evidence fixture matches EvidenceManifest type (deny_unknown_fields)");
                assert_eq!(e.debt_id, "debt-0001");
                kinds |= 32;
            }
            Some("exuvia.collector.workorder") => {
                let w: WorkOrder = serde_json::from_str(b).expect("workorder fixture matches WorkOrder type (deny_unknown_fields)");
                assert_eq!(w.workorder_version, exuvia::version::WORKORDER_VERSION);
                assert_eq!(w.hygiene.hygiene_version, exuvia::version::HYGIENE_VERSION);
                assert_eq!(w.schema, "exuvia.collector.workorder");
                kinds |= 64;
            }
            Some("exuvia.collector.manifest") => {
                let m: CollectorManifest = serde_json::from_str(b).expect("manifest fixture matches CollectorManifest type (deny_unknown_fields)");
                assert_eq!(m.manifest_version, exuvia::version::MANIFEST_VERSION);
                kinds |= 128;
            }
            Some("exuvia.collector.hygiene") => {
                let h: HygieneCatalog = serde_json::from_str(b).expect("hygiene fixture matches HygieneCatalog type (deny_unknown_fields)");
                assert_eq!(h.hygiene_version, exuvia::version::HYGIENE_VERSION);
                kinds |= 256;
            }
            other => panic!("fixture with unknown $schema {other:?} — every json block in SKILL.md must be an anchored fixture"),
        }
    }
    assert_eq!(kinds, 511, "all nine protocol fixtures must be present");
}

#[test]
fn version_anchors_match_source_constants() {
    let md = skill_md();
    // 限定在 §11 Version anchors 节内解析，避免匹配到 §3/§4/§10 fixture 中的同名字段
    let anchors = md
        .split("## 11. Version anchors")
        .nth(1)
        .expect("version anchors section exists");
    let skill_v = anchors
        .lines()
        .find(|l| l.contains("SKILL_VERSION:"))
        .expect("SKILL_VERSION anchor line")
        .split("SKILL_VERSION:")
        .nth(1)
        .unwrap()
        .trim();
    assert_eq!(skill_v, exuvia::version::SKILL_VERSION, "SKILL.md §11 anchor must equal src/version.rs");
    for (name, got) in [
        ("handoff_version", exuvia::version::HANDOFF_VERSION),
        ("goal_version", exuvia::version::GOAL_VERSION),
        ("proposal_version", exuvia::version::PROPOSAL_VERSION),
        ("workorder_version", exuvia::version::WORKORDER_VERSION),
        ("manifest_version", exuvia::version::MANIFEST_VERSION),
        ("hygiene_version", exuvia::version::HYGIENE_VERSION),
    ] {
        let line = anchors.lines().find(|l| l.contains(name)).unwrap_or_else(|| panic!("{name} anchor exists"));
        let doc: i64 = line
            .split(name)
            .nth(1)
            .unwrap()
            .trim()
            .trim_start_matches(':')
            .trim()
            .split_whitespace()
            .next()
            .unwrap()
            .trim_end_matches(',')
            .parse()
            .expect("numeric anchor");
        assert_eq!(doc, got, "{name} anchor must equal src/version.rs");
    }
}

#[test]
fn unknown_fields_are_rejected() {
    let bad = r#"{"$schema":"exuvia.goal","goal_version":1,"targets":[],"levels":{"default":"L1"},"tracks":[],"stop":"targets-satisfied","surprise_field":true}"#;
    assert!(serde_json::from_str::<Goal>(bad).is_err(), "gate layer 1: unknown fields must be rejected");
}

#[test]
fn corrupted_fence_is_a_parse_error() {
    // 负向锚定：fence 语法坏 = installation-broken 的机制证明
    // （"# anchor:" 只存在于 fence 首行注释，替换后为非法 TOML 行）
    let md = skill_md();
    let corrupted = md.replace("# anchor:", "]]not toml[[");
    assert_ne!(corrupted, md, "corruption must apply");
    assert!(exuvia::fence::parse(&corrupted).is_err(), "fence parse must reject corrupt TOML");
}
