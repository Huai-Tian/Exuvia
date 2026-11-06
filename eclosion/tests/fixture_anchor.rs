#![cfg(unix)] // 羽化是设备侧执行器——测试随库同门(Windows 桌面不编译)
// 契约镜像锚定:eclosion 侧手写类型 ↔ 仓根 SKILL.md §10 fixture 双向校验。
// 镜像漂移即红——本测试就是"唯一耦合面"在羽化侧的那一半 CI。
use eclosion::proto::*;

fn skill_md() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../SKILL.md");
    std::fs::read_to_string(p).expect("SKILL.md readable")
}

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
fn skill_fixtures_parse_through_mirror_types() {
    let blocks = json_blocks(&skill_md());
    let mut seen_wo = false;
    let mut seen_mf = false;
    let mut seen_se = false;
    for b in &blocks {
        let v: serde_json::Value = serde_json::from_str(b).expect("fixture is valid JSON");
        match v.get("$schema").and_then(|s| s.as_str()) {
            Some("exuvia.workorder") => {
                let w: WorkOrder = serde_json::from_str(b).expect("workorder fixture 过羽化镜像(deny_unknown_fields)");
                assert_eq!(w.workorder_version, WORKORDER_VERSION, "工单版本镜像漂移");
                assert_eq!(w.hygiene.hygiene_version, HYGIENE_VERSION, "卫生版本镜像漂移");
                seen_wo = true;
            }
            Some("exuvia.manifest") => {
                let m: Manifest = serde_json::from_str(b).expect("manifest fixture 过羽化镜像");
                assert_eq!(m.manifest_version, MANIFEST_VERSION, "manifest 版本镜像漂移");
                seen_mf = true;
            }
            Some("exuvia.session") => {
                let s: SessionEnvelope = serde_json::from_str(b).expect("session fixture 过羽化镜像");
                assert_eq!(s.session_version, SESSION_VERSION, "会话版本镜像漂移");
                seen_se = true;
            }
            _ => {} // goal/proposal/report/... 是主机侧协议,羽化不镜像
        }
    }
    assert!(seen_wo && seen_mf && seen_se, "SKILL.md 必须含 workorder/manifest/session 三件 fixture");
}
