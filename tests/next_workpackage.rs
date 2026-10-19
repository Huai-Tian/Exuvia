//! next 工作包构建测试——外包循环第一环的机械行为。
//! 合成 APK（minimal DEX：1 个 ACC_NATIVE stub）→ handoff → goal → workpackage。

mod common;
use exuvia::next;
use exuvia::protocol::Track;
use exuvia::track_a::first_pass;
use std::path::Path;

fn setup_handoff(dir: &Path) {
    let apk = dir.join("synthetic.apk");
    common::build_synthetic_apk(&apk);

    let (report, debt, _slices) = first_pass(&apk).unwrap();
    assert_eq!(report.debt.total, 1, "一个 native stub → 一条欠账");
    assert_eq!(debt.entries.len(), 1);
    let hd = dir.join("handoff");
    std::fs::create_dir_all(&hd).unwrap();
    std::fs::write(hd.join("debt.json"), serde_json::to_vec(&debt).unwrap()).unwrap();
}

fn write_goal(dir: &Path, json: &str) -> std::path::PathBuf {
    let p = dir.join("goal.json");
    std::fs::write(&p, json).unwrap();
    p
}

const GOAL_NATIVE: &str = r#"{
  "$schema": "exuvia.goal",
  "goal_version": 1,
  "targets": [{ "kind": "method", "class": "com.example.NativeProbe", "method": "nativeFoo" }],
  "levels": { "default": "L2" },
  "tracks": ["A"],
  "accepts_equivalent": true,
  "stop": "targets-satisfied"
}"#;

#[test]
fn next_builds_workpackage_from_method_target() {
    let dir = std::env::temp_dir().join("exuvia_test_next");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    setup_handoff(&dir);
    let goal = write_goal(&dir, GOAL_NATIVE);

    let wp = next::build(&goal, &dir.join("handoff")).expect("build workpackage");

    assert_eq!(wp.schema, "exuvia.workpackage");
    assert!(wp.goal_sha256.starts_with("sha256:"));
    assert_eq!(wp.handoff_version, exuvia::version::HANDOFF_VERSION);
    // goal 声明逐字副本：范围闸数据源 + Agent 路径决策依据
    assert!(wp.accepts_equivalent);
    assert_eq!(wp.tracks, vec![Track::A]);
    assert_eq!(wp.allowed_debt, vec!["debt-0001".to_string()]);
    assert_eq!(wp.entries.len(), 1);
    assert_eq!(wp.entries[0].method.as_ref().unwrap().name, "nativeFoo");
    // 指纹未匹配（fence 无族条目）→ guidance 必空，不得编造
    assert!(wp.guidance.is_empty());
}

#[test]
fn next_empty_package_when_no_match() {
    let dir = std::env::temp_dir().join("exuvia_test_next2");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    setup_handoff(&dir);
    let goal = write_goal(&dir, r#"{
      "$schema": "exuvia.goal",
      "goal_version": 1,
      "targets": [{ "kind": "method", "class": "com.example.Other", "method": "bar" }],
      "levels": { "default": "L1" },
      "tracks": ["A"],
      "stop": "targets-satisfied"
    }"#);

    let wp = next::build(&goal, &dir.join("handoff")).expect("build");
    assert!(wp.allowed_debt.is_empty(), "无匹配 = 空工作包（诚实，不是错误）");
    assert!(wp.entries.is_empty());
}

#[test]
fn next_rejects_undefined_category() {
    let dir = std::env::temp_dir().join("exuvia_test_next3");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    setup_handoff(&dir);
    let goal = write_goal(&dir, r#"{
      "$schema": "exuvia.goal",
      "goal_version": 1,
      "targets": [{ "kind": "category", "profile": "network-entrypoints" }],
      "levels": { "default": "L2" },
      "tracks": ["A"],
      "stop": "targets-satisfied"
    }"#);

    let err = next::build(&goal, &dir.join("handoff")).expect_err("category must fail while fence has none");
    assert!(err.contains("not defined in fence"), "错误须说明 fence 无定义：{err}");
}

#[test]
fn next_rejects_version_mismatch() {
    let dir = std::env::temp_dir().join("exuvia_test_next4");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    setup_handoff(&dir);
    let goal = write_goal(&dir, r#"{
      "$schema": "exuvia.goal",
      "goal_version": 999,
      "targets": [],
      "levels": { "default": "L1" },
      "tracks": ["A"],
      "stop": "targets-satisfied"
    }"#);

    let err = next::build(&goal, &dir.join("handoff")).expect_err("version mismatch must fail");
    assert!(err.contains("goal_version"), "{err}");
}

#[test]
fn next_payload_target_selects_only_payload_debt() {
    // 一代壳形态：坏 DEX → encrypted-payload 卡点；goal {"kind":"payload"} 只选中它
    let dir = std::env::temp_dir().join("exuvia_test_next_payload");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("encrypted.apk");
    common::build_encrypted_apk(&apk);
    let (report, debt, _groups) = first_pass(&apk).unwrap();
    assert_eq!(debt.entries.len(), 2, "stub + payload 两卡点");
    let hd = dir.join("handoff");
    std::fs::create_dir_all(&hd).unwrap();
    std::fs::write(hd.join("debt.json"), serde_json::to_vec(&debt).unwrap()).unwrap();
    std::fs::write(hd.join("REPORT.json"), serde_json::to_vec(&report).unwrap()).unwrap();

    let goal = write_goal(&dir, r#"{
      "$schema": "exuvia.goal",
      "goal_version": 1,
      "targets": [{ "kind": "payload" }],
      "levels": { "default": "L2" },
      "tracks": ["A"],
      "accepts_equivalent": true,
      "stop": "targets-satisfied"
    }"#);

    let wp = next::build(&goal, &hd).expect("build");
    assert_eq!(wp.allowed_debt, vec!["debt-0002".to_string()], "只选 payload 卡点，stub 不选");
    assert_eq!(wp.entries.len(), 1);
    assert_eq!(wp.entries[0].kind, exuvia::report::DebtKind::EncryptedPayload);
    assert!(wp.entries[0].method.is_none());
}
