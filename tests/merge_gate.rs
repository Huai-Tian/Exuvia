//! merge 闸门测试——四层全链：范围闸、hash、equivalent 接受性、沙箱执行、
//! 判定权（Rust 比对）、结构断言、销账落盘、validate 自检。
//! 全部用合成物（tests/common），零样本纪律。

mod common;
use exuvia::gate;
use exuvia::next;
use exuvia::track_a::first_pass;
use sha2::Digest;
use std::path::{Path, PathBuf};

/// 完整前置：合成 APK → handoff（debt+REPORT）→ goal → workpackage.json
fn setup(dir: &Path, accepts_equivalent: bool) -> PathBuf {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let apk = dir.join("synthetic.apk");
    common::build_synthetic_apk(&apk);
    let (report, debt, _slices) = first_pass(&apk).unwrap();

    let handoff = dir.join("handoff");
    std::fs::create_dir_all(&handoff).unwrap();
    std::fs::write(handoff.join("debt.json"), serde_json::to_vec(&debt).unwrap()).unwrap();
    std::fs::write(handoff.join("REPORT.json"), serde_json::to_vec(&report).unwrap()).unwrap();

    let goal_json = serde_json::json!({
        "$schema": "exuvia.goal",
        "goal_version": 1,
        "targets": [{ "kind": "method", "class": "com.example.NativeProbe", "method": "nativeFoo" }],
        "levels": { "default": "L2" },
        "tracks": ["A"],
        "accepts_equivalent": accepts_equivalent,
        "stop": "targets-satisfied"
    });
    let goal = dir.join("goal.json");
    std::fs::write(&goal, serde_json::to_vec(&goal_json).unwrap()).unwrap();

    let wp = next::build(&goal, &handoff).expect("next");
    let wpp = dir.join("workpackage.json");
    std::fs::write(&wpp, serde_json::to_vec(&wp).unwrap()).unwrap();
    wpp
}

/// 构造合法 proposal（正确 hash）：identity 解密 + 输入=期望=minimal DEX
fn build_identity_proposal(dir: &Path, kind: &str) -> PathBuf {
    let pdir = dir.join("proposal");
    std::fs::create_dir_all(pdir.join("artifacts")).unwrap();
    std::fs::create_dir_all(pdir.join("tests")).unwrap();
    let src = b"def decrypt(data):\n    return data\n".to_vec();
    std::fs::write(pdir.join("artifacts/decrypt.py"), &src).unwrap();
    let dex = common::build_minimal_dex();
    std::fs::write(pdir.join("tests/case.in"), &dex).unwrap();
    std::fs::write(pdir.join("tests/case.out"), &dex).unwrap();
    let hash = format!(
        "sha256:{}",
        sha2::Sha256::digest(&src).iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let manifest = serde_json::json!({
        "$schema": "exuvia.proposal",
        "proposal_version": 1,
        "claims": [{
            "debt_id": "debt-0001",
            "kind": kind,
            "artifact": "artifacts/decrypt.py",
            "entry": "decrypt",
            "tests": [{ "input": "tests/case.in", "expected": "tests/case.out" }]
        }],
        "artifact_hashes": { "artifacts/decrypt.py": hash },
        "generator": "merge-gate-test"
    });
    std::fs::write(pdir.join("proposal.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    pdir
}

#[test]
fn merge_happy_path_recovered() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_ok");
    let wpp = setup(&dir, true);
    let pdir = build_identity_proposal(&dir, "recovered");

    let out = gate::merge(&pdir, &dir.join("handoff"), &wpp).expect("merge ok");
    assert_eq!(out.merged, vec!["debt-0001"]);
    assert_eq!(out.debt_remaining, 0);

    // 销账落盘验证
    let debt: exuvia::report::DebtFile = serde_json::from_slice(&std::fs::read(dir.join("handoff/debt.json")).unwrap()).unwrap();
    assert!(debt.entries.is_empty(), "条目必须被移除");
    assert!(dir.join("handoff/workspace/debt-0001/artifact").is_file(), "artifact 必须归档");
    // L1 骨架最小兑现：recovered 产物（DEX 形状）归档为 recovered.dex（jadx 可开）
    let rdx = dir.join("handoff/workspace/debt-0001/recovered.dex");
    assert!(rdx.is_file(), "recovered.dex 必须落盘");
    let saved = std::fs::read(&rdx).unwrap();
    assert_eq!(saved, common::build_minimal_dex(), "归档字节 = 闸门验证过的期望值");
    let log = std::fs::read_to_string(dir.join("handoff/attempts.log")).unwrap();
    assert!(log.contains("\"event\":\"merge-ok\"") && log.contains("\"kind\":\"recovered\""));
    // 剖析包状态一致（validate 过）
    let v = gate::validate(&dir.join("handoff")).expect("validate after merge");
    assert_eq!(v["valid"], serde_json::json!(true));
}

#[test]
fn merge_rejects_out_of_scope_claim() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_scope");
    let wpp = setup(&dir, true);
    let pdir = build_identity_proposal(&dir, "recovered");
    // 篡改 debt_id 为范围外
    let m = std::fs::read_to_string(pdir.join("proposal.json")).unwrap().replace("debt-0001", "debt-9999");
    std::fs::write(pdir.join("proposal.json"), m).unwrap();
    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_SCOPE");
}

#[test]
fn merge_rejects_equivalent_not_accepted() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_equiv");
    let wpp = setup(&dir, false); // goal 不接受 equivalent
    let pdir = build_identity_proposal(&dir, "equivalent");
    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_EQUIV_NOT_ACCEPTED");
}

#[test]
fn merge_rejects_hash_mismatch() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_hash");
    let wpp = setup(&dir, true);
    let pdir = build_identity_proposal(&dir, "recovered");
    // 声明 hash 与 artifact 实际字节不符
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pdir.join("proposal.json")).unwrap()).unwrap();
    m["artifact_hashes"]["artifacts/decrypt.py"] = serde_json::json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    std::fs::write(pdir.join("proposal.json"), serde_json::to_vec(&m).unwrap()).unwrap();
    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_HASH_MISMATCH");
}

#[test]
fn merge_rejects_output_mismatch() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_out");
    let wpp = setup(&dir, true);
    let pdir = build_identity_proposal(&dir, "recovered");
    // 期望值换成不同字节（独立事实被篡改——闸门必须抓住）
    std::fs::write(pdir.join("tests/case.out"), b"not what identity returns").unwrap();
    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_OUTPUT_MISMATCH");
    assert!(err.hint.is_some(), "修复循环的 hint 必须在场");
    // 拒绝留痕（attempts 闭环）：merge-rejected 事件 + debt 条目 attempts 计数递增
    let log = std::fs::read_to_string(dir.join("handoff/attempts.log")).unwrap();
    assert!(
        log.contains("\"event\":\"merge-rejected\"") && log.contains("E_OUTPUT_MISMATCH"),
        "{log}"
    );
    let debt: exuvia::report::DebtFile =
        serde_json::from_slice(&std::fs::read(dir.join("handoff/debt.json")).unwrap()).unwrap();
    assert_eq!(debt.entries[0].attempts, 1, "提交即尝试：被拒一次即计数 +1");
    assert_eq!(debt.entries.len(), 1, "拒绝不得销账");
    // 第二次拒绝 → attempts=2（escalation §6 "A path that died twice is dead" 的数据基础）
    let err2 = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err2.code, "E_OUTPUT_MISMATCH");
    let debt: exuvia::report::DebtFile =
        serde_json::from_slice(&std::fs::read(dir.join("handoff/debt.json")).unwrap()).unwrap();
    assert_eq!(debt.entries[0].attempts, 2, "再次被拒再次递增");
}

#[test]
fn merge_rejects_structurally_invalid_dex_output() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_struct");
    let wpp = setup(&dir, true);
    // artifact 返回"有 DEX 形状但表烂"的字节；期望值与输出一致（数值锚过），
    // 结构锚（Rust 侧）必须独立抓住
    let pdir = dir.join("proposal");
    std::fs::create_dir_all(pdir.join("artifacts")).unwrap();
    std::fs::create_dir_all(pdir.join("tests")).unwrap();
    let src = b"def decrypt(data):\n    return b'dex\\n035\\0' + b'\\xff' * 64\n".to_vec();
    std::fs::write(pdir.join("artifacts/decrypt.py"), &src).unwrap();
    let out_bytes = b"dex\n035\0".to_vec();
    let expected: Vec<u8> = [b"dex\n035\0".to_vec(), vec![0xff; 64]].concat();
    std::fs::write(pdir.join("tests/case.in"), &out_bytes).unwrap();
    std::fs::write(pdir.join("tests/case.out"), &expected).unwrap();
    let hash = format!(
        "sha256:{}",
        sha2::Sha256::digest(&src).iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let manifest = serde_json::json!({
        "$schema": "exuvia.proposal",
        "proposal_version": 1,
        "claims": [{
            "debt_id": "debt-0001",
            "kind": "recovered",
            "artifact": "artifacts/decrypt.py",
            "entry": "decrypt",
            "tests": [{ "input": "tests/case.in", "expected": "tests/case.out" }]
        }],
        "artifact_hashes": { "artifacts/decrypt.py": hash },
        "generator": "struct-test"
    });
    std::fs::write(pdir.join("proposal.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_STRUCT_INVALID", "双锚：数值锚过了，结构锚（Rust 侧）也必须独立抓错");
}

#[test]
fn merge_rejects_non_whitelisted_import() {
    let dir = std::env::temp_dir().join("exuvia_test_merge_import");
    let wpp = setup(&dir, true);
    let pdir = dir.join("proposal");
    std::fs::create_dir_all(pdir.join("artifacts")).unwrap();
    std::fs::create_dir_all(pdir.join("tests")).unwrap();
    let src = b"import os\ndef decrypt(data):\n    return data\n".to_vec();
    std::fs::write(pdir.join("artifacts/decrypt.py"), &src).unwrap();
    let dex = common::build_minimal_dex();
    std::fs::write(pdir.join("tests/case.in"), &dex).unwrap();
    std::fs::write(pdir.join("tests/case.out"), &dex).unwrap();
    let hash = format!(
        "sha256:{}",
        sha2::Sha256::digest(&src).iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let manifest = serde_json::json!({
        "$schema": "exuvia.proposal",
        "proposal_version": 1,
        "claims": [{
            "debt_id": "debt-0001",
            "kind": "recovered",
            "artifact": "artifacts/decrypt.py",
            "entry": "decrypt",
            "tests": [{ "input": "tests/case.in", "expected": "tests/case.out" }]
        }],
        "artifact_hashes": { "artifacts/decrypt.py": hash },
        "generator": "import-test"
    });
    std::fs::write(pdir.join("proposal.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = gate::merge(&pdir, &dir.join("handoff"), &wpp).unwrap_err();
    assert_eq!(err.code, "E_IMPORT_BLOCKED");
}

#[test]
fn sandbox_enforces_timeout() {
    // 死循环 artifact：软超时（5s）触发；CPU rlimit（10s）为硬熔断兜底
    let dir = std::env::temp_dir().join("exuvia_test_merge_timeout");
    std::fs::create_dir_all(dir.join("artifacts")).unwrap();
    let src = b"def decrypt(data):\n    while True:\n        pass\n".to_vec();
    std::fs::write(dir.join("artifacts/spin.py"), &src).unwrap();
    let err = exuvia::sandbox::run_artifact(dir.join("artifacts/spin.py").to_str().unwrap(), "decrypt", b"x");
    assert!(matches!(err, Err(exuvia::sandbox::SandboxError::Timeout)), "got: {err:?}");
}

#[test]
fn validate_rejects_inconsistent_handoff() {
    let dir = std::env::temp_dir().join("exuvia_test_validate");
    setup(&dir, true);
    let handoff = dir.join("handoff");
    let v = gate::validate(&handoff).expect("consistent");
    assert_eq!(v["valid"], serde_json::json!(true));
    // 破坏一致性：REPORT.debt.total 与 debt 条目数不符
    let mut r: serde_json::Value = serde_json::from_slice(&std::fs::read(handoff.join("REPORT.json")).unwrap()).unwrap();
    r["debt"]["total"] = serde_json::json!(999);
    std::fs::write(handoff.join("REPORT.json"), serde_json::to_vec(&r).unwrap()).unwrap();
    let err = gate::validate(&handoff).unwrap_err();
    assert_eq!(err.code, "E_INTERNAL_STATE");
}
