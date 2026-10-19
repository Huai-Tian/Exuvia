//! ci-verify 合成对自测——比对逻辑公开、样本私有：CI 无私有语料，
//! 用合成对验证工具自身正确性（零样本纪律同源）。

use std::io::Write;

/// uleb128 编码（与主工程 tests/common 同源的最小构造器副本）
fn uleb_bytes(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn str_data(s: &str) -> Vec<u8> {
    let mut d = uleb_bytes(s.len() as u32);
    d.extend_from_slice(s.as_bytes());
    d.push(0);
    d
}

/// 最小合法 DEX（与主工程 common 相同形态：1 类、2 方法、1 个 ACC_NATIVE stub）
fn build_minimal_dex() -> Vec<u8> {
    let strings = [
        "Lcom/example/NativeProbe;",
        "Landroid/content/Context;",
        "V",
        "VL",
        "nativeFoo",
        "plainFoo",
        "Source.java",
    ];
    let mut sdata = Vec::new();
    let mut offs = Vec::new();
    for s in strings {
        offs.push((112 + sdata.len()) as u32);
        sdata.extend_from_slice(&str_data(s));
    }
    let string_ids_off = 112 + sdata.len();
    let type_ids_off = string_ids_off + 4 * strings.len();
    let proto_ids_off = type_ids_off + 3 * 4;
    let type_list_off = proto_ids_off + 12;
    let method_ids_off = type_list_off + 8;
    let class_defs_off = method_ids_off + 2 * 12;
    let class_data_off = class_defs_off + 32;

    let mut out = vec![0u8; 112];
    out[0..8].copy_from_slice(b"dex\n035\0");
    macro_rules! put {
        ($off:expr, $v:expr) => {
            out[$off..$off + 4].copy_from_slice(&$v.to_le_bytes())
        };
    }
    put!(0x20, 0u32);
    put!(0x24, 112u32);
    put!(0x28, 0x12345678u32);
    put!(0x38, strings.len() as u32);
    put!(0x3c, string_ids_off as u32);
    put!(0x40, 3u32);
    put!(0x44, type_ids_off as u32);
    put!(0x48, 1u32);
    put!(0x4c, proto_ids_off as u32);
    put!(0x58, 2u32);
    put!(0x5c, method_ids_off as u32);
    put!(0x60, 1u32);
    put!(0x64, class_defs_off as u32);

    out.extend_from_slice(&sdata);
    for o in offs {
        out.extend_from_slice(&o.to_le_bytes());
    }
    for i in [0u32, 1, 2] {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(type_list_off as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (_, _, n) in [(0u32, 0u32, 4u32), (0, 0, 5)] {
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
    }
    for v in [0u32, 0, 0xFFFF_FFFF, 0, 6, 0, class_data_off as u32, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(2));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0x100));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(1));
    out.extend_from_slice(&uleb_bytes(1));
    out.extend_from_slice(&uleb_bytes(0));

    let n = out.len() as u32;
    out[0x20..0x24].copy_from_slice(&n.to_le_bytes());
    out
}

/// 合成"原包 + 加固包"对：同一 DEX（未加密形态的最小模拟）。
fn build_pair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let orig = dir.join("demo.orig.apk");
    let packed = dir.join("demo.packed.apk");
    for p in [&orig, &packed] {
        let f = std::fs::File::create(p).unwrap();
        let mut w = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(&build_minimal_dex()).unwrap();
        w.finish().unwrap();
    }
    let handoff = dir.join("handoff");
    std::fs::create_dir_all(&handoff).unwrap();
    (orig, packed, handoff)
}

#[test]
fn register_builds_hash_manifest() {
    let dir = std::env::temp_dir().join("ci_verify_register");
    let _ = std::fs::remove_dir_all(&dir);
    let (orig, _packed, _) = build_pair(&dir);
    let out = ci_verify::register(&dir).expect("register");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(v["entries"][0]["name"], "demo");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("corpus.json")).unwrap()).unwrap();
    assert!(manifest["entries"][0]["orig"]["sha256"].as_str().unwrap().starts_with("sha256:"));
    // hash 与实际文件对账
    assert_eq!(
        manifest["entries"][0]["orig"]["sha256"],
        serde_json::json!(ci_verify::sha256_file(&orig).unwrap())
    );
}

#[test]
fn check_reports_full_coverage_on_unpackable_pair() {
    let dir = std::env::temp_dir().join("ci_verify_check");
    let _ = std::fs::remove_dir_all(&dir);
    let (orig, packed, handoff) = build_pair(&dir);
    // 未加密对：可见即全覆盖；recovered 为空集
    let out = ci_verify::check(&orig, &packed, &handoff).expect("check");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["orig"]["classes"], serde_json::json!(1));
    assert_eq!(v["orig"]["methods"], serde_json::json!(2));
    assert_eq!(v["class_coverage"], serde_json::json!(1.0));
    assert_eq!(v["method_coverage"], serde_json::json!(1.0));
}

#[test]
fn check_counts_recovered_dex_into_coverage() {
    let dir = std::env::temp_dir().join("ci_verify_recovered");
    let _ = std::fs::remove_dir_all(&dir);
    let (orig, packed, handoff) = build_pair(&dir);
    // 模拟零可见（坏 dex 的"加固包"）+ 已恢复（workspace/debt-0001/recovered.dex）
    std::fs::remove_file(&packed).unwrap();
    let f = std::fs::File::create(&packed).unwrap();
    let mut w = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default();
    w.start_file("classes.dex", opts).unwrap();
    w.write_all(b"not a dex at all").unwrap();
    w.finish().unwrap();
    let wdir = handoff.join("workspace/debt-0001");
    std::fs::create_dir_all(&wdir).unwrap();
    std::fs::write(wdir.join("recovered.dex"), build_minimal_dex()).unwrap();

    let out = ci_verify::check(&orig, &packed, &handoff).expect("check");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["packed_visible"]["classes"], serde_json::json!(0));
    assert_eq!(v["handoff_recovered"]["classes"], serde_json::json!(1));
    assert_eq!(v["handoff_recovered"]["methods"], serde_json::json!(2));
    // 覆盖完全来自 recovered（对账逻辑把恢复物计入覆盖）
    assert_eq!(v["class_coverage"], serde_json::json!(1.0));
    assert_eq!(v["method_coverage"], serde_json::json!(1.0));
}

#[test]
fn register_rejects_orig_without_packed() {
    let dir = std::env::temp_dir().join("ci_verify_broken");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lonely.orig.apk"), b"fake").unwrap();
    let err = ci_verify::register(&dir).expect_err("unpaired orig must fail");
    assert!(err.contains("lonely"), "{err}");
}
