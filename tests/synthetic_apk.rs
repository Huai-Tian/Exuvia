//! 合成 APK 竖切测试——零样本纪律的落地：仓库永不出现真实样本，
//! CI 用合成物（zip 构造的 APK 形状）验证 track_a 全链。构造器见 tests/common。

mod common;
use common::build_synthetic_apk;
use exuvia::track_a::first_pass;

#[test]
fn first_pass_inventories_synthetic_apk() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("synthetic.apk");
    build_synthetic_apk(&apk);

    let (report, debt, slices) = first_pass(&apk).expect("first pass");

    // apk 基本事实
    assert!(report.apk.sha256.starts_with("sha256:"));
    assert!(report.apk.size_bytes > 0);
    assert_eq!(report.schema, "exuvia.report");
    assert_eq!(report.handoff_version, exuvia::version::HANDOFF_VERSION);

    // 指纹：fence 无配置 → 未知族主线（正常态）
    assert!(!report.fingerprint.matched);
    assert!(report.fingerprint.family.is_none());

    // DEX：1 个，magic + 表结构双通过
    assert_eq!(report.inventory.dex.len(), 1);
    assert_eq!(report.inventory.dex[0].name, "classes.dex");
    assert!(report.inventory.dex[0].magic_ok);
    assert!(report.inventory.dex[0].parse_ok);

    // so：1 个，abi 机械提取
    assert_eq!(report.inventory.so.len(), 1);
    assert_eq!(report.inventory.so[0].abi, "arm64-v8a");

    // 熵测量：随机数据高熵、窄分布低熵（测量正确性的双向锚定）
    assert_eq!(report.inventory.assets.len(), 2);
    let hi = report.inventory.assets.iter().find(|a| a.name == "assets/payload.bin").unwrap();
    let lo = report.inventory.assets.iter().find(|a| a.name == "assets/readme.txt").unwrap();
    assert!(hi.entropy > 7.5, "random data must be high entropy, got {}", hi.entropy);
    assert!(lo.entropy < 1.5, "two-symbol stream must be ~1 bit/byte, got {}", lo.entropy);

    // Manifest 存在性 + other 计数
    assert!(report.inventory.android_manifest_present);
    assert!(report.inventory.other_entries >= 2, "manifest + res entry counted");

    // debt：ACC_NATIVE stub → 1 条欠账（类名 FQCN 形态、descriptor 机械拼装）
    assert_eq!(debt.entries.len(), 1);
    assert_eq!(report.debt.total, 1);
    assert_eq!(report.debt.blocked_solvable, 1);
    let e = &debt.entries[0];
    assert_eq!(e.debt_id, "debt-0001");
    assert_eq!(e.method.class, "com.example.NativeProbe");
    assert_eq!(e.method.name, "nativeFoo");
    assert_eq!(e.method.descriptor, "(Landroid/content/Context;)V");
    assert_eq!(e.status, exuvia::report::DebtStatus::BlockedSolvable);
    assert!(e.facts.iter().any(|f| f.contains("ACC_NATIVE")));
    // evidence：符号命中 → 切片引用 + 内容 = so 数据区对应段（VA 0x204 → 文件 0x1204）
    assert_eq!(e.evidence, vec!["evidence/debt-0001/".to_string()]);
    assert_eq!(slices.len(), 1);
    let sl = &slices[0];
    assert_eq!(sl.st_value, 0x204);
    assert_eq!(sl.file_offset, 0x1204);
    let expected = common::prng_bytes(common::ELF_DATA_SEED, common::ELF_DATA_LEN);
    assert_eq!(sl.bytes, expected[0x204..0x204 + 64], "切片必须精确等于数据区对应字节");
}

#[test]
fn dex_parser_reads_native_flag_and_descriptor() {
    let dex = common::build_minimal_dex();
    let methods = exuvia::track_a::dex::parse(&dex).expect("parse minimal dex");
    assert_eq!(methods.len(), 2, "one class_data with 2 direct methods");
    let native = methods.iter().find(|m| m.name == "nativeFoo").expect("nativeFoo");
    let plain = methods.iter().find(|m| m.name == "plainFoo").expect("plainFoo");
    assert!(native.is_native);
    assert!(!plain.is_native);
    assert_eq!(native.class, "Lcom/example/NativeProbe;");
    assert_eq!(native.descriptor, "(Landroid/content/Context;)V");
}

#[test]
fn dex_parser_rejects_hostile_input() {
    // 敌意输入常态：magic 真但表损坏 → 解析错误（first_pass 侧转 parse_ok=false 事实）
    let mut dex = common::build_minimal_dex();
    dex[0x3c..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // string_ids_off 越界
    assert!(exuvia::track_a::dex::parse(&dex).is_err());
    assert!(exuvia::track_a::dex::parse(b"garbage!!").is_err());
}

#[test]
fn dex_parser_rejects_hostile_table_sizes() {
    // 敌意输入防线回归：伪造 method_ids_size 触发 126GB 分配攻击（第二段实战教训）
    let mut dex = common::build_minimal_dex();
    dex[0x58..0x5c].copy_from_slice(&u32::MAX.to_le_bytes()); // method_ids_size 巨大
    assert!(exuvia::track_a::dex::parse(&dex).is_err(), "表范围校验必须先于分配");
}

#[test]
fn first_pass_rejects_non_zip() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("not_an_apk.txt");
    std::fs::write(&bad, b"this is not a zip").unwrap();
    assert!(first_pass(&bad).is_err());
}
