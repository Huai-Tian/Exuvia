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

    let (report, debt, groups) = first_pass(&apk).expect("first pass");

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
    assert_eq!(e.kind, exuvia::report::DebtKind::MethodNativeStub);
    let m = e.method.as_ref().expect("stub 卡点必有 method");
    assert_eq!(m.class, "com.example.NativeProbe");
    assert_eq!(m.name, "nativeFoo");
    assert_eq!(m.descriptor, "(Landroid/content/Context;)V");
    assert_eq!(e.status, exuvia::report::DebtStatus::BlockedSolvable);
    assert!(e.facts.iter().any(|f| f.contains("ACC_NATIVE")));
    // evidence：符号命中 → 切片引用 + 内容 = so 数据区对应段（VA 0x204 → 文件 0x1204）
    assert_eq!(e.evidence, vec!["evidence/debt-0001/".to_string()]);
    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.debt_id, "debt-0001");
    assert_eq!(g.slices.len(), 1);
    let sl = &g.slices[0];
    assert_eq!(sl.st_value, Some(0x204));
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
fn first_pass_handles_shell_style_assets_elf() {
    // 修正案 #1/#2：壳 so 藏 assets——ELF magic 纳入清点与符号查表；so 内明文 DEX 机械扫描
    let dir = std::env::temp_dir().join("exuvia_test_shell_style");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("shell.apk");
    common::build_shell_style_apk(&apk);

    let (report, debt, groups) = first_pass(&apk).expect("first pass");

    // 修正案 #1：assets ELF 进 so 清点（ABI 由 e_machine 映射）
    let shell_so: Vec<_> = report.inventory.so.iter().filter(|s| s.name.starts_with("assets/")).collect();
    assert_eq!(shell_so.len(), 2, "{:?}", report.inventory.so);
    let a64 = shell_so.iter().find(|s| s.name == "assets/libshell_a64.so").unwrap();
    assert_eq!(a64.abi, "arm64-v8a", "e_machine=EM_AARCH64 的机械映射");

    // 修正案 #1：stub 符号查表现在覆盖 assets so → 命中 + 切片
    let stub = debt.entries.iter().find(|e| e.kind == exuvia::report::DebtKind::MethodNativeStub).unwrap();
    assert!(
        stub.facts.iter().any(|f| f.contains("Java_com_example_NativeProbe_nativeFoo") && f.contains("assets/libshell_a64.so")),
        "stub 符号必须命中 assets 壳 so：{:?}",
        stub.facts
    );
    assert_eq!(stub.evidence.len(), 1);
    let stub_g = groups.iter().find(|g| g.debt_id == stub.debt_id).unwrap();
    assert_eq!(stub_g.slices[0].source, "assets/libshell_a64.so");

    // 修正案 #2：payload 卡点三态——命中（明文 DEX 提取）+ 零命中（负事实）
    let payloads: Vec<_> = debt.entries.iter().filter(|e| e.kind == exuvia::report::DebtKind::EncryptedPayload).collect();
    assert_eq!(payloads.len(), 2, "命中卡点 + 零命中卡点：{:?}", payloads.len());
    // 排序：a64 命中在前
    assert_eq!(payloads[0].evidence, vec!["evidence/debt-0002/".to_string()]);
    assert!(payloads[0].facts[0].contains("plaintext DEX found in assets/libshell_a64.so at offset"), "{}", payloads[0].facts[0]);
    assert!(payloads[1].facts[0].contains("assets ELF assets/libshell_plain.so: no plaintext DEX magic found"), "{}", payloads[1].facts[0]);

    // 命中切片：字节精确 = 尾部追加的 minimal dex；候选只挂自身 so
    let hit_g = groups.iter().find(|g| g.debt_id == payloads[0].debt_id).unwrap();
    let emb = hit_g.slices.iter().find(|s| s.name.contains("embedded")).expect("embedded slice");
    assert_eq!(emb.bytes, common::build_minimal_dex(), "提取字节 = 嵌入的 DEX 全量");
    assert!(hit_g.slices.iter().any(|s| s.name.ends_with("JNI_OnLoad")), "命中卡点挂该 so 的 JNI_OnLoad 候选切片");
    // 零命中卡点无切片
    let miss_g = groups.iter().find(|g| g.debt_id == payloads[1].debt_id).unwrap();
    assert!(miss_g.slices.iter().all(|s| s.name.contains("JNI_OnLoad") == false || s.source == "assets/libshell_plain.so"));
}

#[test]
fn first_pass_rejects_non_zip() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("not_an_apk.txt");
    std::fs::write(&bad, b"this is not a zip").unwrap();
    assert!(first_pass(&bad).is_err());
}

#[test]
fn first_pass_generates_encrypted_payload_debt() {
    // 一代壳形态竖切：坏 DEX → encrypted-payload 卡点，解密例程候选与切片齐备
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("encrypted.apk");
    common::build_encrypted_apk(&apk);

    let (report, debt, groups) = first_pass(&apk).expect("first pass");

    // 卡点编号：method-native-stub 在前（debt-0001），encrypted-payload 在后（debt-0002）
    assert_eq!(debt.entries.len(), 2);
    assert_eq!(report.debt.total, 2);
    let stub = &debt.entries[0];
    assert_eq!((stub.debt_id.as_str(), stub.kind), ("debt-0001", exuvia::report::DebtKind::MethodNativeStub));
    assert!(stub.method.is_some());
    let pl = &debt.entries[1];
    assert_eq!((pl.debt_id.as_str(), pl.kind), ("debt-0002", exuvia::report::DebtKind::EncryptedPayload));
    assert!(pl.method.is_none(), "payload 卡点无 method");
    assert_eq!(pl.evidence, vec!["evidence/debt-0002/".to_string()]);

    // facts：坏 DEX 机械事实 + asset 原始熵清单（无阈值判断）+ 解密例程候选（机械定位器）
    assert!(pl.facts[0].contains("claimed-DEX file classes2.dex with non-DEX magic"), "{:?}", pl.facts[0]);
    assert!(pl.facts.iter().any(|f| f.starts_with("asset assets/payload.bin: 4096 bytes, entropy")), "{:?}", pl.facts);
    let onload = pl.facts.iter().find(|f| f.starts_with("decrypt-routine candidate JNI_OnLoad")).expect("JNI_OnLoad candidate fact");
    assert!(onload.contains("st_value=0x300") && onload.contains("lib/arm64-v8a/libtest.so"), "{onload}");
    assert!(
        pl.facts.iter().any(|f| f.starts_with("init_array: 2 entries") && f.contains("lib/arm64-v8a/libtest.so")),
        "{:?}",
        pl.facts
    );

    // evidence 组：坏 DEX 头切片 + JNI_OnLoad 方法体切片（多切片共存，修复旧覆盖 bug 的形态验证）
    let g2 = groups.iter().find(|g| g.debt_id == "debt-0002").expect("payload evidence group");
    assert_eq!(g2.slices.len(), 2, "{:?}", g2.slices.iter().map(|s| &s.name).collect::<Vec<_>>());
    let head = &g2.slices[0];
    assert_eq!(head.name, "classes2.dex");
    assert_eq!(head.source, "classes2.dex");
    assert_eq!(head.symbol, None);
    assert_eq!(head.st_value, None);
    assert_eq!(head.file_offset, 0);
    assert_eq!(head.bytes, common::prng_bytes(99, 4096), "4096 < 64KiB，头切片 = 全量");
    let onload_slice = &g2.slices[1];
    assert_eq!(onload_slice.name, "lib-arm64-v8a-libtest.so--JNI_OnLoad");
    assert_eq!(onload_slice.symbol.as_deref(), Some("JNI_OnLoad"));
    assert_eq!(onload_slice.file_offset, 0x1300, "VA 0x300 → 文件 0x1300");
    let data = common::prng_bytes(common::ELF_DATA_SEED, common::ELF_DATA_LEN);
    assert_eq!(onload_slice.bytes, data[0x300..0x320]);
}
