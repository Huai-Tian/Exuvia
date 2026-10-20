//! 洋葱二次分析（`exuvia analyze --dex`）：解卡产物回注剖析器。
//! 验收：合成 DEX → analyze_dex → 与 first_pass 同一协议格式的欠账地图；
//! 同一消费端（next --goal / merge）无缝衔接——二次卡点走同一外包循环。

mod common;

#[test]
fn reanalyze_produces_next_layer_debt_map() {
    let dir = std::env::temp_dir().join("exuvia_test_reanalyze");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 合成 DEX（common fixture：NativeProbe.nativeFoo = ACC_NATIVE stub）
    let dex_bytes = common::build_minimal_dex();
    let dex_path = dir.join("recovered.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let out = dir.join("handoff-2");
    let debt = exuvia::track_a::reanalyze::analyze_dex(&dex_path, &out).unwrap();

    // 协议形态：schema + 版本 + 稳定 debt_id（与 first_pass 的 debt.json 同构）
    assert_eq!(debt.schema, "exuvia.debt");
    assert_eq!(debt.handoff_version, exuvia::version::HANDOFF_VERSION);
    assert_eq!(debt.entries.len(), 1, "exactly the native stub becomes a debt entry");
    let e = &debt.entries[0];
    assert_eq!(e.debt_id, "debt-0001");
    assert_eq!(e.kind, exuvia::report::DebtKind::MethodNativeStub);
    let m = e.method.as_ref().unwrap();
    assert_eq!(m.class, "Lcom/example/NativeProbe;");
    assert_eq!(m.name, "nativeFoo");
    // 事实层：无判断的机械事实 + 本层上下文说明（单 DEX 无 so 上下文）
    assert!(e.facts.iter().any(|f| f.contains("re-analysis")));
    assert!(e.facts.iter().any(|f| f.contains("no so context")));

    // 落盘产物：debt.json 可被反序列化（协议闭环），REPORT.md 存在
    let on_disk: exuvia::report::DebtFile =
        serde_json::from_str(&std::fs::read_to_string(out.join("debt.json")).unwrap()).unwrap();
    assert_eq!(on_disk.entries.len(), 1);
    assert!(out.join("REPORT.md").exists());
}

#[test]
fn reanalyze_clean_dex_yields_empty_map() {
    let dir = std::env::temp_dir().join("exuvia_test_reanalyze_clean");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 干净层：重写 class_data，把两个方法都置为非 native（flags 0x1）。
    // class_data_off 藏在 class_def 条目内（class_defs_off + 24，第 7 个 u32）
    let mut dex_bytes = common::build_minimal_dex();
    let cd_off = u32::from_le_bytes(dex_bytes[0x64..0x68].try_into().unwrap()) as usize;
    let class_data_off =
        u32::from_le_bytes(dex_bytes[cd_off + 24..cd_off + 28].try_into().unwrap()) as usize;
    dex_bytes.truncate(class_data_off);
    // class_data: fields 0/0, direct_methods 2/0, nativeFoo(diff 0, flags 1, code 0), plainFoo(diff 1, flags 1, code 0)
    for v in [0u32, 0, 2, 0, 0, 1, 0, 1, 1, 0] {
        dex_bytes.extend_from_slice(&common::uleb_bytes(v));
    }
    let n = dex_bytes.len() as u32;
    dex_bytes[0x20..0x24].copy_from_slice(&n.to_le_bytes());

    let dex_path = dir.join("recovered.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let out = dir.join("handoff-2");
    let debt = exuvia::track_a::reanalyze::analyze_dex(&dex_path, &out).unwrap();
    assert!(debt.entries.is_empty(), "clean layer: no debt at this depth");
    let report = std::fs::read_to_string(out.join("REPORT.md")).unwrap();
    assert!(report.contains("No debt at this layer"));
}

#[test]
fn reanalyze_bad_dex_becomes_payload_debt() {
    let dir = std::env::temp_dir().join("exuvia_test_reanalyze_bad");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 坏 DEX（magic 不符）→ 容器层卡点（与 first_pass 坏 DEX 路径同款语义）
    let dex_path = dir.join("recovered.dex");
    std::fs::write(&dex_path, b"not-a-dex-at-all").unwrap();

    let out = dir.join("handoff-2");
    let debt = exuvia::track_a::reanalyze::analyze_dex(&dex_path, &out).unwrap();
    assert_eq!(debt.entries.len(), 1);
    assert_eq!(debt.entries[0].kind, exuvia::report::DebtKind::EncryptedPayload);
    assert!(debt.entries[0].facts.iter().any(|f| f.contains("dex parse failed")));
}
