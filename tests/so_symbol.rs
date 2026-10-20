//! 符号定位段测试：JNI 名推导（格式事实）+ ELF 导出表解析（敌意防线）
//! + first_pass 集成（debt facts 从"body outside DEX"升级到"symbol → so"）。

mod common;
use exuvia::track_a::elf;
use exuvia::track_a::jni;

#[test]
fn jni_name_derivation_is_mechanical() {
    // 短名：. → _
    assert_eq!(jni::short_name("com.example.NativeProbe", "nativeFoo"), "Java_com_example_NativeProbe_nativeFoo");
    // mangled：参数逐字符转义（/ → _、; → _2、[ → _3）
    assert_eq!(
        jni::mangled_name("com.example.Foo", "bar", "(Ljava/lang/String;[B)V"),
        "Java_com_example_Foo_bar__Ljava_lang_String_2_3B"
    );
    // 无参重载：mangled 尾部为空（规范形态）
    assert_eq!(jni::mangled_name("com.example.Foo", "bar", "()V"), "Java_com_example_Foo_bar__");
    // candidates 优先级：[短名, mangled]
    let c = jni::candidates("com.example.Foo", "bar", "(I)V");
    assert_eq!(c[0], "Java_com_example_Foo_bar");
    assert_eq!(c[1], "Java_com_example_Foo_bar__I");
}

#[test]
fn elf_exported_symbols_reads_dynsym() {
    let elf_bytes = common::build_minimal_elf(&[
        ("Java_com_example_NativeProbe_nativeFoo", 0x204, 64),
        ("_JNI_OnLoad", 0x300, 32),
    ]);
    let syms = elf::exported_symbols(&elf_bytes).expect("parse elf");
    assert_eq!(syms.len(), 2, "null 条目不入表");
    let target = syms.iter().find(|s| s.name == "Java_com_example_NativeProbe_nativeFoo").expect("hit");
    assert_eq!(target.st_value, 0x204);
    assert_eq!(target.st_size, 64);
}

#[test]
fn elf_symbols_parse_across_el64_architectures() {
    // 修正案 #3 实战修正：符号表是格式事实无架构语义——非 arm64 的 ELF64 照常全解析
    // （曾因 arm64-only 限制丢失同包 x86_64 壳 so 的全部符号情报）
    let mut elf_bytes = common::build_minimal_elf(&[("Java_x_y_z", 0x204, 8)]);
    elf_bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    let syms = elf::exported_symbols(&elf_bytes).expect("parse");
    assert_eq!(syms.len(), 1, "x86_64 ELF64 符号照常读出");
    assert_eq!(syms[0].name, "Java_x_y_z");
}

#[test]
fn elf_rejects_hostile_input() {
    // 敌意防线：坏 magic / 越界 shoff / 巨大 shnum
    assert!(elf::exported_symbols(b"\x7fELFgarbage").is_err());
    let mut elf_bytes = common::build_minimal_elf(&[("a", 0, 8)]);
    elf_bytes[0x28..0x30].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // e_shoff 指向月球
    assert!(elf::exported_symbols(&elf_bytes).is_err(), "范围校验必须先于读表");
    let mut elf_bytes = common::build_minimal_elf(&[("a", 0, 8)]);
    elf_bytes[60..62].copy_from_slice(&0xFFFFu16.to_le_bytes()); // e_shnum 巨大
    assert!(elf::exported_symbols(&elf_bytes).is_err());
}

#[test]
fn first_pass_locates_symbol_in_debt_facts() {
    let dir = std::env::temp_dir().join("exuvia_test_so_symbol");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("synthetic.apk");
    common::build_synthetic_apk(&apk);

    let (report, debt, groups) = exuvia::track_a::first_pass(&apk).expect("first pass");
    assert_eq!(report.debt.total, 1);
    let e = &debt.entries[0];
    assert_eq!(e.method.as_ref().unwrap().name, "nativeFoo");
    // 事实层升级：stub → 具体符号 + so 定位（干扰符号 _JNI_OnLoad 不得误命中）
    let symbol_fact = e.facts.iter().find(|f| f.starts_with("symbol ")).expect("symbol fact present");
    assert!(
        symbol_fact.contains("Java_com_example_NativeProbe_nativeFoo")
            && symbol_fact.contains("lib/arm64-v8a/libtest.so")
            && symbol_fact.contains("st_value=0x204"),
        "got: {symbol_fact}"
    );
    // 切片：VA→文件偏移映射 + 内容字节精确
    assert_eq!(groups.len(), 1);
    let sl = &groups[0].slices[0];
    assert_eq!(sl.file_offset, 0x1204, "VA 0x204 经 PT_LOAD(p_offset=0x1000) 映射");
    let expected = common::prng_bytes(common::ELF_DATA_SEED, common::ELF_DATA_LEN);
    assert_eq!(sl.bytes, expected[0x204..0x204 + 64]);
    assert_eq!(e.evidence, vec!["evidence/debt-0001/".to_string()]);
    assert!(!e.facts.iter().any(|f| f.contains("_JNI_OnLoad")), "干扰符号不得进入定位事实");
}

#[test]
fn first_pass_reports_symbol_not_found_as_fact() {
    // so 存在但无目标符号：未命中也是事实（未注册 JNI 名/动态注册场景的信号）
    let dir = std::env::temp_dir().join("exuvia_test_so_symbol_miss");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("miss.apk");
    let file = std::fs::File::create(&apk).unwrap();
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();
    w.start_file("classes.dex", opts).unwrap();
    w.write_all(&common::build_minimal_dex()).unwrap();
    w.start_file("lib/arm64-v8a/libother.so", opts).unwrap();
    w.write_all(&common::build_minimal_elf(&[("_unrelated", 0x10, 8)])).unwrap();
    use std::io::Write as _;
    w.finish().unwrap();

    let (_, debt, _) = exuvia::track_a::first_pass(&apk).expect("first pass");
    let e = &debt.entries[0];
    assert!(
        e.facts.iter().any(|f| f.contains("not found in any so export table")),
        "未命中必须如实标注：{:?}",
        e.facts
    );
}

#[test]
fn elf_init_array_located_by_section_name() {
    // .init_array 解析：段名查表 → 位置与条目数（解密例程候选的机械定位器）
    let elf_bytes = common::build_minimal_elf_v2(&[("a", 0x10, 8)], &[0x200, 0x210]);
    let ia = elf::init_array(&elf_bytes).expect("parse").expect("init_array present");
    assert_eq!(ia.entry_count, 2);
    assert_eq!(ia.size, 16);
    // 无 .init_array 的 so：None（事实，不是错误）
    let plain = common::build_minimal_elf(&[("a", 0x10, 8)]);
    assert!(elf::init_array(&plain).expect("parse").is_none());
}

#[test]
fn elf_dynamic_path_survives_stripped_sections() {
    // 修正案 #3：壳 so 剥 section header（e_shnum=0）——PT_DYNAMIC 运行时视角独立可解析
    let elf_bytes = common::build_minimal_elf_v3(
        &[
            ("Java_com_example_NativeProbe_nativeFoo", 0x1204, 64), // identity 映射：VA == 文件偏移
            ("DynCryptor_like", 0x1280, 32),
            ("JNI_OnLoad", 0x1300, 32),
        ],
        &[0x1100, 0x1110, 0x1120],
    );
    // 双路径取动态侧：符号全出（含 st_value/st_size）
    let syms = elf::exported_symbols(&elf_bytes).expect("parse");
    assert_eq!(syms.len(), 3, "{:?}", syms.iter().map(|s| &s.name).collect::<Vec<_>>());
    assert_eq!(syms[0].name, "Java_com_example_NativeProbe_nativeFoo");
    assert_eq!(syms[2].name, "JNI_OnLoad");
    assert_eq!(syms[2].st_value, 0x1300);
    assert_eq!(syms[2].st_size, 32);
    // init_array 走 DT_INIT_ARRAY（linker 真正执行的清单）
    let ia = elf::init_array(&elf_bytes).expect("parse").expect("DT_INIT_ARRAY");
    assert_eq!(ia.entry_count, 3);
    assert_eq!(ia.size, 24);
    // 剥壳后切片映射仍可用（identity：st_value → 文件偏移）
    assert_eq!(
        elf::va_to_file_offset(&elf_bytes, 0x1300).expect("map"),
        0x1300
    );
}
