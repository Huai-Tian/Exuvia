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
fn elf_non_arm64_returns_empty_not_error() {
    // 非 arm64：空表（事实，不是错误——多 ABI 清点场景的诚实输出）
    let mut elf_bytes = common::build_minimal_elf(&[("Java_x_y_z", 0, 8)]);
    elf_bytes[18..20].copy_from_slice(&40u16.to_le_bytes()); // e_machine = EM_ARM
    assert_eq!(elf::exported_symbols(&elf_bytes).unwrap(), Vec::new());
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

    let (report, debt, slices) = exuvia::track_a::first_pass(&apk).expect("first pass");
    assert_eq!(report.debt.total, 1);
    let e = &debt.entries[0];
    assert_eq!(e.method.name, "nativeFoo");
    // 事实层升级：stub → 具体符号 + so 定位（干扰符号 _JNI_OnLoad 不得误命中）
    let symbol_fact = e.facts.iter().find(|f| f.starts_with("symbol ")).expect("symbol fact present");
    assert!(
        symbol_fact.contains("Java_com_example_NativeProbe_nativeFoo")
            && symbol_fact.contains("lib/arm64-v8a/libtest.so")
            && symbol_fact.contains("st_value=0x204"),
        "got: {symbol_fact}"
    );
    // 切片：VA→文件偏移映射 + 内容字节精确
    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].file_offset, 0x1204, "VA 0x204 经 PT_LOAD(p_offset=0x1000) 映射");
    let expected = common::prng_bytes(common::ELF_DATA_SEED, common::ELF_DATA_LEN);
    assert_eq!(slices[0].bytes, expected[0x204..0x204 + 64]);
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
