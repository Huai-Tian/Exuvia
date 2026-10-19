//! 合成 APK 竖切测试——零样本纪律的落地：仓库永不出现真实样本，
//! CI 用合成物（zip 构造的 APK 形状）验证 track_a 第一段全链。

use exuvia::track_a::first_pass;
use std::io::Write;

/// 固定 seed 的 xorshift64* 伪随机（测试可复现，无随机依赖）
fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
        })
        .collect()
}

/// uleb128 编码（builder 侧）
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

/// 最小合法 DEX：一个类、两个方法（一个 ACC_NATIVE stub、一个普通）。
/// 全部表结构真实（header/string_ids/type_ids/proto_ids/method_ids/class_defs/class_data）。
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
    put!(0x20, 0u32); // file_size，末尾修正
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
    // proto: shorty_idx=3, return_type_idx=2(V), parameters_off=type_list
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(type_list_off as u32).to_le_bytes());
    // type_list: size=1 → [Context(1)]
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    // method_ids: nativeFoo(class 0,proto 0,name 4) / plainFoo(class 0,proto 0,name 5)
    for (_, _, n) in [(0u32, 0u32, 4u32), (0, 0, 5)] {
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
    }
    // class_def: class_idx 0, access 0, super none, interfaces 0, source 6, annot 0, class_data_off, static 0
    for v in [0u32, 0, 0xFFFF_FFFF, 0, 6, 0, class_data_off as u32, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // class_data: 0/0/2/0，nativeFoo(diff 0, ACC_NATIVE 0x100, code 0)，plainFoo(diff 1, 0x1, 0)
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

fn build_synthetic_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    // AndroidManifest.xml：二进制 XML，此段不解析，仅清点存在性
    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff]).unwrap();

    // classes.dex：最小合法 DEX（真表结构，含 1 个 ACC_NATIVE stub）
    w.start_file("classes.dex", opts).unwrap();
    w.write_all(&build_minimal_dex()).unwrap();

    // assets/payload.bin：伪随机 4096 字节 → 高熵（加密 asset 信号）
    w.start_file("assets/payload.bin", opts).unwrap();
    w.write_all(&prng_bytes(42, 4096)).unwrap();

    // assets/readme.txt：双字节交替（分布熵 = 1.0 bit/byte）——低熵对照。
    // 注：真实英语文本熵约 3.7-4.1（字母分布），不是低熵。
    w.start_file("assets/readme.txt", opts).unwrap();
    let low = (0..4096).map(|i| if i % 2 == 0 { b'a' } else { b'b' }).collect::<Vec<u8>>();
    w.write_all(&low).unwrap();

    // lib/arm64-v8a/libtest.so：假 ELF 头 + 文本
    w.start_file("lib/arm64-v8a/libtest.so", opts).unwrap();
    let mut so = b"\x7fELF".to_vec();
    so.extend_from_slice(&prng_bytes(99, 256));
    w.write_all(&so).unwrap();

    // 无关条目（res/ 资源）→ other 计数
    w.start_file("res/layout/main.xml", opts).unwrap();
    w.write_all(b"<layout/>").unwrap();

    w.finish().unwrap();
}

#[test]
fn first_pass_inventories_synthetic_apk() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let apk = dir.join("synthetic.apk");
    build_synthetic_apk(&apk);

    let (report, debt) = first_pass(&apk).expect("first pass");

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

    // 熵测量：随机数据高熵、文本低熵（测量正确性的双向锚定）
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
}

#[test]
fn dex_parser_reads_native_flag_and_descriptor() {
    let dex = build_minimal_dex();
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
    let mut dex = build_minimal_dex();
    dex[0x3c..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // string_ids_off 越界
    assert!(exuvia::track_a::dex::parse(&dex).is_err());
    assert!(exuvia::track_a::dex::parse(b"garbage!!").is_err());
}

#[test]
fn first_pass_rejects_non_zip() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("not_an_apk.txt");
    std::fs::write(&bad, b"this is not a zip").unwrap();
    assert!(first_pass(&bad).is_err());
}
