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

fn build_synthetic_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    // AndroidManifest.xml：二进制 XML，此段不解析，仅清点存在性
    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff]).unwrap();

    // classes.dex：真 DEX 头（"dex\n035\0"）+ 填充 → magic_ok = true
    w.start_file("classes.dex", opts).unwrap();
    let mut dex = b"dex\n035\0".to_vec();
    dex.extend_from_slice(&prng_bytes(7, 512));
    w.write_all(&dex).unwrap();

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

    let report = first_pass(&apk).expect("first pass");

    // apk 基本事实
    assert!(report.apk.sha256.starts_with("sha256:"));
    assert!(report.apk.size_bytes > 0);
    assert_eq!(report.schema, "exuvia.report");
    assert_eq!(report.handoff_version, exuvia::version::HANDOFF_VERSION);

    // 指纹：fence 无配置 → 未知族主线（正常态）
    assert!(!report.fingerprint.matched);
    assert!(report.fingerprint.family.is_none());

    // DEX：1 个，magic 格式事实通过
    assert_eq!(report.inventory.dex.len(), 1);
    assert_eq!(report.inventory.dex[0].name, "classes.dex");
    assert!(report.inventory.dex[0].magic_ok);

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
}

#[test]
fn first_pass_rejects_non_zip() {
    let dir = std::env::temp_dir().join("exuvia_test_apk");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("not_an_apk.txt");
    std::fs::write(&bad, b"this is not a zip").unwrap();
    assert!(first_pass(&bad).is_err());
}
