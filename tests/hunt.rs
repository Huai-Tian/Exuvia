//! L2 参数空间搜索器测试——零样本纪律：全部自造 fixture（独立 RC4 双实现交叉验证，
//! 与第一战 unicorn/python 双实现哲学同源）。核心锚定：
//! ① 判据链命中（offset / cipher_len / payload round-trip）；
//! ② zlib 流边界自决（consumed 不受尾部垃圾影响）；
//! ③ 诚实负事实（无命中不沉默）；
//! ④ run() 落盘契约（hunt.json + hits/<n>.dex）。

mod common;
use exuvia::track_a::hunt::{self, Predicate, Rc4Params};

/// 测试内独立 RC4 实现（KSA/PRGA 公开标准）——加密 fixture 用，
/// 与 hunt::rc4_keystream 构成双实现交叉验证：round-trip 对上 = 两实现一致。
fn rc4_xor_indep(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|&b| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

/// 测试内独立**变体** RC4 实现（第一战形态：i/j 种子 3/5、i+=2、j+=S[i]+1）
/// ——与 hunt 的参数化 PRGA 交叉验证（Battle-1 汇编蒸馏语义的独立复现）。
fn rc4_variant_xor_indep(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (3usize, 5usize);
    data.iter()
        .map(|&b| {
            i = (i + 2) % 256;
            j = (j + s[i] as usize + 1) % 256;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn hunt_finds_rc4_zlib_dex_in_ocean() {
    let dex = common::build_minimal_dex();
    let cipher = rc4_xor_indep(&[0x11, 0x22, 0x33, 0x44, 0x55], &zlib_compress(&dex));
    let prefix = common::prng_bytes(0xAA, 4096);
    let suffix = common::prng_bytes(0xBB, 64);
    let mut carrier = prefix.clone();
    carrier.extend_from_slice(&cipher);
    carrier.extend_from_slice(&suffix);

    let (hits, dexes, negs) = hunt::hunt(&carrier, &[Predicate::Rc4 { key: vec![0x11, 0x22, 0x33, 0x44, 0x55], params: Rc4Params::default() }]);

    assert_eq!(hits.len(), 1, "exactly one hit expected (ocean pseudohits must be filtered by the chain)");
    let h = &hits[0];
    assert_eq!(h.offset, prefix.len());
    assert_eq!(h.cipher_len, cipher.len(), "zlib stream boundary self-decides cipher length (trailing ocean excluded)");
    assert_eq!(h.chain, vec!["zlib-magic", "inflate-ok", "dex-magic", "dex-parse-ok"]);
    assert_eq!(h.payload_methods, 2);
    assert_eq!(&dexes[0], &dex, "payload round-trips to the original DEX (dual-implementation RC4 cross-check)");
    assert!(negs.is_empty());
}

#[test]
fn hunt_finds_xor_dex_direct() {
    let dex = common::build_minimal_dex();
    let key = [0x5Au8, 0xC3, 0x0F];
    let cipher: Vec<u8> = dex.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
    let prefix = common::prng_bytes(0x77, 512);
    let mut carrier = prefix.clone();
    carrier.extend_from_slice(&cipher);

    let (hits, dexes, _negs) = hunt::hunt(&carrier, &[Predicate::Xor { key: key.to_vec() }]);

    assert_eq!(hits.len(), 1);
    let h = &hits[0];
    assert_eq!(h.offset, prefix.len());
    assert_eq!(h.cipher_len, dex.len(), "DEX header file_size field self-decides cipher length");
    assert_eq!(h.chain, vec!["dex-magic", "dex-parse-ok"]);
    assert_eq!(&dexes[0], &dex);
}

#[test]
fn hunt_negative_facts_when_no_hit() {
    // 纯随机海洋：两谓词全空间扫描皆无命中 → 每谓词一条诚实负事实（不沉默）
    let carrier = common::prng_bytes(0xC0FFEE, 8192);
    let (hits, dexes, negs) = hunt::hunt(
        &carrier,
        &[
            Predicate::Rc4 { key: vec![0x42; 16], params: Rc4Params::default() },
            Predicate::Xor { key: vec![0x99, 0x37] },
        ],
    );
    assert!(hits.is_empty());
    assert!(dexes.is_empty());
    assert_eq!(negs.len(), 2, "one negative fact per predicate");
    assert!(negs.iter().all(|n| n.contains("no decrypt hit")), "negatives must state the scan model");
}

#[test]
fn hunt_wrong_key_is_negative_not_hallucination() {
    // 正确嵌入 + 错误 key：解不出 = 不产出（诚实性：hunt 不撒谎）
    let dex = common::build_minimal_dex();
    let cipher = rc4_xor_indep(&[0xDE, 0xAD], &zlib_compress(&dex));
    let mut carrier = common::prng_bytes(0x11, 256);
    carrier.extend_from_slice(&cipher);

    let (hits, _, negs) = hunt::hunt(&carrier, &[Predicate::Rc4 { key: vec![0xBE, 0xEF], params: Rc4Params::default() }]);
    assert!(hits.is_empty());
    assert_eq!(negs.len(), 1);
}

#[test]
fn hunt_run_persists_artifacts() {
    let dex = common::build_minimal_dex();
    let cipher = rc4_xor_indep(&[0x0A, 0x0B, 0x0C], &zlib_compress(&dex));
    let mut carrier = common::prng_bytes(0x33, 1024);
    carrier.extend_from_slice(&cipher);

    let dir = std::env::temp_dir().join(format!("exuvia-hunt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let carrier_path = dir.join("carrier.bin");
    std::fs::write(&carrier_path, &carrier).unwrap();

    let out = dir.join("hunt");
    let file = hunt::run(&carrier_path, &[Predicate::Rc4 { key: vec![0x0A, 0x0B, 0x0C], params: Rc4Params::default() }], &out).unwrap();

    // 落盘契约：hunt.json（serde 类型即格式）+ hits/<n>.dex（机械证据存档）
    let raw = std::fs::read(out.join("hunt.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["schema"], "exuvia.hunt");
    assert_eq!(v["carrier"]["size"], carrier.len());
    assert_eq!(v["hits"][0]["payload_path"], "hits/0.dex");

    let dex_out = std::fs::read(out.join("hits/0.dex")).unwrap();
    assert_eq!(dex_out, dex, "archived hit must equal the embedded original DEX");
    assert_eq!(file.hits.len(), 1);
    assert_eq!(file.carrier.size, carrier.len());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hex_parsing_contract() {
    assert_eq!(hunt::hex_to_bytes("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(hunt::hex_to_bytes("abc").is_err(), "odd length rejected");
    assert!(hunt::hex_to_bytes("zz").is_err(), "non-hex rejected");
    assert!(hunt::hex_to_bytes("").is_err() || hunt::hex_to_bytes("").unwrap().is_empty());
}

#[test]
fn hunt_finds_variant_rc4_payload_in_ocean() {
    // 第一战实测变体形态（stride=2, seed=3:5, jbias=1）：独立实现加密 →
    // 参数化谓词解密——PRGA 参数空间的交叉验证（汇编蒸馏语义 vs 独立复现）。
    let dex = common::build_minimal_dex();
    let key = [0x76u8, 0x56, 0x57, 0x34, 0x23, 0x91, 0x23, 0x53, 0x56, 0x74]; // Battle-1 static key
    let cipher = rc4_variant_xor_indep(&key, &zlib_compress(&dex));
    let prefix = common::prng_bytes(0x7E11, 2048);
    let mut carrier = prefix.clone();
    carrier.extend_from_slice(&cipher);

    let params = Rc4Params { stride: 2, i_seed: 3, j_seed: 5, jbias: 1 };
    let (hits, dexes, negs) = hunt::hunt(&carrier, &[Predicate::Rc4 { key: key.to_vec(), params }]);

    assert_eq!(hits.len(), 1, "variant predicate must hit where standard RC4 cannot");
    assert_eq!(hits[0].offset, prefix.len());
    assert_eq!(hits[0].cipher_len, cipher.len());
    assert_eq!(hits[0].chain, vec!["zlib-magic", "inflate-ok", "dex-magic", "dex-parse-ok"]);
    assert_eq!(&dexes[0], &dex);
    assert!(negs.is_empty());
    // 标准参数对同一密文必然零命中（负向对照：变体不是标准 RC4）
    let (std_hits, _, std_negs) =
        hunt::hunt(&carrier, &[Predicate::Rc4 { key: key.to_vec(), params: Rc4Params::default() }]);
    assert!(std_hits.is_empty(), "standard RC4 must NOT decrypt the variant stream");
    assert_eq!(std_negs.len(), 1);
}
