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

// ── AES-128-CBC tail 容器谓词（剖面 aes128cbc-tail-v1，第二战族知识）──────────
// 双锚纪律：解密方向由 NIST SP 800-38A 已知答案独立锚定（不依赖本 crate 加密）；
// fixture 加密方向用本 crate 构造（容器格式本身由 trackb/dexcontainer.py 锚定）。

/// NIST SP 800-38A F.2.1 CBC-AES128 已知答案：hunt 的解密原语必须逐字节
/// 复现明文向量——解密方向由外部权威锚定，而非本 crate 加密方向的自证。
#[test]
fn aes_cbc_decrypt_nist_kat() {
    let key = hunt::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hunt::hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
    let pt = hunt::hex_to_bytes(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ))
    .unwrap();
    let ct = hunt::hex_to_bytes(concat!(
        "7649abac8119b246cee98e9b12e9197d",
        "5086cb9b507219ee95db113a917678b2",
        "73bed6b8e3c1743b7116e69e22229516",
        "3ff1caa1681fac09120eca307586e1a7"
    ))
    .unwrap();
    assert_eq!(hunt::aes128_cbc_decrypt(&key, &iv, &ct).unwrap(), pt, "decrypt must reproduce NIST SP 800-38A F.2.1 plaintext");
    // 畸形输入契约：非 16 对齐 / 非 16B key-iv → None（负事实路径，不 panic）
    assert!(hunt::aes128_cbc_decrypt(&key, &iv, &ct[..17]).is_none());
    assert!(hunt::aes128_cbc_decrypt(&key[..8], &iv, &ct).is_none());
}

/// fixture 构造器：AES-128-CBC 加密（手工链接，与 hunt 解密同 crate 对向）。
fn aes128_cbc_encrypt_blocks(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert_eq!(data.len() % 16, 0);
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut out = data.to_vec();
    let mut prev: [u8; 16] = iv.try_into().unwrap();
    for chunk in out.chunks_exact_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        prev = chunk.try_into().unwrap();
    }
    out
}

/// 合成 aes128cbc-tail-v1 容器：[stub][加密头块][dex#1 明文体][子容器]*[BE32 trailer]。
/// enc_len 显式给定（≠ 族默认 0x210 时即演练头块长度扫描路径）；
/// subs 的 bool = 是否按族默认（0x70/0x66）XOR 剥离存放。
fn build_tail_container(
    stub: &[u8],
    name: &str,
    dex1: &[u8],
    subs: &[(&[u8], bool)],
    key: &[u8],
    iv: &[u8],
    enc_len: usize,
) -> Vec<u8> {
    let hdr_off = name.len() + 5;
    let frag_len = dex1.len().min(enc_len - hdr_off - 16);
    let pad = enc_len - hdr_off - frag_len;
    assert!((1..=16).contains(&pad), "fixture enc_len leaves no room for pkcs7 pad");
    let mut pt = Vec::with_capacity(enc_len);
    pt.push(name.len() as u8);
    pt.extend_from_slice(name.as_bytes());
    pt.push(0);
    pt.extend_from_slice(&(dex1.len() as u32).to_be_bytes()[1..]); // 3B BE fsize
    pt.extend_from_slice(&dex1[..frag_len]);
    pt.extend(std::iter::repeat(pad as u8).take(pad));
    assert_eq!(pt.len(), enc_len);

    let mut carrier = stub.to_vec();
    carrier.extend_from_slice(&aes128_cbc_encrypt_blocks(key, iv, &pt));
    carrier.extend_from_slice(&dex1[frag_len..]);
    for (sub, strip) in subs {
        let mut p = sub.to_vec();
        if *strip {
            for b in p.iter_mut().take(0x70) {
                *b ^= 0x66;
            }
        }
        carrier.extend_from_slice(&(p.len() as u32).to_be_bytes());
        carrier.extend_from_slice(&p);
    }
    carrier.extend_from_slice(&(stub.len() as u32).to_be_bytes()); // trailer = BE32 容器起点
    carrier
}

#[test]
fn hunt_finds_aes_tail_container_trailer_anchor() {
    let dex1 = common::build_minimal_dex();
    let sub_raw = common::build_minimal_dex();
    let sub_stripped = common::build_minimal_dex();
    let key = b"0123456789abcdef";
    let iv = b"fedcba9876543210";
    let stub = common::prng_bytes(0x5A1E, 0x123); // 非 16 对齐 stub：块边界相对容器起点
    let enc_len = 0x50; // ≠ 族默认 → 头块长度扫描路径
    let carrier = build_tail_container(
        &stub,
        "com.test.App",
        &dex1,
        &[(&sub_raw, false), (&sub_stripped, true)],
        key,
        iv,
        enc_len,
    );

    let (hits, dexes, negs) = hunt::hunt(
        &carrier,
        &[Predicate::AesCbc { key: key.to_vec(), iv: iv.to_vec(), params: hunt::AesCbcTailParams::default() }],
    );

    assert_eq!(hits.len(), 3, "dex#1 + raw sub + stripped sub");
    assert!(negs.is_empty());
    let frag_len = dex1.len().min(enc_len - ("com.test.App".len() + 5) - 16);
    let body_len = dex1.len() - frag_len;
    let h0 = &hits[0];
    assert_eq!(h0.offset, stub.len());
    assert_eq!(h0.cipher_len, enc_len + body_len);
    assert_eq!(
        h0.chain,
        vec![
            "cbc-anchor-trailer".to_string(),
            format!("cbc-header-decrypt(enc_len=0x{enc_len:x})"),
            "dex-magic".to_string(),
            "dex-parse-ok".to_string(),
            "sub-walk(2 dex, 0 non-dex skipped)".to_string(),
        ]
    );
    assert_eq!(&dexes[0], &dex1, "dex#1 round-trips (header fragment + plaintext body)");

    let sub1_off = stub.len() + enc_len + body_len;
    let h1 = &hits[1];
    assert_eq!(h1.offset, sub1_off);
    assert_eq!(h1.cipher_len, 4 + sub_raw.len());
    assert!(h1.chain.contains(&"raw-payload".to_string()));
    assert_eq!(&dexes[1], &sub_raw);

    let h2 = &hits[2];
    assert_eq!(h2.offset, sub1_off + 4 + sub_raw.len());
    assert!(h2.chain.contains(&"xor-prefix-strip".to_string()));
    assert_eq!(&dexes[2], &sub_stripped, "XOR prefix strip restores the stored sub dex");
}

#[test]
fn hunt_aes_tail_scan_anchor_when_trailer_absent() {
    // 载体为切片（trailer 失真）→ 全范围锚点扫描路径必须同样命中
    let dex1 = common::build_minimal_dex();
    let key = b"0123456789abcdef";
    let iv = b"fedcba9876543210";
    let stub = common::prng_bytes(0x0CEA, 0x87);
    let mut carrier = build_tail_container(&stub, "com.test.App", &dex1, &[], key, iv, 0x50);
    let n = carrier.len();
    carrier[n - 4..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // trailer 失真

    let (hits, dexes, negs) = hunt::hunt(
        &carrier,
        &[Predicate::AesCbc { key: key.to_vec(), iv: iv.to_vec(), params: hunt::AesCbcTailParams::default() }],
    );

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].offset, stub.len());
    assert_eq!(hits[0].chain[0], "cbc-anchor-scan");
    assert_eq!(&dexes[0], &dex1);
    assert!(negs.is_empty());
}

#[test]
fn hunt_aes_tail_wrong_key_is_negative_not_hallucination() {
    let dex1 = common::build_minimal_dex();
    let key = b"0123456789abcdef";
    let iv = b"fedcba9876543210";
    let stub = common::prng_bytes(0xBAD, 0x40);
    let carrier = build_tail_container(&stub, "com.test.App", &dex1, &[], key, iv, 0x50);

    let (hits, dexes, negs) = hunt::hunt(
        &carrier,
        &[Predicate::AesCbc {
            key: b"0000000000000000".to_vec(),
            iv: iv.to_vec(),
            params: hunt::AesCbcTailParams::default(),
        }],
    );
    assert!(hits.is_empty());
    assert!(dexes.is_empty());
    assert_eq!(negs.len(), 1);
    assert!(negs[0].contains("aes128cbc-tail-v1"), "negative fact must state the container model");
    assert!(negs[0].contains("no container hit"));
}

#[test]
fn key_spec_hex_or_ascii_contract() {
    assert_eq!(hunt::key_spec_bytes("deadbeefdeadbeefdeadbeefdeadbeef").unwrap().len(), 16);
    assert_eq!(hunt::key_spec_bytes("bajk3b4j3bvuoa3h").unwrap(), b"bajk3b4j3bvuoa3h");
    // 16 字符全 hex 数字的 ASCII key：hex 先得 8B ≠ 16B → 回落 ASCII（无歧义）
    assert_eq!(hunt::key_spec_bytes("0123456789abcdef").unwrap(), b"0123456789abcdef");
    assert!(hunt::key_spec_bytes("short").is_err());
    assert!(hunt::key_spec_bytes("deadbeef").is_err(), "8B hex is not a key");
}
