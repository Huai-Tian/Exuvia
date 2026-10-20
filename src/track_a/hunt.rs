//! L2 参数空间搜索器（`exuvia hunt`）：已知算法 + 未知密文段参数的机械搜索。
//! 背景：轨道 C 桌面化（维护者拍板：摒弃真机/模拟器——成本高，且企业壳
//! 反检测使其在主战场不可行）。解密算法族与 key 由外循环确定后（facts /
//! LLM 复现），调用现场参数（密文段起点/长度）不再是"必须上真机"的运行时
//! 事实，而是机械可搜的有限空间——RC4/zlib 判据链的每一环都是格式事实。
//!
//! 搜索模型（机械假设，负事实如实记录）：密文段 = 载体某起点开始、
//! keystream 从零对齐的连续字节段；长度由判据链自决（zlib 流边界 /
//! DEX header 的 file_size 字段——两个自描述边界，零猜测）。
//! 判据链全机械：zlib magic（RFC 1950 CMF/FLG 校验）→ inflate →
//! DEX magic → dex::parse 全表自洽。
//!
//! 机械边界：谓词族 = rc4（标准 KSA + PRGA 参数空间）与 xor 循环。
//! 变体参数化（r11 产品化，Battle-1 实测形态驱动）：RC4 的 stride/seed/jbias
//! 是算法参数空间的表达（--rc4-stride/--rc4-seed/--rc4-jbias），不是样本特判——
//! 第一战变体（stride=2, seed=3:5, jbias=1）即一行命令。超出参数空间的变体
//! （KSA 改造、双 S-box 等）仍走 proposal 外循环。
//! hunt 不做最终销账：命中的产物只是机械事实，proposal → merge 四层闸门的
//! 判定权链条不变。

use crate::track_a::dex;
use serde::Serialize;

/// RC4 参数空间（stride=1, seed=0:0, jbias=0 即标准 RC4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rc4Params {
    /// i 每轮步长（标准 1）
    pub stride: u32,
    /// PRGA i/j 种子（标准 0:0）
    pub i_seed: u32,
    pub j_seed: u32,
    /// j 额外增量（标准 0；第一战变体 j = j + S[i] + 1 → jbias=1）
    pub jbias: u32,
}

impl Default for Rc4Params {
    fn default() -> Self {
        Rc4Params { stride: 1, i_seed: 0, j_seed: 0, jbias: 0 }
    }
}

/// 搜索谓词：密钥流生成算法（标准族 + 参数化变体）。
#[derive(Debug, Clone)]
pub enum Predicate {
    /// RC4（标准 KSA + 参数化 PRGA），key 外部传入（来源：facts / LLM 复现）
    Rc4 { key: Vec<u8>, params: Rc4Params },
    /// n 字节循环 XOR
    Xor { key: Vec<u8> },
}

impl Predicate {
    /// 报告标签（key 本体不进标签：xor 密钥短直接给，rc4 用 sha 前缀）
    pub fn label(&self) -> String {
        match self {
            Predicate::Rc4 { key, params } => {
                if *params == Rc4Params::default() {
                    format!("rc4(key sha256:{}…)", short_sha(key))
                } else {
                    format!(
                        "rc4-variant(stride={}, seed={}:{}, jbias={}, key sha256:{}…)",
                        params.stride, params.i_seed, params.j_seed, params.jbias, short_sha(key)
                    )
                }
            }
            Predicate::Xor { key } => format!("xor:{}", hex(key)),
        }
    }

    /// 预生成 keystream（长度 = 载体长度）。
    /// 流密码 keystream 只依赖 key 与位置——解密任意起点段 = 查表 XOR，搜索降为 O(n)。
    fn keystream(&self, len: usize) -> Vec<u8> {
        match self {
            Predicate::Rc4 { key, params } => rc4_keystream(key, *params, len),
            Predicate::Xor { key } => (0..len).map(|i| key[i % key.len()]).collect(),
        }
    }
}

/// RC4 keystream（标准 KSA 置换 + 参数化 PRGA 输出）。
/// KSA 固定标准（第一战实证：变体壳的 KSA 与 unicorn 快照逐字节一致——变体在 PRGA）。
pub fn rc4_keystream(key: &[u8], params: Rc4Params, len: usize) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut jj) = (params.i_seed as usize & 0xff, params.j_seed as usize & 0xff);
    let (stride, jbias) = (params.stride.max(1) as usize, params.jbias as usize);
    (0..len)
        .map(|_| {
            i = (i + stride) & 0xff;
            jj = (jj + s[i] as usize + jbias) & 0xff;
            s.swap(i, jj);
            s[(s[i] as usize + s[jj] as usize) & 0xff]
        })
        .collect()
}

/// RFC 1950 zlib 头校验：CM=8（deflate）、FCHECK 整除、FDICT=0。
/// 比"硬编码 0x78"通用（覆盖全部合法 CINFO 窗口），纯机械。
fn is_zlib_magic(a: u8, b: u8) -> bool {
    let cmf = a as u16;
    let flg = b as u16;
    a & 0x0f == 8 && (cmf * 256 + flg) % 31 == 0 && (b & 0x20) == 0
}

/// 从 data 头部解 zlib 流：返回 (解出字节, 流自然消耗的输入长度)。
/// 流边界由 zlib 自终止标志决定（adler32 尾）——consumed 即密文段长度，零猜测。
/// 流未终止 / 坏流 / 超过 1GB 熔断 → None。
fn zlib_inflate_prefix(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(true);
    let mut out = vec![0u8; 1 << 20];
    let (mut filled, mut input_pos) = (0usize, 0usize);
    loop {
        let (before_in, before_out) = (d.total_in(), d.total_out());
        let r = d.decompress(&data[input_pos..], &mut out[filled..], FlushDecompress::None);
        input_pos += (d.total_in() - before_in) as usize;
        filled += (d.total_out() - before_out) as usize;
        match r {
            Ok(Status::StreamEnd) => {
                out.truncate(filled);
                return Some((out, input_pos));
            }
            Ok(_) => {
                // 输入耗尽而流未终止，或输出满需扩容续跑
                if input_pos >= data.len() || out.len() >= 1 << 30 {
                    return None;
                }
                out.resize(out.len() * 2, 0);
            }
            Err(_) => return None, // 坏流（流中坏数据 → 伪命中，弃）
        }
    }
}

/// 单个命中：判据链全过后的机械事实。
#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    /// 命中谓词标签（如 rc4(key sha256:…)）
    pub predicate: String,
    /// 密文段在载体内的起点（字节偏移）
    pub offset: usize,
    /// 密文段长度（zlib 流边界 / DEX file_size 自决，非猜测）
    pub cipher_len: usize,
    /// 判据链逐环记录（如 zlib-magic → inflate-ok → dex-magic → dex-parse-ok）
    pub chain: Vec<String>,
    /// 解出产物长度
    pub payload_len: usize,
    /// 解出产物 sha256
    pub payload_sha256: String,
    /// 解出 DEX 的方法数（dex::parse 机械清点）
    pub payload_methods: usize,
    /// 产物存档相对路径（hits/<n>.dex）
    pub payload_path: String,
}

/// hunt 落盘产物（serde 类型即格式，与协议族同风格）。
#[derive(Serialize)]
pub struct HuntFile {
    pub schema: String,
    pub carrier: CarrierInfo,
    /// 跑过的谓词标签（报告可复现性）
    pub predicates: Vec<String>,
    pub hits: Vec<Hit>,
    /// 诚实负事实（含搜索模型声明）
    pub negative_facts: Vec<String>,
}

#[derive(Serialize)]
pub struct CarrierInfo {
    pub path: String,
    pub sha256: String,
    pub size: usize,
}

/// 核心搜索（纯函数）：carrier × predicates → 命中 + 负事实。
/// 返回 (报告条目, 解出 DEX 字节)——payload 与 hits 平行，CLI 层落盘。
pub fn hunt(carrier: &[u8], predicates: &[Predicate]) -> (Vec<Hit>, Vec<Vec<u8>>, Vec<String>) {
    let mut hits: Vec<Hit> = Vec::new();
    let mut dexes: Vec<Vec<u8>> = Vec::new();
    let mut negatives: Vec<String> = Vec::new();

    for pred in predicates {
        let ks = pred.keystream(carrier.len());
        // D_offset(j) = carrier[offset + j] ^ ks[j]（段内第 j 字节的解密视图）
        let dec = |offset: usize, j: usize| -> u8 { carrier[offset + j] ^ ks[j] };
        let mut pred_hit_count = 0usize;

        for offset in 0..carrier.len() {
            if offset + 4 > carrier.len() {
                break;
            }
            let m = [dec(offset, 0), dec(offset, 1), dec(offset, 2), dec(offset, 3)];

            if &m == b"dex\n" {
                if let Some(h) = try_dex_direct(carrier, &ks, offset, pred) {
                    pred_hit_count += 1;
                    dexes.push(h.1);
                    hits.push(h.0);
                }
            } else if is_zlib_magic(m[0], m[1]) {
                if let Some(h) = try_zlib_then_dex(carrier, &ks, offset, pred) {
                    pred_hit_count += 1;
                    dexes.push(h.1);
                    hits.push(h.0);
                }
            }
        }

        if pred_hit_count == 0 {
            negatives.push(format!(
                "{}: full-range scan of {} offsets — no decrypt hit (model: keystream-zero-aligned segment, chain: zlib-magic/{}dex-magic)",
                pred.label(),
                carrier.len(),
                "inflate-ok/",
            ));
        }
    }

    (hits, dexes, negatives)
}

/// DEX magic 直接命中：file_size 字段自决长度 → dex::parse 验证。
fn try_dex_direct(carrier: &[u8], ks: &[u8], offset: usize, pred: &Predicate) -> Option<(Hit, Vec<u8>)> {
    if offset + 0x24 > carrier.len() {
        return None; // header 读不完 → 伪命中，弃
    }
    let file_size = u32::from_le_bytes([
        carrier[offset + 0x20] ^ ks[0x20],
        carrier[offset + 0x21] ^ ks[0x21],
        carrier[offset + 0x22] ^ ks[0x22],
        carrier[offset + 0x23] ^ ks[0x23],
    ]) as usize;
    if file_size < 0x70 || offset + file_size > carrier.len() {
        return None; // header 自述长度不合法或越界 → 伪命中，弃
    }
    let payload: Vec<u8> = (0..file_size).map(|j| carrier[offset + j] ^ ks[j]).collect();
    let methods = dex::parse(&payload).ok()?;
    Some((Hit {
        predicate: pred.label(),
        offset,
        cipher_len: file_size,
        chain: vec!["dex-magic".into(), "dex-parse-ok".into()],
        payload_len: payload.len(),
        payload_sha256: sha256_hex(&payload),
        payload_methods: methods.len(),
        payload_path: String::new(), // CLI 层填充
    }, payload))
}

/// zlib magic 命中 → inflate 全流（流边界自决密文长度）→ 解出流须为 DEX。
fn try_zlib_then_dex(carrier: &[u8], ks: &[u8], offset: usize, pred: &Predicate) -> Option<(Hit, Vec<u8>)> {
    let rest: Vec<u8> = (0..carrier.len() - offset).map(|j| carrier[offset + j] ^ ks[j]).collect();
    let (plain, consumed) = zlib_inflate_prefix(&rest)?;
    if plain.len() < 0x24 || &plain[0..4] != b"dex\n" {
        return None; // inflate 成功但产物非 DEX → 非目标，弃
    }
    let file_size = u32::from_le_bytes([plain[0x20], plain[0x21], plain[0x22], plain[0x23]]) as usize;
    if file_size < 0x70 || file_size > plain.len() {
        return None;
    }
    let payload = plain[..file_size].to_vec();
    let methods = dex::parse(&payload).ok()?;
    Some((Hit {
        predicate: pred.label(),
        offset,
        cipher_len: consumed,
        chain: vec![
            "zlib-magic".into(),
            "inflate-ok".into(),
            "dex-magic".into(),
            "dex-parse-ok".into(),
        ],
        payload_len: payload.len(),
        payload_sha256: sha256_hex(&payload),
        payload_methods: methods.len(),
        payload_path: String::new(),
    }, payload))
}

/// CLI 包装：读载体 → hunt → 落盘 `<out>/hunt.json` + `<out>/hits/<n>.dex`。
pub fn run(carrier_path: &std::path::Path, predicates: &[Predicate], out_dir: &std::path::Path) -> Result<HuntFile, String> {
    let carrier = std::fs::read(carrier_path).map_err(|e| format!("read {}: {e}", carrier_path.display()))?;
    if carrier.is_empty() {
        return Err(format!("carrier {}: empty file", carrier_path.display()));
    }
    if predicates.is_empty() {
        return Err("no predicate given — need at least one of --rc4/--xor".into());
    }

    let (mut hits, dexes, negatives) = hunt(&carrier, predicates);

    std::fs::create_dir_all(out_dir.join("hits")).map_err(|e| format!("mkdir: {e}"))?;
    for (i, (hit, dex_bytes)) in hits.iter_mut().zip(dexes.into_iter()).enumerate() {
        let rel = format!("hits/{i}.dex");
        std::fs::write(out_dir.join(&rel), &dex_bytes).map_err(|e| format!("write {rel}: {e}"))?;
        hit.payload_path = rel;
    }

    let file = HuntFile {
        schema: "exuvia.hunt".to_string(),
        carrier: CarrierInfo {
            path: carrier_path.display().to_string(),
            sha256: sha256_hex(&carrier),
            size: carrier.len(),
        },
        predicates: predicates.iter().map(|p| p.label()).collect(),
        hits,
        negative_facts: negatives,
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(out_dir.join("hunt.json"), &json).map_err(|e| format!("write hunt.json: {e}"))?;
    Ok(file)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(data);
    format!("{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn short_sha(data: &[u8]) -> String {
    sha256_hex(data).chars().take(8).collect()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// CLI hex 参数解析（偶数长度、纯 hex）。
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex length {} is odd: {s}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("bad hex pair in {s}"))
        })
        .collect()
}
