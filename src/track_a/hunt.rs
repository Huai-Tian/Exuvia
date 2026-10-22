//! L2 参数空间搜索器（`exuvia hunt`）：已知算法 + 未知密文段参数的机械搜索。
//! 背景：轨道 C 桌面化（维护者拍板：摒弃真机/模拟器——成本高，且企业壳
//! 反检测使其在主战场不可行）。解密算法族与 key 由外循环确定后（facts /
//! LLM 复现），调用现场参数（密文段起点/长度）不再是"必须上真机"的运行时
//! 事实，而是机械可搜的有限空间——RC4/zlib 判据链的每一环都是格式事实。
//!
//! 搜索模型（机械假设，负事实如实记录）分两谓词族：
//! ① 流谓词（rc4/xor）：密文段 = 载体某起点开始、keystream 从零对齐的连续
//! 字节段；长度由判据链自决（zlib 流边界 / DEX header 的 file_size 字段——
//! 两个自描述边界，零猜测）。判据链全机械：zlib magic（RFC 1950 CMF/FLG
//! 校验）→ inflate → DEX magic → dex::parse 全表自洽。
//! ② 块链容器谓词（aes-128-cbc-tail，剖面 aes128cbc-tail-v1）：容器 = 载体
//! 尾部 [加密头块][明文 dex 体][子容器]*[BE32 起点 trailer]；起点由 trailer
//! 自述（无 trailer 的切片退化为全范围锚点扫描），头块长度由 PKCS#7 +
//! dex::parse 判据扫描自决，子容器由长度前缀走查——每环都是格式事实。
//!
//! 机械边界：流谓词 = rc4（标准 KSA + PRGA 参数空间）与 xor 循环；
//! 容器谓词 = aes-128-cbc-tail（族知识来自第二战 trackb 复盘，与
//! trackb/dexcontainer.py 同一格式剖面，Rust/Python 双实现互为锚）。
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

/// AES-CBC tail 容器参数（族级默认，与 trackb/dexcontainer.py 的 argparse
/// 默认同源——剖面 aes128cbc-tail-v1 的变体轴，非样本值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCbcTailParams {
    /// 子容器 payload 前缀 XOR 覆盖长度（族默认 0x70；0 = 子容器明文存放）
    pub xor_prefix: usize,
    /// 子容器 XOR key（族默认 0x66）
    pub xor_key: u8,
}

impl Default for AesCbcTailParams {
    fn default() -> Self {
        AesCbcTailParams { xor_prefix: 0x70, xor_key: 0x66 }
    }
}

/// 头块长度扫描：族默认 0x210 首试（dexcontainer.py 同参），其后 0x10 起
/// 步进 0x10 至本上限——容器头块是"dex 头 + 短类名"量级，超上限 = 非本剖面。
const AES_TAIL_ENC_LEN_FIRST: usize = 0x210;
const AES_TAIL_ENC_LEN_CAP: usize = 0x1000;
/// 锚点结构检查所需的最小解密深度：namelen ≤ 64 时 hdr_off + 0x24 ≤ 0x69。
const AES_TAIL_STRUCT_DEPTH: usize = 0x80;

/// 搜索谓词：密钥流生成算法（标准族 + 参数化变体）与块链容器剖面。
#[derive(Debug, Clone)]
pub enum Predicate {
    /// RC4（标准 KSA + 参数化 PRGA），key 外部传入（来源：facts / LLM 复现）
    Rc4 { key: Vec<u8>, params: Rc4Params },
    /// n 字节循环 XOR
    Xor { key: Vec<u8> },
    /// AES-128-CBC tail 容器（key/iv 外部传入，来源同上；起点/长度/子容器全链自决）
    AesCbc { key: Vec<u8>, iv: Vec<u8>, params: AesCbcTailParams },
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
            Predicate::AesCbc { key, iv, .. } => format!(
                "aes-128-cbc-tail(key sha256:{}…, iv sha256:{}…)",
                short_sha(key),
                short_sha(iv)
            ),
        }
    }

    /// 预生成 keystream（长度 = 载体长度）。
    /// 流密码 keystream 只依赖 key 与位置——解密任意起点段 = 查表 XOR，搜索降为 O(n)。
    /// 块链容器谓词无 keystream 概念（链接态依赖前块）→ None，走 hunt_aes_tail 臂。
    fn keystream(&self, len: usize) -> Option<Vec<u8>> {
        match self {
            Predicate::Rc4 { key, params } => Some(rc4_keystream(key, *params, len)),
            Predicate::Xor { key } => Some((0..len).map(|i| key[i % key.len()]).collect()),
            Predicate::AesCbc { .. } => None,
        }
    }

    /// 无命中时的诚实负事实（含搜索模型声明，逐谓词族一份）。
    fn negative_fact(&self, carrier_len: usize) -> String {
        match self {
            Predicate::Rc4 { .. } | Predicate::Xor { .. } => format!(
                "{}: full-range scan of {} offsets — no decrypt hit (model: keystream-zero-aligned segment, chain: zlib-magic/{}dex-magic)",
                self.label(),
                carrier_len,
                "inflate-ok/",
            ),
            Predicate::AesCbc { .. } => format!(
                "{}: trailer anchor + full-range anchor scan of {} offsets (header-block cap 0x{:x}) — no container hit (model: aes128cbc-tail-v1, chain: cbc-anchor/cbc-struct/cbc-header/dex-magic/dex-parse-ok)",
                self.label(),
                carrier_len,
                AES_TAIL_ENC_LEN_CAP,
            ),
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
        let before = hits.len();
        match pred.keystream(carrier.len()) {
            Some(ks) => {
                // D_offset(j) = carrier[offset + j] ^ ks[j]（段内第 j 字节的解密视图）
                let dec = |offset: usize, j: usize| -> u8 { carrier[offset + j] ^ ks[j] };

                for offset in 0..carrier.len() {
                    if offset + 4 > carrier.len() {
                        break;
                    }
                    let m = [dec(offset, 0), dec(offset, 1), dec(offset, 2), dec(offset, 3)];

                    if &m == b"dex\n" {
                        if let Some(h) = try_dex_direct(carrier, &ks, offset, pred) {
                            dexes.push(h.1);
                            hits.push(h.0);
                        }
                    } else if is_zlib_magic(m[0], m[1]) {
                        if let Some(h) = try_zlib_then_dex(carrier, &ks, offset, pred) {
                            dexes.push(h.1);
                            hits.push(h.0);
                        }
                    }
                }
            }
            None => hunt_aes_tail(carrier, pred, &mut hits, &mut dexes),
        }

        if hits.len() == before {
            negatives.push(pred.negative_fact(carrier.len()));
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

/// AES-128-CBC 解密（手工链接：P_i = D_k(C_i) ^ C_{i-1}，首块用给定 IV）。
/// 段内链接自含——从段起点整体解即得全部明文，与绝对块边界无关。
/// key/iv 非 16 字节或数据非 16 对齐 → None（调用侧记负事实，不静默）。
/// pub 与 rc4_keystream 同级（crate 的密码原语面）；正确性由 NIST SP 800-38A
/// F.2.1 已知答案测试独立锚定（非本 crate 加密方向的自证）。
pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    if key.len() != 16 || iv.len() != 16 || data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    let cipher = aes::Aes128::new_from_slice(key).ok()?;
    let mut out = data.to_vec();
    let mut prev: [u8; 16] = iv.try_into().ok()?;
    for chunk in out.chunks_exact_mut(16) {
        let cur: [u8; 16] = chunk.try_into().ok()?;
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = cur;
    }
    Some(out)
}

/// 锚点结构判据（全机械，零硬编码偏移）：
/// pt[0] = namelen ∈ 1..=64；pt[1+namelen] = NUL；
/// hdr_off = namelen + 5（[namelen][name][NUL][3B BE fsize][dex#1 header]）；
/// pt[hdr_off..+4] == "dex\n"；fsize = LE32 @hdr_off+0x20 ≥ 0x70（dex 头最小量）。
/// 返回 (hdr_off, fsize)。
fn aes_tail_struct(pt: &[u8]) -> Option<(usize, usize)> {
    let namelen = *pt.first()? as usize;
    if namelen == 0 || namelen > 64 {
        return None;
    }
    if pt.get(1 + namelen) != Some(&0) {
        return None;
    }
    let hdr_off = namelen + 5;
    if hdr_off + 0x24 > pt.len() || &pt[hdr_off..hdr_off + 4] != b"dex\n" {
        return None;
    }
    let fsize = u32::from_le_bytes(pt[hdr_off + 0x20..hdr_off + 0x24].try_into().ok()?) as usize;
    if fsize < 0x70 {
        return None;
    }
    Some((hdr_off, fsize))
}

/// 在锚点 l 处跑全链：结构 → 头块长度扫描自决 → dex#1 装配终审 → 子容器走查。
/// bound = 容器区右端（trailer 锚点 = 载体末 4 字节前；扫描锚点 = 载体末）。
/// 命中即推入 hits/dexes 并返回 true（单容器模型：一个载体一个 tail 容器）。
fn aes_tail_attempt(
    carrier: &[u8],
    l: usize,
    anchor_tag: &str,
    bound: usize,
    key: &[u8],
    iv: &[u8],
    params: &AesCbcTailParams,
    hits: &mut Vec<Hit>,
    dexes: &mut Vec<Vec<u8>>,
) -> bool {
    if l + 0x20 > bound {
        return false;
    }
    let depth = AES_TAIL_ENC_LEN_CAP.min((bound - l) / 16 * 16);
    let Some(pt) = aes128_cbc_decrypt(key, iv, &carrier[l..l + depth]) else { return false };
    let Some((hdr_off, fsize)) = aes_tail_struct(&pt) else { return false };

    // 头块长度扫描：族默认首试，其后全候选——判据逐环收紧：
    // PKCS#7 pad 合法（1..=16 且尾 pad 字节全等）→ 片段至少覆盖 file_size 字段
    // （与结构判据已读区域自洽；片段小于完整 dex 头的短块容器不被误杀）
    // → 体长不自负不越界 → dex::parse 全表自洽（终审）。
    let mut cands: Vec<usize> = vec![AES_TAIL_ENC_LEN_FIRST];
    cands.extend((0x10..=AES_TAIL_ENC_LEN_CAP).step_by(0x10).filter(|&e| e != AES_TAIL_ENC_LEN_FIRST));
    let mut found: Option<(Vec<u8>, usize, usize)> = None; // (dex1, enc_len, body_len)
    for e in cands {
        if e < 0x20 || e > depth {
            continue;
        }
        let pad = pt[e - 1] as usize;
        if pad == 0 || pad > 16 || !pt[e - pad..e].iter().all(|&b| b as usize == pad) {
            continue;
        }
        let hdrlen = e - pad;
        if hdrlen < hdr_off + 0x24 || hdrlen - hdr_off > fsize {
            continue;
        }
        let body_len = fsize - (hdrlen - hdr_off);
        if l + e + body_len > bound {
            continue;
        }
        let mut dex1 = pt[hdr_off..hdrlen].to_vec();
        dex1.extend_from_slice(&carrier[l + e..l + e + body_len]);
        if dex::parse(&dex1).is_ok() {
            found = Some((dex1, e, body_len));
            break;
        }
    }
    let Some((dex1, enc_len, body_len)) = found else { return false };

    // 子容器走查：紧跟 dex#1 体尾，[4B BE len][payload]* 至长度不自洽止；
    // payload 先试明文 dex magic，不中再试族默认 XOR 前缀剥离——非 dex 跳过不沉默（计入走查摘要）。
    let mut sub_dex: Vec<(usize, Vec<u8>, usize, &'static str)> = Vec::new(); // (cpos, payload, ln, strip_tag)
    let mut skipped = 0usize;
    let mut cpos = l + enc_len + body_len;
    while cpos + 4 <= bound {
        let ln = u32::from_be_bytes(carrier[cpos..cpos + 4].try_into().unwrap()) as usize;
        if ln == 0 || cpos + 4 + ln > bound {
            break;
        }
        let raw = &carrier[cpos + 4..cpos + 4 + ln];
        let stripped: Option<(Vec<u8>, &'static str)> = if raw.starts_with(b"dex\n") {
            Some((raw.to_vec(), "raw-payload"))
        } else if params.xor_prefix > 0 {
            let mut v = raw.to_vec();
            for b in v.iter_mut().take(params.xor_prefix) {
                *b ^= params.xor_key;
            }
            if v.starts_with(b"dex\n") {
                Some((v, "xor-prefix-strip"))
            } else {
                None
            }
        } else {
            None
        };
        match stripped {
            Some((payload, tag)) if dex::parse(&payload).is_ok() => sub_dex.push((cpos, payload, ln, tag)),
            _ => skipped += 1,
        }
        cpos += 4 + ln;
    }

    let walk_summary = format!("sub-walk({} dex, {} non-dex skipped)", sub_dex.len(), skipped);
    let methods = dex::parse(&dex1).map(|m| m.len()).unwrap_or(0);
    hits.push(Hit {
        predicate: Predicate::AesCbc { key: key.to_vec(), iv: iv.to_vec(), params: *params }.label(),
        offset: l,
        cipher_len: enc_len + body_len,
        chain: vec![
            anchor_tag.to_string(),
            format!("cbc-header-decrypt(enc_len=0x{enc_len:x})"),
            "dex-magic".into(),
            "dex-parse-ok".into(),
            walk_summary,
        ],
        payload_len: dex1.len(),
        payload_sha256: sha256_hex(&dex1),
        payload_methods: methods,
        payload_path: String::new(),
    });
    dexes.push(dex1);
    for (k, (cpos, payload, ln, strip_tag)) in sub_dex.into_iter().enumerate() {
        let methods = dex::parse(&payload).map(|m| m.len()).unwrap_or(0);
        hits.push(Hit {
            predicate: Predicate::AesCbc { key: key.to_vec(), iv: iv.to_vec(), params: *params }.label(),
            offset: cpos,
            cipher_len: 4 + ln,
            chain: vec![
                anchor_tag.to_string(),
                format!("sub-container#{k}"),
                strip_tag.into(),
                "dex-magic".into(),
                "dex-parse-ok".into(),
            ],
            payload_len: payload.len(),
            payload_sha256: sha256_hex(&payload),
            payload_methods: methods,
            payload_path: String::new(),
        });
        dexes.push(payload);
    }
    true
}

/// AES-CBC tail 容器搜索臂：trailer 锚点（族格式自述指针）优先；
/// 载体为切片、trailer 缺席时退化为全范围锚点扫描（结构判据先行，
/// 过判据者才进全链——扫描成本集中在 0x80 深度的一块解密上）。
fn hunt_aes_tail(carrier: &[u8], pred: &Predicate, hits: &mut Vec<Hit>, dexes: &mut Vec<Vec<u8>>) {
    let Predicate::AesCbc { key, iv, params } = pred else { return };
    if key.len() != 16 || iv.len() != 16 || carrier.len() < 4 + 0x30 {
        return;
    }

    // ① trailer 锚点：末 4 字节 BE = 容器起点 L
    let l_trailer = u32::from_be_bytes(carrier[carrier.len() - 4..].try_into().unwrap()) as usize;
    if l_trailer >= 0x10 && l_trailer + 0x30 <= carrier.len() - 4
        && aes_tail_attempt(carrier, l_trailer, "cbc-anchor-trailer", carrier.len() - 4, key, iv, params, hits, dexes)
    {
        return;
    }

    // ② 全范围锚点扫描（trailer 缺席/失真的切片载体）
    for o in 0..carrier.len().saturating_sub(0x30) {
        if o == l_trailer {
            continue;
        }
        let depth = AES_TAIL_STRUCT_DEPTH.min((carrier.len() - o) / 16 * 16);
        if depth < 0x20 {
            continue;
        }
        let Some(pt) = aes128_cbc_decrypt(key, iv, &carrier[o..o + depth]) else { continue };
        if aes_tail_struct(&pt).is_none() {
            continue;
        }
        if aes_tail_attempt(carrier, o, "cbc-anchor-scan", carrier.len(), key, iv, params, hits, dexes) {
            return;
        }
    }
}

/// CLI 包装：读载体 → hunt → 落盘 `<out>/hunt.json` + `<out>/hits/<n>.dex`。
pub fn run(carrier_path: &std::path::Path, predicates: &[Predicate], out_dir: &std::path::Path) -> Result<HuntFile, String> {
    let carrier = std::fs::read(carrier_path).map_err(|e| format!("read {}: {e}", carrier_path.display()))?;
    if carrier.is_empty() {
        return Err(format!("carrier {}: empty file", carrier_path.display()));
    }
    if predicates.is_empty() {
        return Err("no predicate given — need at least one of --rc4/--xor/--aes-cbc".into());
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

/// AES key/IV 规格解析：hex（32 hex 字符 → 16B）或 16 字节 ASCII——
/// 与 trackb/dexcontainer.py read_key_spec 同规则（减去 file:offset 形式：
/// hunt 是桌面 L2，key/iv 由 facts/LLM 复现后以字面值传入）。
/// hex 优先；16 字符全 hex 数字的 ASCII 串会先得 8B hex ≠ 16B → 回落 ASCII，无歧义。
pub fn key_spec_bytes(spec: &str) -> Result<Vec<u8>, String> {
    if let Ok(b) = hex_to_bytes(spec) {
        if b.len() == 16 {
            return Ok(b);
        }
    }
    if spec.len() == 16 {
        return Ok(spec.as_bytes().to_vec());
    }
    Err(format!("key/iv must resolve to 16 bytes (hex or ascii): {spec:?}"))
}
