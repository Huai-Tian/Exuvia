// 羽化(eclosion)库件——守护三动词 / 会话层 / 采集引擎 / 驱动对接层。
// 零内置策略的纯执行引擎:策略全部来自工单(SKILL §10 契约),驱动协议全部来自 profile(§4 立项书)。
// 契约类型 = 本仓 SKILL.md fixture 的手写镜像(tests/fixture_anchor.rs 双向锚定)。

pub mod channel;
pub mod daemon;
pub mod engine;
pub mod probe;
pub mod profile;
pub mod proto;
pub mod session;

use std::sync::{Mutex, OnceLock};

// ---- JSON 行输出工具(probe 各模块共用) ----
pub fn jescape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub fn emit(fields: &[(&str, String)]) {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    let line = format!("{{{}}}", body.join(","));
    println!("{line}");
    // --out 落盘(手机终端不吃 `>` 重定向——2026-11-05 实测 MT 管理器终端)
    if let Some(m) = OUT_SINK.get() {
        if let Some(f) = m.lock().unwrap().as_mut() {
            use std::io::Write;
            writeln!(f, "{line}").ok();
        }
    }
}

static OUT_SINK: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();

/// probe --out <路径>:结果同时写文件(手机屏幕拷贝之外的可靠通道)
pub fn set_out(path: &str) -> Result<(), String> {
    let f = std::fs::File::create(path).map_err(|e| format!("create {path}: {e}"))?;
    OUT_SINK.set(Mutex::new(Some(f))).map_err(|_| "out sink already set".to_string())
}

pub fn js(s: &str) -> String { format!("\"{}\"", jescape(s)) }
pub fn jn<T: std::fmt::Display>(v: T) -> String { v.to_string() }
pub fn jh(v: u64) -> String { format!("\"0x{v:x}\"") }

/// 铁律 4 随机工件名:随机长度(10..=16)+随机字符(小写字母数字)
pub fn rand_name(prefix: &str) -> String {
    let mut extra = [0u8; 1];
    getrandom::fill(&mut extra).unwrap_or_default();
    let n = 10 + (extra[0] % 7) as usize;
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).unwrap_or_default();
    let body: String = buf.iter().map(|b| (b"abcdefghijklmnopqrstuvwxyz0123456789"[(b % 36) as usize]) as char).collect();
    format!("{prefix}{body}")
}

/// 工件 sha256(manifest 对账;"sha256:" 前缀与 exuvia 侧 fixture 一致)
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}
