//! REPORT.json 类型——handoff 协议的机器索引部分（SKILL.md §2，DRAFT v0）。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Report {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub handoff_version: i64,
    pub apk: ApkInfo,
    /// fence 未配置任何指纹字段时恒为 matched=false（未知族主线，正常态）
    pub fingerprint: Fingerprint,
    pub inventory: Inventory,
    /// 缺席的外部能力（jadx/ghidra 探测，轨道 A 第二段接入）
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApkInfo {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub matched: bool,
    pub family: Option<String>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub dex: Vec<DexEntry>,
    pub so: Vec<SoEntry>,
    pub assets: Vec<AssetEntry>,
    pub android_manifest_present: bool,
    pub other_entries: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DexEntry {
    pub name: String,
    pub size_bytes: u64,
    /// 前 8 字节为 "dex\n" + 版本 + \0 的格式事实校验（机械，非语义）
    pub magic_ok: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoEntry {
    pub name: String,
    pub abi: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetEntry {
    pub name: String,
    pub size_bytes: u64,
    /// 香农熵 bits/byte（0..8）。原始测量值，无阈值分档——分档等 fence 挣得字段
    pub entropy: f64,
}
