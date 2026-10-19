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
    /// debt.json 汇总（机器索引；条目本体在 debt.json）
    pub debt: DebtSummary,
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
    /// 表结构可完整解析（magic_ok 但表损坏 = 敌意输入常态，debt 不收该 dex）
    pub parse_ok: bool,
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

// ─── debt.json（handoff 协议：欠账清单）───

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebtFile {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub handoff_version: i64,
    pub entries: Vec<DebtEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebtEntry {
    pub debt_id: String,
    pub method: MethodRef,
    pub status: DebtStatus,
    /// 事实列表（无判断；难度信号字段待 so 分析段挣得后加入）
    pub facts: Vec<String>,
    pub attempts: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MethodRef {
    /// FQCN（L/; 描述符的规范形态）
    pub class: String,
    pub name: String,
    /// "(Ltype;)ret" 形式描述符，与 DEX proto 一致
    pub descriptor: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum DebtStatus {
    #[serde(rename = "blocked-solvable")]
    BlockedSolvable,
    #[serde(rename = "out-of-scope")]
    OutOfScope,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebtSummary {
    pub total: u64,
    pub blocked_solvable: u64,
    pub out_of_scope: u64,
}
