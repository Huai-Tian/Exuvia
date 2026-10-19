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
    /// 卡点类型：路由条目形态与 next 的 payload 匹配
    pub kind: DebtKind,
    /// 方法卡点才有；encrypted-payload 为 null
    pub method: Option<MethodRef>,
    pub status: DebtStatus,
    /// 事实列表（无判断；难度信号字段待 so 分析段挣得后加入）
    pub facts: Vec<String>,
    /// 切片目录引用（handoff/evidence/<debt_id>/；无切片时为空）
    pub evidence: Vec<String>,
    pub attempts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum DebtKind {
    #[serde(rename = "method-native-stub")]
    MethodNativeStub,
    #[serde(rename = "encrypted-payload")]
    EncryptedPayload,
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

// ─── workpackage.json（外包循环：next 的输出、proposal 范围闸的数据源）───

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkPackage {
    #[serde(rename = "$schema")]
    pub schema: String,
    /// goal 文件字节锚定（proposal 回流时可复核 goal 未变）
    pub goal_sha256: String,
    pub handoff_version: i64,
    /// goal 声明的副本——Agent 决定 recovered/equivalent 路径的依据
    pub accepts_equivalent: bool,
    pub tracks: Vec<crate::protocol::Track>,
    /// 按 goal 注入的族知识；指纹未匹配 = 空
    pub guidance: Vec<String>,
    /// 范围闸数据源：proposal 的 claims 只允许认领这里的 debt_id
    pub allowed_debt: Vec<String>,
    /// 条目副本（Agent 无需再翻 debt.json）
    pub entries: Vec<DebtEntry>,
}

// ─── evidence 切片（按 debt 分组：payload 头部样本 / 符号命中的方法体字节 + hash 锚定 manifest）───

/// 内存态切片（bytes 不进 JSON；写盘时落 <name>.bin）
#[derive(Debug, Clone)]
pub struct SliceBytes {
    /// manifest.slices[].name 同名；落盘为 <name>.bin
    pub name: String,
    /// APK 内路径（dex/asset/so）
    pub source: String,
    /// so 符号名；非符号切片为 None
    pub symbol: Option<String>,
    pub st_value: Option<u64>,
    pub st_size: Option<u64>,
    pub file_offset: u64,
    pub bytes: Vec<u8>,
}

/// 内存态证据组（一个 debt 一组；多命中切片共存，互不覆盖）
#[derive(Debug, Clone)]
pub struct EvidenceGroup {
    pub debt_id: String,
    pub slices: Vec<SliceBytes>,
}

/// handoff/evidence/<debt_id>/manifest.json（CI fixture 之一）
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub debt_id: String,
    pub slices: Vec<SliceEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SliceEntry {
    /// 与同目录 <name>.bin 对应
    pub name: String,
    /// APK 内路径（dex/asset/so）
    pub source: String,
    /// so 符号名；非符号切片为 null
    pub symbol: Option<String>,
    pub st_value: Option<u64>,
    pub st_size: Option<u64>,
    pub file_offset: u64,
    pub slice_sha256: String,
}

// ─── REPORT.md（人类可读摘要；纯事实渲染，无判断）───

/// 渲染 REPORT.md（handoff 结构 §4.2 的人类可读半边）。内容 = REPORT.json 的事实平铺。
pub fn render_markdown(r: &Report) -> String {
    let mut s = String::new();
    s.push_str("# Exuvia handoff report\n\n");
    s.push_str(&format!("- APK: {} ({} bytes)\n", r.apk.sha256, r.apk.size_bytes));
    s.push_str(&format!(
        "- fingerprint: {} ({})\n",
        if r.fingerprint.matched { "matched" } else { "unmatched (unknown family — default state)" },
        r.fingerprint.family.as_deref().unwrap_or("none")
    ));
    s.push_str("\n## Inventory\n\n");
    s.push_str("| kind | name | facts |\n|---|---|---|\n");
    for d in &r.inventory.dex {
        s.push_str(&format!(
            "| dex | {} | {} bytes, magic {}, parse {} |\n",
            d.name,
            d.size_bytes,
            if d.magic_ok { "ok" } else { "MISMATCH" },
            if d.parse_ok { "ok" } else { "FAILED" }
        ));
    }
    for so in &r.inventory.so {
        s.push_str(&format!("| so | {} | {}, {} bytes |\n", so.name, so.abi, so.size_bytes));
    }
    for a in &r.inventory.assets {
        s.push_str(&format!("| asset | {} | {} bytes, entropy {} bits/byte |\n", a.name, a.size_bytes, a.entropy));
    }
    s.push_str(&format!(
        "| other | AndroidManifest.xml | {} |\n| other | (remaining entries) | {} |\n",
        if r.inventory.android_manifest_present { "present" } else { "absent" },
        r.inventory.other_entries
    ));
    s.push_str("\n## Debt\n\n");
    s.push_str(&format!(
        "- total: {} (blocked-solvable: {}, out-of-scope: {})\n",
        r.debt.total, r.debt.blocked_solvable, r.debt.out_of_scope
    ));
    s.push_str("\n## Unavailable capabilities\n\n");
    if r.unavailable.is_empty() {
        s.push_str("- none\n");
    } else {
        for u in &r.unavailable {
            s.push_str(&format!("- {u}\n"));
        }
    }
    s
}
