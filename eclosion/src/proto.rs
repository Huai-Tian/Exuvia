// 契约类型的羽化侧手写镜像(SKILL.md §10;fixture 即锚定)。
// 开放点落地(立项书 §7):不经路径依赖共享 exuvia 类型——eclosion 目标含 aarch64-musl/android,
// 不拖主机侧依赖;镜像诚实性由 tests/fixture_anchor.rs 直读 ../SKILL.md fixture 断言。
// 镜像纪律:字段名/版本常量与 SKILL.md §10/§11 逐字一致;deny_unknown_fields = 闸门第①层。

use serde::{Deserialize, Serialize};

pub const WORKORDER_VERSION: i64 = 4;
pub const MANIFEST_VERSION: i64 = 2;
pub const HYGIENE_VERSION: i64 = 3;
pub const SESSION_VERSION: i64 = 1;

// ─── 10.1 workorder.json(exuvia → 羽化)───

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrder {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub workorder_version: i64,
    pub order_id: String,
    pub target: WoTarget,
    pub family: WoFamily,
    pub extraction: WoExtraction,
    pub env_gates: Vec<WoEnvGate>,
    pub stealth: WoStealth,
    pub hygiene: WoHygiene,
    pub deliverables: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoTarget {
    pub package: String,
    pub apk_sha256: String,
    pub launch_activity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoFamily {
    pub id: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoExtraction {
    pub mode: String,
    pub art_anchors: Vec<String>,
    pub seed_plan: Option<SeedPlanRef>,
    /// 载荷直扫配置(2026-11-06 设备实证:直扫 = 通用定位主通路,SKILL §9)
    pub scan: WoScan,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoScan {
    pub regions: WoScanRegions,
    pub magic: Vec<WoScanMagic>,
    pub poll: WoScanPoll,
    pub carve: WoScanCarve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoScanRegions {
    pub perms: String,
    pub anonymous_only: bool,
    pub min_size: u64,
    pub max_size: u64,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoScanMagic {
    pub name: String,
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoScanPoll {
    pub interval_ms: u64,
    pub stable_rounds: u64,
    pub window_s: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoScanCarve {
    pub verify_header: bool,
    pub max_size: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedPlanRef {
    pub file: String,
    pub sha256: String,
    pub hot_first: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoEnvGate {
    pub gate: String,
    pub expected: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoStealth {
    pub tier: String,
    pub driver: Option<DriverReq>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverReq {
    pub required: bool,
    pub min_version: String,
    pub channels: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WoHygiene {
    pub hygiene_version: i64,
    pub random_artifacts: bool,
    pub one_shot: bool,
}

// ─── 10.2 manifest.json(羽化 → exuvia)───

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub manifest_version: i64,
    pub order_id: String,
    pub workorder_sha256: String,
    pub collector: CollectorInfo,
    pub device: DeviceInfo,
    pub stealth_tier_used: String,
    pub driver: Option<DriverStatus>,
    pub anchors_hit: Vec<String>,
    pub env_gates: Vec<GateResult>,
    pub artifacts: Vec<ArtifactEntry>,
    pub errors: Vec<RunError>,
    pub residuals_accepted: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub abi: String,
    pub android_release: String,
    pub kernel: String,
    pub root: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverStatus {
    pub name: String,
    pub version: String,
    pub handshake: bool,
    pub channels_used: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateResult {
    pub gate: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub name: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunError {
    pub code: String,
    pub detail: String,
}

// ─── 10.4 session.json(会话消息词汇表,双向共用)───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum SessionKind {
    #[serde(rename = "workorder.assign")]
    WorkorderAssign,
    #[serde(rename = "workorder.cancel")]
    WorkorderCancel,
    #[serde(rename = "status.query")]
    StatusQuery,
    #[serde(rename = "workorder.ack")]
    WorkorderAck,
    #[serde(rename = "progress")]
    Progress,
    #[serde(rename = "event")]
    Event,
    #[serde(rename = "status.report")]
    StatusReport,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "done")]
    Done,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnvelope {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub session_version: i64,
    pub kind: SessionKind,
    pub seq: u64,
    pub order_id: Option<String>,
    pub body: serde_json::Value,
}
