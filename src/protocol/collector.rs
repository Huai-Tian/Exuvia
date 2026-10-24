//! 采集契约三件套 serde 类型（SKILL.md §10，DRAFT v0）。
//! 与 §3/§4 同纪律：不发明契约外字段；deny_unknown_fields = 闸门第①层。
//! 采集器本体不在本仓（§9 铁律 3）——这三个类型是双方唯一的耦合面。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ─── 共用枚举 ───

/// 隐身档（§9 隐身分级：L0 纯用户态 → L1 用户态强化 → L2 内核辅助）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum Tier {
    L0,
    L1,
    L2,
}

/// 提取模式（§9：passive = 加载期整 dex 解密族，零进程内触发；active = FART 式方法触发）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExtractionMode {
    Passive,
    Active,
}

/// 内核驱动能力通道（驱动 client 冻结面；ditPro ABI 参考——壳无关原语，zero-sample 延伸到内核）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum DriverChannel {
    #[serde(rename = "phys_read")]
    PhysRead,
    #[serde(rename = "phys_write")]
    PhysWrite,
    #[serde(rename = "hide_proc")]
    HideProc,
}

/// 交付物种类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum Deliverable {
    #[serde(rename = "dex")]
    Dex,
    #[serde(rename = "runtime-log")]
    RuntimeLog,
    #[serde(rename = "maps")]
    Maps,
}

// ─── 10.1 workorder.json（exuvia → 采集器）───

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkOrder {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub workorder_version: i64,
    /// opaque；manifest 原样回显（建议取工单正文 sha256 派生）
    pub order_id: String,
    pub target: WoTarget,
    pub family: WoFamily,
    pub extraction: WoExtraction,
    pub env_gates: Vec<WoEnvGate>,
    pub stealth: WoStealth,
    pub hygiene: WoHygiene,
    pub deliverables: Vec<Deliverable>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoTarget {
    /// 已安装加壳包名
    pub package: String,
    /// exuvia 分析对象锚——采集器动作前必须核对已安装应用，不符 = 大声拒绝
    pub apk_sha256: String,
    /// 采集器 am start 启动的组件名——启动目标恒为采集器职责（§9 铁律 5：E2EE 会话线）
    pub launch_activity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoFamily {
    /// §8 技术族 id（如 family-3-extract-nop）；未知 = "unknown"。
    /// 机器字段永不出现厂商名（§8 围栏规则延伸到采集线）
    pub id: String,
    /// 分类依据事实串（如 rodata 符号命中），无判断
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoExtraction {
    pub mode: ExtractionMode,
    /// 挂钩引擎存在时 = 挂钩规范；被动模式 = 计时/侦察提示。
    /// 只挂 ART 标准入口（§9 教义集），永不挂壳符号
    pub art_anchors: Vec<String>,
    /// active 模式专用：fart_plan 产物文件引用（与工单同包交付）
    pub seed_plan: Option<SeedPlanRef>,
    /// AGENT 按族给出的动态扫描配置——采集器零内置扫描策略
    /// （zero-sample 从"无壳特征"延伸到"无扫描策略"，2026-10-24 维护者裁定）
    pub scan: WoScan,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoScan {
    pub regions: WoScanRegions,
    pub magic: Vec<WoScanMagic>,
    pub poll: WoScanPoll,
    pub carve: WoScanCarve,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoScanRegions {
    /// maps 权限过滤（如 "rw-p"）
    pub perms: String,
    pub anonymous_only: bool,
    pub min_size: u64,
    pub max_size: u64,
    /// 路径名排除表（如 "[stack]"）
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoScanMagic {
    /// 回报用标识（如 "dex035"）
    pub name: String,
    /// 无前缀字节串 hex（如 "6465780a30333500"）
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoScanPoll {
    pub interval_ms: u64,
    /// 同一命中连续 N 轮 sha256 一致判稳（防解密进行中的半成品快照）
    pub stable_rounds: u64,
    /// 总窗口封顶（秒）
    pub window_s: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoScanCarve {
    /// 魔数 + file_size 自洽 + map_off 非零
    pub verify_header: bool,
    /// 单体上限（字节）
    pub max_size: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeedPlanRef {
    pub file: String,
    pub sha256: String,
    /// 热层先行（§7 fart_plan hot 层排序）
    pub hot_first: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoEnvGate {
    /// 检查点标识（prop 名 / 文件路径 / 行为名）
    pub gate: String,
    /// 真机期望值（通过条件）
    pub expected: String,
    /// 侦察依据引用
    pub evidence: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoStealth {
    /// 最低档；采集器可超档执行，禁止静默降档
    pub tier: Tier,
    /// L2 必填；required=true 时握手失败 = 大声拒绝运行（§9 冻结面：静默降级 = 裸奔）。
    /// 任何读写内核驱动同走此字段（KPM / 独立 .ko 等形态皆可），字段永不出现驱动标识
    pub driver: Option<DriverReq>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverReq {
    pub required: bool,
    /// 驱动 ABI 最低版本（semver 串）
    pub min_version: String,
    pub channels: Vec<DriverChannel>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WoHygiene {
    /// 生单时对齐的卫生目录版本
    pub hygiene_version: i64,
    pub random_artifacts: bool,
    pub one_shot: bool,
}

// ─── 10.2 manifest.json（采集器 → exuvia）───

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectorManifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub manifest_version: i64,
    /// 工单回显
    pub order_id: String,
    /// 所消费工单字节的 sha256 锚
    pub workorder_sha256: String,
    pub collector: CollectorInfo,
    pub device: DeviceInfo,
    /// 实际执行档（≥ 工单要求）
    pub stealth_tier_used: Tier,
    /// 驱动 client status 回读：实际生效通道落在这里（不是请求值）
    pub driver: Option<DriverStatus>,
    /// 实际命中的 ART 锚点——提取路径执行过的证据
    pub anchors_hit: Vec<String>,
    pub env_gates: Vec<GateResult>,
    pub artifacts: Vec<ArtifactEntry>,
    pub errors: Vec<RunError>,
    /// 本次运行适用的卫生目录残余通道 id（挂接 hygiene.json）
    pub residuals_accepted: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectorInfo {
    pub name: String,
    /// 采集器独立版本号（铁律 3：独立发行物、独立版本号）
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub abi: String,
    pub android_release: String,
    pub kernel: String,
    /// 例："ksu-lkm" / "ksu" / "magisk"
    pub root: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverStatus {
    pub name: String,
    pub version: String,
    pub handshake: bool,
    pub channels_used: Vec<DriverChannel>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GateResult {
    pub gate: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub name: String,
    pub kind: Deliverable,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunError {
    pub code: String,
    pub detail: String,
}

// ─── 10.3 hygiene.json（工件卫生目录，双向基准）───

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HygieneCatalog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub hygiene_version: i64,
    pub channels: Vec<HygieneChannel>,
}

/// tell-surface 通道条目：一个可观察面 = 一行。
/// 工单按 hygiene_version 对齐目录；manifest 按通道 id 登记残余。
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HygieneChannel {
    /// 通道标识（kebab-case，manifest.residuals_accepted 的引用键）
    pub id: String,
    /// 可被观察到什么
    pub surface: String,
    /// 谁在观察（in-process scanner / system-wide scanner / app-layer）
    pub observer: String,
    /// 各隐身档缓解手段（不适用 = "n/a"）
    pub l0: String,
    pub l1: String,
    pub l2: String,
    /// 做满缓解后仍存在的残余痕迹
    pub residual: String,
    /// 残余是否已有明确接受/缓解裁定
    pub residual_accepted: bool,
    /// 裁定原文 + 日期；无裁定 = null
    pub decision: Option<String>,
}
