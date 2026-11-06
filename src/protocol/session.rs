//! 会话消息词汇表 serde 类型（SKILL.md §10.4，DRAFT v0）。
//! E2EE 会话控制面的共用语言（2026-11-03 裁定：词汇表进主协议，双向共用）。
//! 信封锁 kind 词封闭集与骨架字段（deny_unknown_fields = 闸门第①层）；
//! body 字段约定见 §10.4 词表，逐词随守护进程实现钉死。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 会话词（控制面九词封闭集；方向硬性，反向收到 = 协议错误）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum SessionKind {
    /// 主机→羽化：下发工单（body = workorder JSON），下发即排队执行
    #[serde(rename = "workorder.assign")]
    WorkorderAssign,
    /// 主机→羽化：撤销在跑工单（order_id 指定）
    #[serde(rename = "workorder.cancel")]
    WorkorderCancel,
    /// 主机→羽化：查询守护进程/工单状态
    #[serde(rename = "status.query")]
    StatusQuery,
    /// 羽化→主机：收讫回执 + 能力核对结论（不符 = 响亮拒绝）
    #[serde(rename = "workorder.ack")]
    WorkorderAck,
    /// 羽化→主机：进度回报（枚举数 / 已挖取 / 已用时）
    #[serde(rename = "progress")]
    Progress,
    /// 羽化→主机：结构化证据事件（探针事件流；事件名表随实现滚动，信封不锁）
    #[serde(rename = "event")]
    Event,
    /// 羽化→主机：status.query 应答
    #[serde(rename = "status.report")]
    StatusReport,
    /// 羽化→主机：大声拒绝三件套（code + detail + hint）
    #[serde(rename = "error")]
    Error,
    /// 羽化→主机：完工声明（body = manifest JSON；工件经文件族随后到达）
    #[serde(rename = "done")]
    Done,
}

/// 会话信封——控制面唯一消息形态（speak() 帧，单帧 ≤64KB）。
/// 无保活帧（裁定 27：周期流量 = 时序指纹）；order_id 即幂等键。
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionEnvelope {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub session_version: i64,
    pub kind: SessionKind,
    /// 发送方单调序号
    pub seq: u64,
    /// 工单幂等键；与工单无关的消息 = null
    pub order_id: Option<String>,
    /// 词义载体（字段约定见 SKILL.md §10.4 词表）
    pub body: serde_json::Value,
}
