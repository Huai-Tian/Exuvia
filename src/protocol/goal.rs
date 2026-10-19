//! goal.json 类型（SKILL.md §3，DRAFT v0）。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub goal_version: i64,
    pub targets: Vec<Target>,
    pub levels: Levels,
    pub tracks: Vec<Track>,
    /// 目标是否接受语义等效实现销账（false 时 equivalent 类 proposal 被范围闸拒绝）
    #[serde(default)]
    pub accepts_equivalent: bool,
    pub stop: Stop,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Target {
    Method { class: String, method: String },
    Category { profile: String },
    /// 匹配全部自动生成的 encrypted-payload 卡点（坏 DEX 机械事实；语义定位在 goal 作者）
    Payload,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Levels {
    pub default: Level,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub enum Level {
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum Track {
    A,
    B,
    C,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub enum Stop {
    #[serde(rename = "targets-satisfied")]
    TargetsSatisfied,
}
