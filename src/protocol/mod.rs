//! 三条协议的 serde 类型——格式的机器事实源。
//! 严格对齐 SKILL.md §3/§4（DRAFT v0）：不发明契约外的字段；
//! deny_unknown_fields 实现"未知字段拒绝"（闸门第①层）。

pub mod collector;
pub mod goal;
pub mod proposal;

pub use collector::{CollectorManifest, HygieneCatalog, WorkOrder};
pub use goal::{Goal, Target, Track};
pub use proposal::{Claim, ClaimKind, Proposal};

use clap::ValueEnum;

/// schema --dump 的目标名。handoff 格式尚未 DRAFT，仅保留名字位（CLI 契约已拍板支持范围）。
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum SchemaName {
    Handoff,
    Goal,
    Proposal,
}

/// 从类型按需派生机器可读格式（schema 是视图不是实体，无静态 schema 文件）。
/// handoff = 四协议物的联合视图（report / debt / workpackage / evidence）。
pub fn schema_dump(name: SchemaName) -> Result<String, String> {
    match name {
        SchemaName::Handoff => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "report": schemars::schema_for!(crate::report::Report),
            "debt": schemars::schema_for!(crate::report::DebtFile),
            "workpackage": schemars::schema_for!(crate::report::WorkPackage),
            "evidence": schemars::schema_for!(crate::report::EvidenceManifest),
        }))
        .unwrap()),
        SchemaName::Goal => Ok(serde_json::to_string_pretty(&schemars::schema_for!(Goal)).unwrap()),
        SchemaName::Proposal => Ok(serde_json::to_string_pretty(&schemars::schema_for!(Proposal)).unwrap()),
    }
}
