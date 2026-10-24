//! 版本锚点——与 SKILL.md §11 的版本锚点节双向绑定（tests/skill_doc.rs 断言一致性）。

pub const EXUVIA_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SKILL_VERSION: &str = "1.13.1";
pub const HANDOFF_VERSION: i64 = 1;
pub const GOAL_VERSION: i64 = 1;
pub const PROPOSAL_VERSION: i64 = 1;
pub const WORKORDER_VERSION: i64 = 2;
pub const MANIFEST_VERSION: i64 = 1;
pub const HYGIENE_VERSION: i64 = 1;

pub fn protocol_line() -> String {
    format!(
        "skill {} | handoff {} | goal {} | proposal {} | workorder {} | manifest {} | hygiene {}",
        SKILL_VERSION,
        HANDOFF_VERSION,
        GOAL_VERSION,
        PROPOSAL_VERSION,
        WORKORDER_VERSION,
        MANIFEST_VERSION,
        HYGIENE_VERSION
    )
}
