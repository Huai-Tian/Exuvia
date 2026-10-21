//! 版本锚点——与 SKILL.md §8 的版本锚点节双向绑定（tests/skill_doc.rs 断言一致性）。

pub const EXUVIA_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SKILL_VERSION: &str = "1.3.0";
pub const HANDOFF_VERSION: i64 = 1;
pub const GOAL_VERSION: i64 = 1;
pub const PROPOSAL_VERSION: i64 = 1;

pub fn protocol_line() -> String {
    format!(
        "skill {} | handoff {} | goal {} | proposal {}",
        SKILL_VERSION, HANDOFF_VERSION, GOAL_VERSION, PROPOSAL_VERSION
    )
}
