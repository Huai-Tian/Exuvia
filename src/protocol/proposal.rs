//! proposal.json 类型（SKILL.md §4，DRAFT v0）。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub proposal_version: i64,
    pub claims: Vec<Claim>,
    pub artifact_hashes: BTreeMap<String, String>,
    pub generator: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub debt_id: String,
    /// 产出路径，闸门按此路由验证：recovered → 结构断言×字节测试；equivalent → 行为差分
    pub kind: ClaimKind,
    pub artifact: String,
    pub entry: String,
    pub tests: Vec<TestPair>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClaimKind {
    Recovered,
    Equivalent,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestPair {
    pub input: String,
    pub expected: String,
}
