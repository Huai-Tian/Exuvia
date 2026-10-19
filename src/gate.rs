//! merge 闸门——四层校验，判定权在 Rust（README_AGENT §4.3/4.4）。
//! ① 语法/格式：serde 解析，未知字段拒绝（协议类型自带 deny_unknown_fields）
//! ② 对账：范围闸（workpackage.allowed_debt）+ hash 字节精确 + equivalent 接受性
//! ③ 语义（双锚）：数值测试对走沙箱、结构断言（DEX 形状 → dex::parse）永驻 Rust
//! ④ 结果：通过 → 销账（debt.json 移除、workspace 归档、attempts.log 追加、REPORT 更新）；
//!        拒绝 → 结构化错误（错误码 + 定位 + 期望 + hint）
//! 错误码是第一批实现定义集（SKILL §5 公开表），下游 Agent 依赖以 SKILL 为准。

use crate::protocol::proposal::{ClaimKind, Proposal};
use crate::report::DebtFile;
use crate::sandbox;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::path::Path;

#[derive(Debug)]
pub struct GateError {
    pub code: &'static str,
    pub detail: String,
    pub hint: Option<String>,
}

impl GateError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into(), hint: None }
    }
    fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MergeOutcome {
    pub merged: Vec<String>,
    pub debt_remaining: u64,
}

/// 全流程：读 proposal → 四层 → 销账。handoff_dir 为剖析包目录，workpackage_path 为范围闸数据源。
/// 拒绝时如实留痕：attempts.log 记 merge-rejected 事件 + 对 handoff 中存在的被认领卡点递增 attempts
/// （escalation §6 的数据基础；best-effort——记账失败不产生新的失败源）。
pub fn merge(proposal_dir: &Path, handoff_dir: &Path, workpackage_path: &Path) -> Result<MergeOutcome, GateError> {
    let result = merge_inner(proposal_dir, handoff_dir, workpackage_path);
    if let Err(e) = &result {
        record_rejection(proposal_dir, handoff_dir, e);
    }
    result
}

fn merge_inner(proposal_dir: &Path, handoff_dir: &Path, workpackage_path: &Path) -> Result<MergeOutcome, GateError> {
    // ── ① 语法/格式 ──
    let pp = proposal_dir.join("proposal.json");
    let raw = std::fs::read(&pp).map_err(|e| GateError::new("E_READ", format!("proposal.json: {e}")))?;
    let proposal: Proposal = serde_json::from_slice(&raw).map_err(|e| {
        GateError::new("E_JSON", format!("proposal.json parse: {e}"))
            .hint("unknown or mistyped fields are rejected (gate layer 1); fix the manifest, not the artifacts")
    })?;
    if proposal.schema != "exuvia.proposal" {
        return Err(GateError::new("E_SCHEMA", format!("unexpected $schema: {}", proposal.schema)));
    }
    if proposal.proposal_version != crate::version::PROPOSAL_VERSION {
        return Err(GateError::new(
            "E_VERSION",
            format!("proposal_version {} not supported (tool supports {})", proposal.proposal_version, crate::version::PROPOSAL_VERSION),
        ));
    }

    // ── 范围闸数据源：workpackage.json ──
    let wp_raw = std::fs::read(workpackage_path).map_err(|e| GateError::new("E_SCOPE_SOURCE", format!("{}: {e}", workpackage_path.display())))?;
    let wp: crate::report::WorkPackage = serde_json::from_slice(&wp_raw).map_err(|e| GateError::new("E_SCOPE_SOURCE", format!("workpackage parse: {e}")))?;
    let wp_debt: std::collections::HashSet<&str> = wp.allowed_debt.iter().map(|s| s.as_str()).collect();

    // ── ② 对账 ──
    let mut claimed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for c in &proposal.claims {
        if !wp_debt.contains(c.debt_id.as_str()) {
            return Err(GateError::new(
                "E_SCOPE",
                format!("claim {} is outside the work package (allowed: {:?})", c.debt_id, wp.allowed_debt),
            )
            .hint("claim only debt ids from allowed_debt; re-run exuvia next --goal for a fresh package"));
        }
        if !claimed.insert(c.debt_id.as_str()) {
            return Err(GateError::new("E_DUPLICATE_CLAIM", format!("{} claimed twice", c.debt_id)));
        }
        if c.kind == ClaimKind::Equivalent && !wp.accepts_equivalent {
            return Err(GateError::new(
                "E_EQUIV_NOT_ACCEPTED",
                format!("equivalent claim on {} but goal does not accept it", c.debt_id),
            )
            .hint("rewrite as a recovered claim, or ask the goal author to set accepts_equivalent next round"));
        }
        // hash 字节精确
        let art_path = proposal_dir.join(&c.artifact);
        let art_bytes = std::fs::read(&art_path).map_err(|e| GateError::new("E_MISSING_FILE", format!("artifact {}: {e}", c.artifact)))?;
        let digest = format!(
            "sha256:{}",
            sha2::Sha256::digest(&art_bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let declared = proposal.artifact_hashes.get(&c.artifact).ok_or_else(|| {
            GateError::new("E_HASH_MISMATCH", format!("no artifact_hashes entry for {}", c.artifact))
        })?;
        if &digest != declared {
            return Err(GateError::new(
                "E_HASH_MISMATCH",
                format!("artifact {} hash mismatch: declared {declared}, actual {digest}", c.artifact),
            )
            .hint("re-hash after editing; reordering imports changes the hash"));
        }
        // import 白名单（文本级防线，见 sandbox 模块注释）
        let src = String::from_utf8_lossy(&art_bytes);
        sandbox::check_imports(&src).map_err(|e| GateError::new("E_IMPORT_BLOCKED", e.to_string()))?;
        for t in &c.tests {
            for f in [&t.input, &t.expected] {
                if !proposal_dir.join(f).is_file() {
                    return Err(GateError::new("E_MISSING_FILE", format!("test file {f}")));
                }
            }
        }
    }

    // ── ③ 语义验证（双锚）：数值测试对走沙箱，判定在 Rust ──
    for c in &proposal.claims {
        for t in &c.tests {
            let input = std::fs::read(proposal_dir.join(&t.input)).map_err(|e| GateError::new("E_MISSING_FILE", format!("{}: {e}", t.input)))?;
            let expected = std::fs::read(proposal_dir.join(&t.expected)).map_err(|e| GateError::new("E_MISSING_FILE", format!("{}: {e}", t.expected)))?;
            let art_abs = proposal_dir.join(&c.artifact).to_string_lossy().into_owned();
            let out = sandbox::run_artifact(&art_abs, &c.entry, &input).map_err(|e| match e {
                sandbox::SandboxError::Timeout => GateError::new(
                    "E_SANDBOX_TIMEOUT",
                    format!("artifact {} exceeded soft timeout on input {}", c.artifact, t.input),
                )
                .hint("check for unbounded loops; the CPU rlimit is the hard backstop"),
                other => GateError::new("E_SANDBOX", format!("{} on input {}: {other}", c.artifact, t.input)),
            })?;
            if out != expected {
                let (ep, ap) = (hex_prefix(&expected, 8), hex_prefix(&out, 8));
                return Err(GateError::new(
                    "E_OUTPUT_MISMATCH",
                    format!("{} on input {}: expected starts {ep}, got {ap}", c.debt_id, t.input),
                )
                .hint(format!("build expected values from independent format facts (DEX magic = \"dex\\n035\\0\"), never from your own algorithm's output")));
            }
            // 结构断言（Rust 可信侧）：recovered 且输出呈 DEX 形状 → 必须过 dex::parse
            if c.kind == ClaimKind::Recovered && out.starts_with(b"dex\n") {
                if crate::track_a::dex::parse(&out).is_err() {
                    return Err(GateError::new(
                        "E_STRUCT_INVALID",
                        format!("{} output claims DEX shape but fails structural parse", c.debt_id),
                    )
                    .hint("output has DEX magic but broken tables; re-check the decryption key assumption"));
                }
            }
        }
    }

    // ── ④ 销账落盘 ──
    let debt_path = handoff_dir.join("debt.json");
    let debt_raw = std::fs::read(&debt_path).map_err(|e| GateError::new("E_READ", format!("debt.json: {e}")))?;
    let mut debt: DebtFile = serde_json::from_slice(&debt_raw).map_err(|e| GateError::new("E_JSON", format!("debt.json parse: {e}")))?;
    let claimed_set: std::collections::HashSet<String> = proposal.claims.iter().map(|c| c.debt_id.clone()).collect();
    debt.entries.retain(|e| !claimed_set.contains(&e.debt_id));

    // 归档进 workspace/<debt_id>/，追加 attempts.log（无时间戳：产物字节确定性）
    for c in &proposal.claims {
        let wdir = handoff_dir.join("workspace").join(&c.debt_id);
        std::fs::create_dir_all(&wdir).map_err(|e| GateError::new("E_IO", format!("mkdir workspace: {e}")))?;
        std::fs::write(wdir.join("artifact"), std::fs::read(proposal_dir.join(&c.artifact)).unwrap_or_default()).ok();
        for t in &c.tests {
            std::fs::write(wdir.join(std::path::Path::new(&t.input).file_name().unwrap_or_default()), std::fs::read(proposal_dir.join(&t.input)).unwrap_or_default()).ok();
            std::fs::write(wdir.join(std::path::Path::new(&t.expected).file_name().unwrap_or_default()), std::fs::read(proposal_dir.join(&t.expected)).unwrap_or_default()).ok();
        }
        // L1 骨架最小兑现：recovered 产物的闸门验证值呈 DEX 形状 → 归档为 recovered.dex（jadx 可开）。
        // 数值锚已保证 expected == 沙箱输出，无需重跑；取第一个 DEX 形状的测试对。
        if c.kind == ClaimKind::Recovered {
            for t in &c.tests {
                if let Ok(b) = std::fs::read(proposal_dir.join(&t.expected)) {
                    if b.starts_with(b"dex\n") {
                        std::fs::write(wdir.join("recovered.dex"), &b).ok();
                        break;
                    }
                }
            }
        }
        let line = serde_json::json!({
            "event": "merge-ok",
            "debt_id": c.debt_id,
            "kind": if c.kind == ClaimKind::Recovered { "recovered" } else { "equivalent" },
            "goal_sha256": wp.goal_sha256,
            "generator": proposal.generator,
        });
        use std::io::Write as _;
        let mut log = std::fs::OpenOptions::new().create(true).append(true).open(handoff_dir.join("attempts.log")).map_err(|e| GateError::new("E_IO", format!("attempts.log: {e}")))?;
        writeln!(log, "{line}").map_err(|e| GateError::new("E_IO", format!("attempts.log write: {e}")))?;
    }

    // debt.json 与 REPORT.debt 重写（审计事实同步；REPORT.md 同步渲染）
    let total = debt.entries.len() as u64;
    std::fs::write(&debt_path, serde_json::to_vec_pretty(&debt).unwrap()).map_err(|e| GateError::new("E_IO", format!("debt write: {e}")))?;
    let report_path = handoff_dir.join("REPORT.json");
    if let Ok(mut r) = serde_json::from_slice::<crate::report::Report>(&std::fs::read(&report_path).unwrap_or_default()) {
        r.debt.blocked_solvable = r.debt.blocked_solvable.saturating_sub(claimed_set.len() as u64);
        r.debt.total = total;
        std::fs::write(&report_path, serde_json::to_vec_pretty(&r).unwrap()).ok();
        std::fs::write(handoff_dir.join("REPORT.md"), crate::report::render_markdown(&r)).ok();
    }

    Ok(MergeOutcome {
        merged: proposal.claims.iter().map(|c| c.debt_id.clone()).collect(),
        debt_remaining: total,
    })
}

/// 拒绝留痕（best-effort，任何失败静默放弃——记账不是新的失败源）：
/// ① attempts.log 追加 merge-rejected（错误码 + hint + 能读出的 generator）；
/// ② proposal 里被认领且存在于 handoff 的 debt_id，attempts 计数 +1（提交即尝试）。
fn record_rejection(proposal_dir: &Path, handoff_dir: &Path, e: &GateError) {
    let mut line = serde_json::json!({
        "event": "merge-rejected",
        "code": e.code,
        "detail": e.detail,
    });
    if let Some(h) = &e.hint {
        line["hint"] = serde_json::json!(h);
    }
    let claims: Vec<String> = std::fs::read(proposal_dir.join("proposal.json"))
        .ok()
        .and_then(|raw| serde_json::from_slice::<Proposal>(&raw).ok())
        .map(|p| {
            line["generator"] = serde_json::json!(p.generator);
            p.claims.into_iter().map(|c| c.debt_id).collect()
        })
        .unwrap_or_default();
    if !claims.is_empty() {
        line["claims"] = serde_json::json!(claims);
    }
    use std::io::Write as _;
    if let Ok(mut log) = std::fs::OpenOptions::new().create(true).append(true).open(handoff_dir.join("attempts.log")) {
        let _ = writeln!(log, "{line}");
    }
    // attempts 递增：只动 handoff 中存在的条目（范围外认领不动账）
    let debt_path = handoff_dir.join("debt.json");
    if let Ok(mut debt) = std::fs::read(&debt_path)
        .map_err(|_| ())
        .and_then(|raw| serde_json::from_slice::<DebtFile>(&raw).map_err(|_| ()))
    {
        let mut changed = false;
        for entry in debt.entries.iter_mut() {
            if claims.contains(&entry.debt_id) {
                entry.attempts += 1;
                changed = true;
            }
        }
        if changed {
            if let Ok(bytes) = serde_json::to_vec_pretty(&debt) {
                let _ = std::fs::write(&debt_path, bytes);
            }
        }
    }
}

fn hex_prefix(data: &[u8], n: usize) -> String {
    data.iter().take(n).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

/// `unpack validate`：下游自检剖析包可读性与版本。
pub fn validate(handoff_dir: &Path) -> Result<serde_json::Value, GateError> {
    let report: crate::report::Report = serde_json::from_slice(
        &std::fs::read(handoff_dir.join("REPORT.json")).map_err(|e| GateError::new("E_READ", format!("REPORT.json: {e}")))?,
    )
    .map_err(|e| GateError::new("E_JSON", format!("REPORT parse: {e}")))?;
    let debt: DebtFile = serde_json::from_slice(
        &std::fs::read(handoff_dir.join("debt.json")).map_err(|e| GateError::new("E_READ", format!("debt.json: {e}")))?,
    )
    .map_err(|e| GateError::new("E_JSON", format!("debt parse: {e}")))?;
    if report.handoff_version != crate::version::HANDOFF_VERSION || debt.handoff_version != crate::version::HANDOFF_VERSION {
        return Err(GateError::new("E_VERSION", "handoff_version mismatch"));
    }
    if report.debt.total != debt.entries.len() as u64 {
        return Err(GateError::new(
            "E_INTERNAL_STATE",
            format!("REPORT.debt.total {} != debt.entries {}", report.debt.total, debt.entries.len()),
        ));
    }
    Ok(serde_json::json!({ "valid": true, "debt": debt.entries.len() }))
}
