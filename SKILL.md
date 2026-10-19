# SKILL — Exuvia

Exuvia: deterministic Android unpacking pipeline. `exuvia packed.apk` → dissection handoff (L1 skeleton + debt + evidence), zero LLM tokens. §3/§4 are format DRAFT v0 (maintainer audits fields); fixtures here are the source of truth for serde types.

## 1. Actions

1. READ `handoff/REPORT.json` + `debt.json` (§2)
2. WRITE `goal.json` (§3) — semantic targeting is yours; the tool executes formatted targets only
3. SUBMIT proposal package (§4); on rejection: read error → patch → resubmit (§5)

Hard limits: never modify `workspace/`; never claim debt ids outside your work package; never submit prose where an executable artifact is required.
Work packages may inject family guidance — follow it first; it outranks general intuition.

## 2. Handoff

- `fingerprint.matched = false` → unknown-family full exploration. Normal, not an error.
- `unavailable[]` → absent external capabilities; related levels annotated, nothing fails.
- `workspace/` L1 skeleton is jadx-compatible — if structure/navigation alone answers the task, read it and stop.
- debt entry = facts + difficulty signals, no cost estimates (you price tokens):
  - `status = blocked-solvable` → your arena; `out-of-scope` → spend nothing;
  - `jni_calls` high → JNI idiom lens; `vm_handlers` high → VMP, weigh out-of-scope (§6 step 2) first; `opcode_entropy` high without vm_handlers → control-flow obfuscation, tractable;
  - thresholds live in the fence (§7).
- `attempts.log`: read before attempting. A path that died twice is dead.

## 3. goal.json — DRAFT v0

Every field machine-decidable. Categories are named lookup tables defined in the fence (§7).

| Field | Semantics |
|---|---|
| `$schema` | literal `"exuvia.goal"` |
| `goal_version` | `1` |
| `targets[].kind` | `"method"` or `"category"` |
| `targets[].class` / `.method` | exact match, names as they appear in debt.json |
| `targets[].profile` | category name defined in the fence |
| `levels.default` | `"L1"` / `"L2"` / `"L3"` |
| `tracks` | subset of `["A","B","C"]` |
| `stop` | `"targets-satisfied"` — targets cleared, a fact not a promise |

Example (CI fixture):

```json
{
  "$schema": "exuvia.goal",
  "goal_version": 1,
  "targets": [
    { "kind": "method", "class": "com.example.LoginManager", "method": "sign" },
    { "kind": "category", "profile": "network-entrypoints" }
  ],
  "levels": { "default": "L2" },
  "tracks": ["A", "B"],
  "stop": "targets-satisfied"
}
```

Natural language in targets is rejected.

## 4. Proposal package — DRAFT v0

Structure: `proposal.json` (manifest) + `artifacts/` + `tests/`. Rules:

- claims limited to work-package debt ids (scope gate);
- artifacts: pure functions, bytes → bytes, no I/O / network / global state; sandbox enforces an import whitelist;
- `.in`/`.out` pairs built from independent format facts (DEX magic = `"dex\n035\0"`), never from your own algorithm's output — the dual anchor catches self-consistent errors;
- artifact hashes byte-exact; hash before submitting;
- no timestamps or machine names — identical content must produce identical bytes.

Example (CI fixture):

```json
{
  "$schema": "exuvia.proposal",
  "proposal_version": 1,
  "claims": [
    {
      "debt_id": "debt-0f3a",
      "artifact": "artifacts/decrypt_a3f9.py",
      "entry": "decrypt",
      "tests": [{ "input": "tests/slice-a3f9.in", "expected": "tests/slice-a3f9.out" }]
    }
  ],
  "artifact_hashes": {
    "artifacts/decrypt_a3f9.py": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "generator": "<agent-identifier>"
}
```

## 5. Merge gate

Layers: syntax/format (serde, unknown fields rejected) → scope + hash reconciliation → semantic (structural assertion Rust-side × numeric tests in sandbox) → verdict.
Rejection = `error code + location + expected + hint`. The hint outranks intuition. Error codes are implementation-defined — do not invent or rely on undocumented ones.

## 6. Escalation

1. Re-read work-package guidance + attempts.log for this debt id.
2. Signals indicate out-of-scope (vm_handlers high, device-bound key, network payload) → conclude without a proposal; report. Exit.
3. Need a prerequisite (adjacent method, key derivation) → reorder `targets` next round.
4. Rejected twice → hint holds the reason; one more fix with a different approach. A third identical approach is waste.
5. Still stuck → attempts.log-grade note: tried / why failed / next. Honest debt is a valid deliverable.

## 7. Profile fence

```toml profile
# anchor: info string "toml profile". Rust extracts + parses at startup;
# TOML syntax error = installation-broken.
# growth rules (binding): sections and fields earned from implementation need
# only (a need x3, including section names); family knowledge only after
# maintainer-validated research, vendor names forbidden (technical-family
# naming); knowledge/value additions = minor, methodology/format = major
# (human confirmation). current state: empty by design.
```

## 8. Version anchors

```text
SKILL_VERSION: 1.0.0
handoff_version: 1    goal_version: 1    proposal_version: 1
```

- File version = methodology + §7 fence snapshot. Format changes start in fixtures, serde types follow, CI binds both directions.
- Before adapting to a new environment, compare `exuvia --version` against these.
