# SKILL — Exuvia

Exuvia: deterministic Android unpacking pipeline. `exuvia packed.apk` → dissection handoff (L1 skeleton + debt + evidence), zero LLM tokens. §3/§4 are format DRAFT v0 (maintainer audits fields); fixtures here are the source of truth for serde types.

## 1. Actions

1. READ `handoff/REPORT.json` + `debt.json` (§2)
2. WRITE `goal.json` (§3) — semantic targeting is yours; the tool executes formatted targets only
3. SUBMIT proposal package (§4); on rejection: read error → patch → resubmit (§5)

Hard limits: never modify `workspace/`; never claim debt ids outside your work package; never submit prose where an executable artifact is required.
Work packages may inject family guidance — follow it first; it outranks general intuition.

## 2. Handoff

`REPORT.json` (machine index; CI fixture):

```json
{
  "$schema": "exuvia.report",
  "handoff_version": 1,
  "apk": { "sha256": "…", "size_bytes": 0 },
  "fingerprint": { "matched": false, "family": null, "confidence": null },
  "inventory": {
    "dex": [{ "name": "classes.dex", "size_bytes": 0, "magic_ok": true, "parse_ok": true }],
    "so": [{ "name": "lib/arm64-v8a/libtest.so", "abi": "arm64-v8a", "size_bytes": 0 }],
    "assets": [{ "name": "assets/payload.bin", "size_bytes": 0, "entropy": 7.941 }],
    "android_manifest_present": true,
    "other_entries": 0
  },
  "debt": { "total": 1, "blocked_solvable": 1, "out_of_scope": 0 },
  "unavailable": []
}
```

`debt.json` (entry list; CI fixture):

```json
{
  "$schema": "exuvia.debt",
  "handoff_version": 1,
  "entries": [
    {
      "debt_id": "debt-0001",
      "method": { "class": "com.example.LoginManager", "name": "sign", "descriptor": "(Landroid/content/Context;[B)[B" },
      "status": "blocked-solvable",
      "facts": [
        "native stub — body outside DEX (access_flags ACC_NATIVE)",
        "symbol Java_com.example.LoginManager_sign → lib/arm64-v8a/libtest.so (dynsym, st_value=0x1204, st_size=64)"
      ],
      "evidence": ["evidence/debt-0001/"],
      "attempts": 0
    }
  ]
}
```

`workpackage.json` (output of `exuvia next --goal`; scope-gate source; CI fixture):

```json
{
  "$schema": "exuvia.workpackage",
  "goal_sha256": "sha256:…",
  "handoff_version": 1,
  "accepts_equivalent": true,
  "tracks": ["A", "B"],
  "guidance": [],
  "allowed_debt": ["debt-0001"],
  "entries": [
    {
      "debt_id": "debt-0001",
      "method": { "class": "com.example.LoginManager", "name": "sign", "descriptor": "(Landroid/content/Context;[B)[B" },
      "status": "blocked-solvable",
      "facts": [
        "native stub — body outside DEX (access_flags ACC_NATIVE)",
        "symbol Java_com.example.LoginManager_sign → lib/arm64-v8a/libtest.so (dynsym, st_value=0x1204, st_size=64)"
      ],
      "evidence": ["evidence/debt-0001/"],
      "attempts": 0
    }
  ]
}
```

- `allowed_debt` is the scope-gate source: your proposal may only claim these debt ids.
- `guidance` empty = family knowledge not matched/absent in the fence; when present it outranks general intuition.

`evidence/<debt_id>/` (sliced so bytes for each symbol hit; CI fixture):

```json
{
  "$schema": "exuvia.evidence",
  "debt_id": "debt-0001",
  "so": "lib/arm64-v8a/libtest.so",
  "symbol": "Java_com.example.LoginManager_sign",
  "st_value": 4612,
  "st_size": 64,
  "file_offset": 4628,
  "slice_sha256": "sha256:…"
}
```

- `slice.bin` beside the manifest carries the method-body bytes; verify the hash before trusting them.

- `fingerprint.matched = false` → unknown-family full exploration. Normal, not an error; it is the default while the fence defines no fingerprint.
- `dex[].magic_ok` false or `parse_ok` false → encrypted/corrupt DEX (hostile-input normal): no method facts from that file; a high-entropy asset beside it is the classic packer shape.
- `assets[].entropy` = Shannon bits/byte (0..8), a raw measurement — no thresholds applied, interpretation is yours.
- `unavailable[]` → absent external capabilities; related levels annotated, nothing fails.
- `workspace/` L1 skeleton is jadx-compatible — if structure/navigation alone answers the task, read it and stop.
- debt entry = facts + difficulty signals, no cost estimates (you price tokens):
  - `status = blocked-solvable` → your arena; `out-of-scope` → spend nothing;
  - `jni_calls` high → JNI idiom lens; `vm_handlers` high → VMP, weigh out-of-scope (§6 step 2) first; `opcode_entropy` high without vm_handlers → control-flow obfuscation, tractable;
  - thresholds live in the fence (§7).
- Two output paths per method, chosen by cost comparison (yours, from the facts above): `recovered` (restore original bytes) vs `equivalent` (read the L2 decompilation of the native code, write a functionally equivalent implementation). When recovery cost far exceeds equivalent-implementation cost, take the `equivalent` path — but only if `accepts_equivalent` is set in the goal (§3).
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
| `accepts_equivalent` | bool, default `false` — if true, debt may be cleared by a `kind = "equivalent"` proposal (§4) |
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
  "accepts_equivalent": true,
  "stop": "targets-satisfied"
}
```

Natural language in targets is rejected.

## 4. Proposal package — DRAFT v0

Structure: `proposal.json` (manifest) + `artifacts/` + `tests/`. Rules:

- claims limited to work-package debt ids (scope gate);
- `claims[].kind` routes gate validation: `"recovered"` → structural assertion (legal DEX, magic, class-count reconciliation) × byte-level tests; `"equivalent"` → behavioral differential tests only; an `equivalent` claim against a goal without `accepts_equivalent` is rejected at the scope layer;
- artifacts: pure functions, bytes → bytes, no I/O / network / global state; sandbox enforces an import whitelist;
- test pairs: for `recovered`, expected values from independent format facts (DEX magic = `"dex\n035\0"`), never from your own algorithm's output; for `equivalent`, expected values derived from reading the L2 decompilation of the native code — the differential proves behavior on covered cases, not full equivalence;
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
      "kind": "recovered",
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

Layers: syntax/format (serde, unknown fields rejected) → scope + hash reconciliation (including `accepts_equivalent` check for `kind = "equivalent"` claims) → semantic, routed by `kind`: structural assertion Rust-side × byte tests (`recovered`) or behavioral differential (`equivalent`) → verdict.
Rejection = `error code + detail + hint` on stderr, exit 1. The hint outranks intuition.

Documented error codes (this set is authoritative; do not rely on others):

| code | layer | meaning |
|---|---|---|
| `E_JSON` / `E_SCHEMA` / `E_VERSION` | ① | manifest parse failed / wrong `$schema` / unsupported version |
| `E_SCOPE_SOURCE` | ② | workpackage.json missing or unreadable (re-run `next`) |
| `E_SCOPE` / `E_DUPLICATE_CLAIM` | ② | debt id outside `allowed_debt` / claimed twice |
| `E_EQUIV_NOT_ACCEPTED` | ② | `equivalent` claim while goal lacks `accepts_equivalent` |
| `E_HASH_MISMATCH` | ② | artifact bytes ≠ declared hash |
| `E_MISSING_FILE` | ② | artifact or test file absent |
| `E_IMPORT_BLOCKED` | ② | import outside the sandbox whitelist |
| `E_SANDBOX_TIMEOUT` / `E_SANDBOX` | ③ | soft timeout (CPU rlimit is the hard backstop) / execution failure |
| `E_OUTPUT_MISMATCH` | ③ | output ≠ expected test value |
| `E_STRUCT_INVALID` | ③ | output has DEX shape but fails structural parse (Rust-side anchor) |
| `E_READ` / `E_IO` / `E_INTERNAL_STATE` | — | tool-side I/O or handoff state inconsistency |

## 6. Escalation

1. Re-read work-package guidance + attempts.log for this debt id.
2. Signals indicate out-of-scope (vm_handlers high, device-bound key, network payload) → conclude without a proposal; report. Exit.
3. Recovery cost far exceeds equivalent-implementation cost (heavy VMP, aggressive control-flow) → switch to the `equivalent` path (§2), requires `accepts_equivalent` in the goal; goal not set → reorder `targets` next round with it set, or report the trade-off to the user.
4. Need a prerequisite (adjacent method, key derivation) → reorder `targets` next round.
5. Rejected twice → hint holds the reason; one more fix with a different approach. A third identical approach is waste.
6. Still stuck → attempts.log-grade note: tried / why failed / next. Honest debt is a valid deliverable.

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
