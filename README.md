# Exuvia

[简体中文](README_ZH.md) | English | [AI collaboration doc](README_AGENT.md)

## 📖 Introduction

**Exuvia** (蝉蜕) is a deterministic Android unpacking / code-recovery pipeline built for AI agents, aimed at the new generation of enterprise-grade packers.

One Rust binary performs every mechanical step at **zero token cost** — unpack, inventory, entropy measurement, DEX parsing, JNI symbol location, decrypt-routine candidate locating, evidence slicing — and compresses every genuine gap of intelligence into a **work package** that an external LLM solves. The tool itself never calls a model and never pretends to understand: wherever judgment is needed, a formatted interface hands it to the side that actually has intelligence. Verification of returned solutions is *not* outsourced either — structural assertions live on the Rust-trusted side, numeric test pairs run in a hardened `python3 -I` sandbox, and the word "passed" is one only Rust gets to say.

The ontology is deliberate: **body** (a single binary, including the embedded sandbox runner — nothing ever written to disk), **soul** (a single SKILL.md file carrying the methodology, the format fixtures that double as CI golden files, and the profile fence), **interface** (three protocol streams: handoff / goal / proposal). There is no schema file — the serde types are the format; `exuvia schema --dump` derives machine-readable views on demand.

**Zero learning curve by design**: Exuvia does not rely on accumulated experience. The first analysis of an unknown packer already runs at peak performance because the judgment is injected through architecture (structured starting point, preloaded common sense, per-stub work packages, dual-anchor verification) — not through a fingerprint database that grows with history. When a new packer generation appears, that is once again "a first time that feels like a second time".

> **Using an AI assistant (Copilot / Claude / GPT ...) for development on this project?** Read [README_AGENT.md](README_AGENT.md) first — it is written specifically for AI and contains the project's many **counter-intuitive design decisions and hard red lines**. Skipping it and editing code directly is very likely to reintroduce a decision that was deliberately overturned.

## ✨ Features

- **Drag in, get a map — zero questions, zero tokens**
  `exuvia packed.apk` produces the full dissection handoff: `REPORT.json` + `REPORT.md` (human half), `debt.json` (the honest blocklist), `evidence/` (hash-anchored byte slices), `workspace/`, `attempts.log`. Non-interactive is a hard constraint — any prompt would kill the agent scenario.

- **Two debt kinds, both machine-decided**
  `method-native-stub`: every `ACC_NATIVE` stub is located mechanically — JNI short-name and mangled-signature derivation → dynsym lookup → the method body sliced out of the `.so` (VA → file offset via PT_LOAD). `encrypted-payload`: every claimed-DEX file whose bytes are not DEX becomes an automatic debt entry — no entropy thresholds, just the mechanical fact — with a 64-KiB head slice, raw asset entropies listed as facts, and decrypt-routine candidates located mechanically (`JNI_OnLoad` symbol table hits, `.init_array` section positions).

- **The outsourcing loop — the only place tokens burn**
  `exuvia next --goal goal.json` packs a work package (scope-gate source + evidence references + guidance). An external LLM returns a `proposal/` package: a pure decryption function plus test pairs whose expected values must come from independent format facts, never from the submitter's own output. The loop's driver always lives outside the tool.

- **Four merge gates, verdict in Rust**
  ① syntax/format (serde with unknown fields rejected) → ② reconciliation (scope gate: only debt ids from the work package; byte-exact hashes; `accepts_equivalent` routing) → ③ semantics (**dual anchor**: structural assertions parse the DEX on the trusted side × byte tests in the sandbox — the two anchors never depend on the untrusted layer at the same time) → ④ settle: archive the artifact, drop the debt, append `attempts.log`. Rejections are structured `code + detail + hint` for agents to read, and they increment `attempts` on the claimed debt.

- **L1 recovery on merge**
  A `recovered` claim whose output has DEX shape is archived as `workspace/<debt_id>/recovered.dex` — open it in jadx immediately.

- **Hardened sandbox, zero persistence**
  The glue runner lives inside the binary as a string resource and is fed via stdin to `python3 -I` — no unpacking to disk (a security tool must not look like malware). Environment is cleared; CPU 10 s / address space 512 MB / fd 64 rlimits backstop a 5 s soft timeout; a text-level import whitelist guards misuse.

- **Hostile-input hardened**
  Every size/offset field is bounds-checked against the data length before any allocation — the DEX parser was battle-tested against a forged 126-GB allocation attack. A corrupt DEX is a *fact* (`magic_ok`/`parse_ok`), never a crash of the whole run.

- **Byte-deterministic outputs**
  No timestamps, stable debt ordering, entropy rounded to 3 decimals: identical input produces byte-identical handoffs. Determinism is a protocol requirement, not a nicety — the double-anchored CI fixtures depend on it.

- **CLI is the API (deliberately no MCP)**
  Output is JSON across the board, with structured error codes documented in SKILL.md §5; exit codes split into exactly two semantic worlds — `installation-broken` (own components damaged: refuse to run, code 2) vs `unavailable` (external capabilities absent: annotate, never fail). `--profile` overrides the judgment embedded in the SKILL fence; `--resume` skips re-dissection idempotently; `--json` makes even `--version` machine-readable.

- **Honest debt, vendor-neutral naming**
  Debt entries carry facts and difficulty signals only — no cost estimates (a deterministic binary does not know token prices; you price them). Fingerprints, SOPs and processors are named by *technical family* ("whole-file encryption — single segment", "JNI translation idiom") — never by vendor name, by design and enforced in contributions.

## 📐 The outsourcing loop

```
exuvia packed.apk ──► handoff/   (REPORT.json+md · debt.json · evidence/ · workspace/)
        │                          all mechanical, zero tokens
        │
        │   read REPORT + debt, write goal.json          (semantic targeting is
        ▼    — yours; the tool only matches machine facts          yours too)
  exuvia next --goal goal.json ──► workpackage.json      (scope-gate source)
        │
        │   solve the package: pure decrypt function
        ▼    + test pairs from independent facts         the only token-burning step
  external LLM ──► proposal/
        │
        ▼
  exuvia unpack merge proposal/
        │   gate ① serde  ② scope+hash  ③ dual-anchor semantics  ④ settle
        ▼
  debt settled · workspace/<debt_id>/recovered.dex ──► validate, or loop again
```

Two output paths per debt, chosen by cost comparison (yours): `recovered` (restore the original bytes) vs `equivalent` (write a functionally equivalent implementation) — the latter requires `accepts_equivalent` in the goal and passes behavioral differential tests instead of byte-level ones.

## 🚀 Quick Start

Build from source (no release binaries yet — the planned release form is two platform binaries + SKILL.md + checksums, nothing else):

```bash
cargo build --release
```

Prerequisite: a system `python3` on PATH. It is the sandbox executor for merge-gate semantic verification — a *bound* component of the design (IDA-style assumption), never bundled; missing or fake = `installation-broken`, and the tool refuses to run rather than degrade.

```bash
# 1) Dissect (zero tokens)
exuvia packed.apk

# 2) Read handoff/REPORT.json + handoff/debt.json, then write goal.json.
#    Semantic targeting is yours; every field is machine-decidable:
cat > goal.json <<'EOF'
{
  "$schema": "exuvia.goal",
  "goal_version": 1,
  "targets": [{ "kind": "payload" }],
  "levels": { "default": "L2" },
  "tracks": ["A"],
  "accepts_equivalent": true,
  "stop": "targets-satisfied"
}
EOF

# 3) Pack the stub work package (mechanical filtering, no ranking, no verdict)
exuvia next --goal goal.json

# 4) External LLM reads the package, returns proposal/
#    (pure functions bytes→bytes, test pairs built from independent format facts)

# 5) Return flow: four gates, dual-anchor verification, Rust-side verdict
exuvia unpack merge proposal/

# 6) Downstream self-check of the handoff
exuvia unpack validate handoff/
```

## 🧩 CLI Reference

| Command / flag | Semantics |
|---|---|
| `exuvia packed.apk` | Drag-and-drop dissection → handoff/ |
| `--resume` | Idempotent: skip re-dissection when the handoff's APK sha256 matches |
| `--profile <file>` | Override the judgment embedded in the SKILL.md fence (TOML; parse failure = installation-broken) |
| `--json` | Output is JSON anyway; this flag JSON-ifies `--version` too |
| `--version` | Version + supported protocol versions |
| `exuvia next --goal <file>` | Pack the work package (scope-gate source) |
| `exuvia schema --dump <handoff\|goal\|proposal>` | Derive machine-readable format views on demand (no static schema files) |
| `exuvia unpack merge <dir>` | Proposal return flow: four gates → settle |
| `exuvia unpack validate <dir>` | Handoff self-check before downstream consumption |

Exit codes: **2** = `installation-broken` (own components; refuse to run — there is no degraded mode); **1** = a merge rejection with a structured `code + detail + hint` on stderr; **0** = success — and a handoff with remaining debt *is* success (debt is a deliverable, not a failure).

## ⚙️ Requirements

- **OS**: Linux x64 (current CI baseline). A Windows exe is a planned release target; the OS-level sandbox currently implements Linux rlimits, with the Windows Job Object path scheduled for the release engineering phase.
- **Build**: Rust stable (edition 2024).
- **Runtime**: a system `python3` (sandbox verification layer — bound, never bundled); no root required; expect hostile inputs by default and prefer a disposable snapshot environment.
- **No other runtime is shipped or required**: the pipeline carries no Python distribution of its own.

## ⚠️ Project Status

Research-grade, v0.1. The full protocol loop (`packed.apk` → next → merge → validate) is implemented and graduated on synthetic samples (36 tests, CI-enforced fixture↔serde double anchoring, byte-deterministic outputs). **It has not yet been battle-tested against a real packed sample** — the first dissection of a real first-generation packer is the next milestone, and everything after that is expected to teach the tool some humility.

Honest scope notes — static/simulated analysis cannot solve these, and the debt list says so instead of pretending: device-environment-derived keys (IMEI, build fingerprint), network-fetched payloads, streamed DEX assembly, and full semantic recovery of VMP (that last one is Track C / L3 territory — "equivalent semantics", not original bytes).

The end state is defined behaviorally, not byte-exactly: an installable, runnable APK with behavioral parity. Restoring the original bytes is the most reliable *means* for one- and two-generation packers; equivalent implementations serve where original bytes never existed.

## 🚫 Non-Commercial Statement

This project is initiated by the developer out of personal interest and for technical research purposes, and is **non-commercial** in nature:

- **Permanently Free**:
This project is completely free, with **no paid features, memberships, subscriptions, or in-app purchases**. All features are fully accessible to all users.

- **No Sponsorship Channels**:
The author has **never opened any sponsorship channels**, nor does the author **accept any financial donations** — to maintain the project's neutrality and purity.

- **Non-Profit Purpose**:
This project involves no commercial operations, and the author derives no direct or indirect financial benefit from it.

- **Research-Oriented**:
This project is consistently positioned for **security research, packer adversarial research, software testing and education** — providing a research tool for the community, not a commercial product. Any commercial use of this project is the user's own initiative and is unrelated to this project.

- **License is AGPL-3.0-only — no commercial exceptions.**
This project is offered under the terms of the AGPL-3.0 (see LICENSE),
and every use must comply with that license in full. AGPL was chosen over
GPL deliberately: it closes the "wrap it as a paid API without releasing
the modifications" loophole. The author does not offer, and will not
negotiate, dual licensing, commercial exceptions, or proprietary
redistribution. Reselling this project for profit while ignoring AGPL
obligations is copyright infringement.

- **Attribution and statement integrity:**
Redistribution of unmodified builds is permitted only together with
this statement and proper attribution. Removing, altering, or obscuring
this non-commercial statement when redistributing is prohibited.

- **Official channels only:**
Obtain this project only from this repository (GitHub) or other
officially designated channels. Builds from any other source are
unofficial, unverified, and used entirely at the downloader's own risk.

## ⚖️ Disclaimer

- **Purpose Limitation**:
This project is intended for **security research, packer/protector adversarial research, auditing applications you own or are authorized to test, and educational purposes** only.
Do not use this project for any illegal purposes (including but not limited to software piracy, cracking and redistributing third-party applications, or circumventing technical protection measures to infringe copyright).

- **Analyze only what you legitimately hold.**
The user is responsible for having lawful access to any sample analyzed. This project does not target any specific hardening vendor: packers may be *identified* (industry practice), but fingerprints, SOPs and processors are named by technical family — vendor names are never written, and community contributions are held to the same rule.

- **A recovery tool, not a patcher — by design and by law:**
Exuvia restores or faithfully reproduces behavior; it does not tamper. Signature self-check logic is treated like any other logic and faithfully restored — an "always-true" patch is permanently outside the feature surface. That line is also the legal boundary between research recovery and cracking.

- **Consequences Warning**:
Unpacking and repackaging may violate the terms of service of third-party software and the laws of your jurisdiction. The developer and contributors **are not responsible for any legal liabilities or other consequences** arising from such use.

- **Research Quality**:
The pipeline is research-grade and has not yet been validated against real-world packer samples; results may be incomplete (the debt list is a deliverable, not a failure). Run analysis on samples in an appropriate isolated environment.

- **No Warranty**:
This software is provided under the terms of its license, **without any express or implied warranties**, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

- **Limitation of Liability**:
To the fullest extent permitted by applicable law, **in no event shall the author or contributors be liable** for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with the use or inability to use this software, even if advised of the possibility of such damages.

- **User Responsibility**:
Users assume all legal responsibilities arising from the use of this project.

- **Final Interpretation**:
The final interpretation of this disclaimer belongs to the author of this project.

## 💬 Contact

You are welcome to submit issues, suggestions, and bug reports via GitHub Issues.

## ⭐ Support the Project

If you find this project helpful, or if you recognize its value in technical research, consider giving it a ⭐ on GitHub.

Your support helps more people discover this project, and also lets the author feel the significance of continued maintenance.

Thank you for your recognition.
