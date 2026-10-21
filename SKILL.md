# SKILL — Exuvia

Exuvia: deterministic Android unpacking + repair pipeline. Two product lines in one binary: (a) `exuvia packed.apk` → dissection handoff (L1 skeleton + debt + evidence), zero LLM tokens; (b) `exuvia repair` → one-command dump-to-runnable-APK repair (§7). §3/§4 are format DRAFT v0 (maintainer audits fields); fixtures here are the source of truth for serde types.

## 1. Actions

0. REPAIR (independent of the outsourcing loop): `exuvia repair <packed.apk> <dumped.dex> -o <out.apk> [--dump <dex>]...` — §7. Skip this loop entirely.
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
      "kind": "method-native-stub",
      "method": { "class": "com.example.LoginManager", "name": "sign", "descriptor": "(Landroid/content/Context;[B)[B" },
      "status": "blocked-solvable",
      "facts": [
        "native stub — body outside DEX (access_flags ACC_NATIVE)",
        "symbol Java_com.example.LoginManager_sign → lib/arm64-v8a/libtest.so (dynsym, st_value=0x1204, st_size=64)"
      ],
      "evidence": ["evidence/debt-0001/"],
      "attempts": 0
    },
    {
      "debt_id": "debt-0002",
      "kind": "encrypted-payload",
      "method": null,
      "status": "blocked-solvable",
      "facts": [
        "claimed-DEX file classes.dex with non-DEX magic (encrypted or renamed payload — mechanical fact)",
        "decrypt-routine candidate JNI_OnLoad → lib/arm64-v8a/libtest.so (dynsym, st_value=0x300, st_size=32) — mechanical locator",
        "init_array: 2 entries at file_offset 0x1180 in lib/arm64-v8a/libtest.so — decrypt-routine candidates, mechanical locator"
      ],
      "evidence": ["evidence/debt-0002/"],
      "attempts": 0
    }
  ]
}
```

- `kind` routes the entry shape: `method-native-stub` (method facts + so symbol slices) vs `encrypted-payload` (hidden original-code container; three mechanical sources — a claimed-DEX file whose bytes are not DEX, auto-generated for every DEX with `magic_ok=false` or `parse_ok=false`; a plaintext DEX found inside any ELF by magic scan, sliced whole as evidence; an assets-resident ELF where the scan found nothing — the shell-engine form, negative fact from absence). ELFs under `assets/` are inventoried as `so` too (ABI from e_machine), so stub symbols may hit shell libraries there. dynsym and init_array are read from PT_DYNAMIC first (the runtime view — a shell can strip the section-header table, not the dynamic segment the linker needs), with the section-header path as fallback; every ELF64 exports its defined symbol names as raw facts (no architecture filter — symbol tables are format facts). No entropy thresholds anywhere; nearby asset entropies are raw facts.
- `attempts` counts rejected proposals for this entry (merge gate increments on rejection; read it before retrying).

`workpackage.json` (output of `exuvia next --goal`; scope-gate source; CI fixture):

```json
{
  "$schema": "exuvia.workpackage",
  "goal_sha256": "sha256:…",
  "handoff_version": 1,
  "accepts_equivalent": true,
  "tracks": ["A", "B"],
  "guidance": [
    "RAW: work on the original objects themselves (apk entries, native libraries — paths appear in facts and evidence references). Slices are coordinates, not the working set.",
    "TOOLKIT: trackb/ ships with the product — disasm.py (full-arch disassembly streams, PT_DYNAMIC view survives stripped section headers), so_emulator.py (black-box execution with JNI/world semantics, --fs file bridge, --sig-file/--utf8-file feeding channels for signature-derived key chains), sigx.py (APK signing-chain certificate extractor; feeds --sig-file), sm4recon.py (GB/T 32907 SM4: CFB decrypt/encrypt, material-lattice/zlib/dex full-offset scan, textbook rkexp), crypto_recon.py (entropy / ecb / aes / rc4 / hash / dxor recon); the binary itself carries `exuvia hunt` (L2 parameter-space search: when facts establish the cipher family + key, it mechanically recovers the ciphertext segment coordinates — variant RC4 via --rc4-stride/--rc4-seed/--rc4-jbias; a hit hands you the decrypt inputs, a negative fact rules out the scanned parameter space). Tools answer your NEXT question; static artifacts only answer the designer's questions.",
    "COORDINATES: evidence slices are entry coordinates. Deep work = tools over raw objects, starting from those coordinates.",
    "RE-ANALYZE LOOP: when a claim settles and a recovered DEX lands (workspace/<debt_id>/recovered.dex), run `exuvia analyze --dex` over it — packers layer their defenses (shell → strings → methods → VMP); each settled debt reveals the next layer's debt map. The handoff map is a per-layer sequence, not a one-shot census."
  ],
  "allowed_debt": ["debt-0001"],
  "entries": [
    {
      "debt_id": "debt-0001",
      "kind": "method-native-stub",
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
- `guidance` has a fixed four-entry toolkit form (RAW / TOOLKIT / COORDINATES / RE-ANALYZE LOOP — the product's role: pre-analyzer + analyzer + toolkit), followed by fence family knowledge when matched. Family entries outrank general intuition; the fixed four describe HOW to work, not WHAT to conclude.

`evidence/<debt_id>/` (sliced bytes per debt entry; CI fixture):

```json
{
  "$schema": "exuvia.evidence",
  "debt_id": "debt-0001",
  "slices": [
    {
      "name": "lib-arm64-v8a-libtest.so--Java_com_example_LoginManager_sign",
      "source": "lib/arm64-v8a/libtest.so",
      "symbol": "Java_com_example_LoginManager_sign",
      "st_value": 4612,
      "st_size": 64,
      "file_offset": 4628,
      "slice_sha256": "sha256:…"
    }
  ]
}
```

- Each `slices[]` entry is a file `<name>.bin` beside `manifest.json` — the sliced bytes; verify `slice_sha256` before trusting them. A debt may carry several slices (multiple symbol hits, payload-head samples, decrypt-routine candidate bodies); multiple hits never overwrite each other.
- `encrypted-payload` slices carry `symbol`/`st_value`/`st_size` as `null`; `source` is the APK-internal path, `file_offset` the slice start within it. Claimed-DEX files are sliced from byte 0 (first 65536 bytes; the total size is in the facts).

- `fingerprint.matched = false` → unknown-family full exploration. Normal, not an error; it is the default while the fence defines no fingerprint.
- `dex[].magic_ok` false or `parse_ok` false → encrypted/corrupt DEX (hostile-input normal): no method facts from that file; it becomes an `encrypted-payload` debt entry automatically, so the decrypt work enters the outsourcing loop; a high-entropy asset beside it is the classic packer shape.
- `assets[].entropy` = Shannon bits/byte (0..8), a raw measurement — no thresholds applied, interpretation is yours.
- `unavailable[]` → absent external capabilities; related levels annotated, nothing fails.
- `workspace/` L1 skeleton is jadx-compatible — if structure/navigation alone answers the task, read it and stop. A `recovered` claim whose output has DEX shape is archived as `workspace/<debt_id>/recovered.dex` on merge (open it in jadx directly). Onion loop: re-run `exuvia analyze --dex workspace/<debt_id>/recovered.dex` over it — packers layer their defenses; the next layer's debt map is a new handoff, and its debts go through this same loop.
- `exuvia hunt` (L2 parameter-space search; desktop-only runtime-fact acquisition — no device/emulator anywhere in the loop): when your facts establish the cipher family AND the key (e.g. an RC4 key confirmed in read-only data), run `exuvia hunt --carrier <slice or raw object> --rc4 <hex> [--xor <hex>]`. Variant PRGA parameters (stride/seed/jbias — e.g. Battle-1's stride=2, seed=3:5, jbias=1) go via `--rc4-stride/--rc4-seed/--rc4-jbias`; they widen the scanned algorithm space, they are not vendor special-casing. It scans the full offset space under a keystream-zero-aligned model; segment length is self-decided by the mechanical chain (RFC 1950 zlib header check → inflate → DEX magic → full-table parse). A hit gives you exact ciphertext coordinates (`hunt/hits/<n>.dex` is the recovered payload) — your proposal then TRANSCRIBES the decrypt (algorithm + key + segment coordinates), no exploration left. A negative fact is honest: it rules out the scanned parameter space and points at what remains (deeper key derivation — signature-chain material via trackb/sigx.py + so_emulator.py --sig-file/--utf8-file, or variants outside the parameter space — your arena). hunt never settles debt itself; the merge gate stays the sole judge.
- debt entry = facts + difficulty signals, no cost estimates (you price tokens):
  - `status = blocked-solvable` → your arena; `out-of-scope` → spend nothing;
  - `jni_calls` high → JNI idiom lens; `vm_handlers` high → VMP, weigh out-of-scope (§6 step 2) first; `opcode_entropy` high without vm_handlers → control-flow obfuscation, tractable;
  - thresholds live in the fence (§8).
- Two output paths per debt entry, chosen by cost comparison (yours, from the facts above): `recovered` (restore original bytes) vs `equivalent` (read the L2 decompilation of the native code, write a functionally equivalent implementation). When recovery cost far exceeds equivalent-implementation cost, take the `equivalent` path — but only if `accepts_equivalent` is set in the goal (§3).
- `attempts.log`: read before attempting. A path that died twice is dead. Rejected proposals increment `attempts` on every claimed debt that exists in the handoff.

## 3. goal.json — DRAFT v0

Every field machine-decidable. Categories are named lookup tables defined in the fence (§8).

| Field | Semantics |
|---|---|
| `$schema` | literal `"exuvia.goal"` |
| `goal_version` | `1` |
| `targets[].kind` | `"method"`, `"category"` or `"payload"` |
| `targets[].class` / `.method` | exact match, names as they appear in debt.json |
| `targets[].profile` | category name defined in the fence |
| `levels.default` | `"L1"` / `"L2"` / `"L3"` |
| `tracks` | subset of `["A","B","C"]` |
| `accepts_equivalent` | bool, default `false` — if true, debt may be cleared by a `kind = "equivalent"` proposal (§4) |
| `stop` | `"targets-satisfied"` — targets cleared, a fact not a promise |

`kind = "payload"` selects every auto-generated `encrypted-payload` debt entry (claimed-DEX files whose bytes are not DEX). Semantic targeting of which file is the payload stays with the goal author; the tool only matches the mechanical fact.

Example (CI fixture):

```json
{
  "$schema": "exuvia.goal",
  "goal_version": 1,
  "targets": [
    { "kind": "method", "class": "com.example.LoginManager", "method": "sign" },
    { "kind": "category", "profile": "network-entrypoints" },
    { "kind": "payload" }
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

## 7. Repair pipeline (`exuvia repair`)

The industry gap this closes: dumpers (third-party services, FART, frida hooks) produce DEX, but nobody repairs the APK so the dumped DEX actually LAUNCHES — the shell's markers (wrapper Application in the manifest, stub dex, native loader assets, woven bytecode, frozen native stubs) are still in the APK. `exuvia repair` removes the shell's protection and rebuilds an installable, v2-signed APK in one command:

```bash
exuvia repair packed.apk dumped.dex -o restored.apk \
  [--dump third_party_dump.dex]... [--reference original_classes.dex]
```

Stages (all embedded in the binary; output JSON reports counts per stage):

| Stage | Tool | What it does |
|---|---|---|
| doctor | dexdoctor | triage & heal dump pathologies (sabotaged checksums, wiped map_off, page padding, map section anomalies P1-P11) |
| clean | dexclean | drop shell/foreign class_defs (reachability from manifest components; R8-obfuscation aware) |
| deweave | deweave | restore shell-woven bytecode in place (bridge invokes → the framework calls they replaced; probes → nops) |
| restore | dexlib2 Restore | merge method bodies for shell-extracted stubs from every source that carries them (§ sources below) |
| stubsafe | dexlib2 StubSafe | synthesize contract-equivalent bodies for lethal stubs no source could fill; final standard-layout re-serialization |
| surgery | axmltool+repair | remove `<application android:name="WRAPPER">`, strip shell asset entries, swap classes.dex |
| sign | sign2 | fresh APK v2 signature (RSASSA-PKCS1+SHA2-256) + zipalign semantics (4-byte aligned entries, resources.arsc STORED) |

**Method-body sources, in order** (shell extraction freezes methods as `native + no code_item` — the body lived in the runtime hook; once the shell is gone such a stub dies with UnsatisfiedLinkError):

- `--dump <dex>` (repeatable) — third-party dumps / earlier unpack-stage output. THE PRODUCTION PATH: a dump taken at the right moment carries decrypted bodies; several dumps are complementary (each source is tried; any source carrying a body wins).
- `--reference <dex>` — the unpacked original. INTERNAL TESTING ONLY (production has no original; same merge mechanism as `--dump`).
- no source — StubSafe fallback: `native + framework-lifecycle name` is the shell's tell (a legal native lifecycle override cannot exist — the template-method contract requires the super chain). StubSafe synthesizes the contract-equivalent minimal body (`invoke-super {pN}, Super.sameSignature` + return, ACC_NATIVE cleared). Everything else native is KEPT — a legal JNI declaration backed by a `.so` still in the APK is a necessary, side-effect-free leftover we reuse rather than re-invent.
- dex2c-translate source (trackb/jnitrace.py + trackb/trace2smali.py) — for the translate-to-JNI family (§8 family 2): the body exists as JNI C++ in the shell .so, so it IS recoverable without any dump. jnitrace runs the native function under the trackb emulator against a 233-slot fake JNIEnv and records the JNI call sequence (= the original method's behavioral skeleton); trace2smali compiles that sequence into a straight-line smali body, spliced over the hollow stub. Synthesized bodies must satisfy three ART-verifier format facts earned from a device VerifyError (2026-10-22): (a) jvalue ints print hex in traces — treat small `0x…` tokens as literals, never as addresses (an address-keyed register that no traced instruction produced is an UNDEFINED register: VerifyError `copy1 vN<-vM type=Undefined`); (b) a receiver whose traced producer type differs from the callee owner (e.g. `getDecorView():View` feeding `ViewGroup.addView`) needs `check-cast` to the owner — sound because GetMethodID succeeded at runtime; (c) 35c/22c forms carry 4-bit registers — copy operands through a low scratch band (v0..vN) with `move*/from16`, escalate to `/range` past arity 5; interface owners need `invoke-interface`.

**Known semantic boundary (honest)**: a contract-equivalent body satisfies the framework contract (installs, launches, no crash) but carries no business logic. If `onCreate` was extracted and NO source carries its body, the activity shows a blank UI — the body is simply not present in any accessible carrier (method-level lazy decryption never writes it back; 32 fulldump dexes verified zero hits on the reference corpus). Body recovery requires a source; the contract body guarantees survival.

**Runtime prerequisites** (heavy deps stay user-side, apktool-style — the repo ships source only): system `python3`; `java` + dexlib2 jars + `Restore.class`/`StubSafe.class` under `EXUVIA_DEXLIB` (default `/workspace/tools/dexlib`; `tools/dexlib/*.java` sources ship in-repo — compile with the same classpath the other tools use). Absent dexlib2 → the pipeline degrades honestly (stubsafe/repack skipped, patched dump layout kept; the run reports it).

Output JSON carries: `doctor_fixes`, `deweave_restored`, `restore_count` (bodies merged from sources), `stubsafe_count` (contract bodies synthesized), `surgery_removed`, `shell_assets_removed`, `final_size`, full `log`.

## 8. Profile fence

```toml profile
# anchor: info string "toml profile". Rust extracts + parses at startup;
# TOML syntax error = installation-broken.
# growth rules (binding): sections and fields earned from implementation need
# only (a need x3, including section names); family knowledge only after
# maintainer-validated research, vendor names forbidden (technical-family
# naming); knowledge/value additions = minor, methodology/format = major
# (human confirmation). current state: first family entry earned from
# Battle 1 (maintainer-confirmed 2026-10-20).

# 族知识 1：整块加密-压缩载体族（第一战实测毕业，维护者确认入档；
# 2026-10 桌面化修订：维护者拍板摒弃真机/模拟器，剧本改写为桌面三步）。
# 形态：密文载体（dex 尾部 / so 内嵌段）经壳自有流密码解密器解出
# zlib 压缩流，inflate 后为完整原始 DEX（非方法抽取——repack 无需 DEX writer）。
# 卡点重判：原判定"调用现场（真实密文指针/长度）为纯运行时事实"——算法与
# key 已知时实为机械可搜的有限空间（exuvia hunt）；变体算法仍归外循环。
[families.wholefile-encrypt]
description = "whole-file encrypt+compress carrier: ciphertext container -> shell stream-cipher decrypt -> zlib inflate -> intact original DEX; call-site parameters are a mechanically searchable space once algorithm+key are known (desktop re-verdict 2026-10, maintainer-approved)"
guidance = [
    "static recovery fully solves algorithm/key/containers; the call-site binding was long deemed runtime-only — desktop re-verdict: with algorithm+key known, segment parameters are a mechanically searchable finite space, not a device-only fact",
    "desktop recipe, in order: (1) `exuvia hunt --carrier <container> --rc4 <key>` — keystream-zero-aligned full-space scan, the chain self-decides length (zlib stream boundary / DEX file_size); a hit hands you exact segment coordinates; (2) no hit = honest negative ruling out the standard zero-aligned model — variant ahead: reproduce it in the proposal, or black-box the routine via trackb/so_emulator.py; (3) unicorn-stub interception of the inflate boundary (inflateInit_/inflate via DT_NEEDED) stays the fallback yielding both artifacts (ciphertext stream + original DEX) — same interception logic, desktop execution, no device/emulator anywhere",
    "return flow: a hunt hit (or interception pair) transcribes into a pure-function decrypt proposal — no exploration left; recovered claims verify via structural assertions (DEX parse) x byte tests; the repacked APK then needs only the assembler + user-side zipalign/apksigner (no DEX writer for this family)",
    "L2 evidence: attach disassembly streams next to the byte slices (trackb/disasm.py --symbol, capstone user-side) — Battle-1 proved expectation-chasing and routine-reading need instruction streams as first-class artifacts; PT_DYNAMIC runtime view resolves shell symbols that static views miss",
]

# 族知识 2：dex2c 翻译族（第二战实测毕业，维护者真机确认 2026-10-21/22）。
# 形态：方法体被翻译为 JNI C++（常加 OLLVM 控制流平坦化），原 Dalvik 字节码
# 不在包内任何载体（明文/单字节 XOR/操作数掩码骨架/内嵌 dex 全部证伪）；
# 壳 classes.dex 尾部挂 AES-128-CBC 容器（密钥/IV 在 .so rodata，机械可搜），
# 子容器首 0x70 字节 XOR 单字节密钥。
# 卡点重判：原判定"无 dump 不可恢复"——JNI 语义即行为骨架，模拟执行原生
# 函数记录 JNI 调用序列即可重建直线 smali 体，全程桌面、无 dump、无参照。
[families.dex2c-translate]
description = "method bodies translated to (often OLLVM-flattened) JNI C++; original Dalvik absent from the package; shell tail container AES-128-CBC + XOR-prefix sub-containers; recovery = JNI-semantics trace -> smali synthesis, desktop-only, no dump, no reference"
guidance = [
    "prove absence before recovering: plaintext/XOR/skeleton/embedded-dex searches with a sha1+adler self-check oracle must ALL fail — only then is translate-to-JNI the confirmed shape (extraction and translation need opposite pipelines)",
    "desktop recipe, in order: (1) dexcontainer.py rebuilds every dex from the tail container (profile-driven, per-dex sha1+adler oracle — cannot false-positive); (2) locate the JNINativeMethod-like table in the .so (name/sig/fn triples) for the native-ized methods; (3) jnitrace.py per function — fake JNIEnv, token world, numeric Call results return 0 to select the cold-start path, field reads keep unique sentinels for dataflow linking; (4) trace2smali.py compiles traces to smali (ART-verifier rules: hex jvalues are literals, check-cast on receiver-type mismatch, low scratch band vs 4-bit register forms, invoke-interface for interface owners); (5) splice over hollow stubs, assemble, repack, v2-sign",
    "honest boundaries: straight-line bodies only (single-path trace); runtime-built strings needing device state surface as const-string \"\" placeholders flagged in the report; the cold-path convention fixes which branch a repaired fresh launch takes",
    "cross-validation when a baseline exists (internal calibration only): synthesized sequences matched the baseline nearly 1:1 including exact constants",
]
```

## 9. Version anchors

```text
SKILL_VERSION: 1.4.0
handoff_version: 1    goal_version: 1    proposal_version: 1
```

- File version = methodology + §8 fence snapshot. Format changes start in fixtures, serde types follow, CI binds both directions.
- 1.3.0: §7 repair-pipeline documentation added (product line b: `exuvia repair`); no protocol change.
- 1.4.0: §7 fourth method-body source (JNI-trace → smali synthesis) + §8 family 2 dex2c-translate entered (Battle-2 maintainer device-confirmed); no protocol change.
- Before adapting to a new environment, compare `exuvia --version` against these.
