# SKILL — Exuvia

Exuvia: deterministic Android unpacking + repair pipeline. Two product lines in one binary: (a) `exuvia packed.apk` → dissection handoff (L1 skeleton + debt + evidence), zero LLM tokens; (b) `exuvia repair` → one-command dump-to-runnable-APK repair (§7). Extraction doctrine is dual-engine (§9): the static engine keeps reconnaissance and repair; the dynamic engine — a standalone collector binary, never part of this one — does shell-agnostic runtime extraction, coupled to exuvia only by versioned contracts (§10). §3/§4/§10 are format DRAFT v0 (maintainer audits fields); fixtures here are the source of truth for serde types.

## 1. Actions

0. REPAIR (independent of the outsourcing loop): `exuvia repair <packed.apk> [dumped.dex]... -o <out.apk> [--dump <dex>]... [--extra-dex <dex>]... [--from-handoff]` — §7. Skip this loop entirely. `--from-handoff` is the loop's EXIT: gate products feed repair directly.
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
    "TOOLKIT: trackb/ ships with the product — disasm.py (full-arch disassembly streams, PT_DYNAMIC view survives stripped section headers), so_emulator.py (black-box execution with JNI/world semantics, --fs file bridge, --sig-file/--utf8-file feeding channels for signature-derived key chains, emutls contract emulation materializing TLS-built strings offline), sigx.py (APK signing-chain certificate extractor; feeds --sig-file), sm4recon.py (GB/T 32907 SM4: CFB decrypt/encrypt, material-lattice/zlib/dex full-offset scan, textbook rkexp), crypto_recon.py (entropy / ecb / aes / rc4 / hash / dxor recon), elfrecon.py (embedded-ELF recovery), dexcontainer.py (profile-driven tail-container dex rebuild, per-dex sha1+adler oracle), jnitrace.py (JNI-semantics tracer on the emulator world: --init runtime warm-up, --seed-dex clinit static-field seeding, --arms null-guard dual-arm enumeration), trace2smali.py (trace-to-smali synthesis, --sigs-dex descriptor import from hollow stubs), fidelity.py (dump-vs-reference fidelity report); the binary itself carries `exuvia hunt` (L2 parameter-space search: when facts establish the cipher family + key, it mechanically recovers the ciphertext segment coordinates — variant RC4 via --rc4-stride/--rc4-seed/--rc4-jbias, AES-128-CBC tail containers via --aes-cbc/--aes-iv (trailer anchor, header-block length scan-verified, sub-containers walked); a hit hands you the decrypt inputs, a negative fact rules out the scanned parameter space). Tools answer your NEXT question; static artifacts only answer the designer's questions.",
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
- `exuvia hunt` block-chaining arm (aes-128-cbc-tail predicate, profile aes128cbc-tail-v1 — Battle-2 earned family knowledge): when facts establish the tail-container layout AND the 16-byte key/IV (typically shell .so rodata), run `exuvia hunt --carrier <classes.dex> --aes-cbc <key hex|ascii16> --aes-iv <iv hex|ascii16> [--aes-xor-prefix 0x70 --aes-xor-key 0x66]`. The chain is fully self-deciding: the trailer's last-4-byte big-endian value IS the container start (full-range anchor scan as fallback for sliced carriers); the header-block length is scan-verified (PKCS#7 validity → fragment consistency → dex::parse final verdict, family default 0x210 tried first); sub-containers are walked by their length prefixes (payload magic raw first, then XOR-prefix strip with the family defaults). Hits cover dex#1 AND every embedded sub-dex — byte-identical to trackb/dexcontainer.py's rebuild (Rust/Python dual implementation, per-dex sha1+adler oracle on the Python side, dex::parse on the Rust side). The debt that feeds this arm is mechanical: a parse-healthy classes*.dex whose declared file_size exceeds its data-section end (data_off+data_size) by ≥0x70 books an encrypted-payload debt with the tail's head sliced as the carrier coordinate — both battle families share this shape.
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
exuvia repair packed.apk [dumped.dex]... -o restored.apk \
  [--dump third_party_dump.dex]... [--extra-dex gate_product.dex]... \
  [--reference original_classes.dex] [--from-handoff] [--allow-hollow]
```

**Ship channels — three dex roles, not interchangeable** (choosing wrong silently drops code from the output APK): the positional `dumped.dex` is triaged (doctor → clean → deweave) and repacked as `classes.dex`; `--dump <dex>` is a restore SOURCE ONLY — read for method bodies, never ships; `--extra-dex <dex>` (repeatable, order preserved) ships AS-IS as `classes2.dex..classesN.dex` with NO re-serialization — the channel for unpack-stage gate products (e.g. a merge-gate-passed `recovered.dex` / hunt hit) and any complete healthy dex that must reach the output byte-exact. A whole dex that only carries classes absent from the positional dump (the dex2c family's tail-container sub-dex is the case on record: sole `MainActivity` carrier) ships via `--extra-dex`; routing it to `--dump` produces an APK that installs but cannot launch.

**Source channel — `--from-handoff`** (closes the unpack→repair loop, no manual file plumbing): collects every merge-gate product `handoff/workspace/*/recovered.dex` (presence there means the four-layer gate passed, §5) straight into the ship channels. Rules, in order: sha256-dedup against the explicit channels — a gate product already given as positional or `--extra-dex` never ships twice; explicit positionals present → every collected dex appends to `--extra-dex` in debt_id order (gate products ship as-is, never re-triaged); no explicit positional → the LARGEST collected dex promotes to the positional (doctor triage, repacked as classes.dex — the main-dex heuristic: the dex carrying the app's entry classes dwarfs the sub-dexes) and the rest append to `--extra-dex`; no positional AND nothing collected → structured error naming both channels. The one-command form: `exuvia repair packed.apk --from-handoff -o restored.apk` — gate products to a signed APK.

**Completeness precondition (device-earned, tosks 2026-10-22)**: whatever ships must be BODY-COMPLETE for every class the runtime touches. A raw container-recovered dex whose methods are still `native` hollow stubs is NOT shippable as-is — after surgery the shell runtime (`StubApp` + `assets/lib*.so` carrying the translated JNI bodies) is gone, and ART dies with `UnsatisfiedLinkError` on the first lifecycle call. Family-2 translated classes must first pass through the dex2c source (jnitrace → trace2smali synthesis, below); only the synthesized, all-Dalvik dex goes to `--extra-dex`. Container recovery hands you the class/method skeleton and the untranslated classes — the translated bodies come from the trace, never from the container.

**Hollow auto-fill (the precondition's machine execution)**: repair enforces the precondition itself — every ship-channel dex is scanned, and a `native` method whose name sits in StubSafe's framework-lifecycle table marks the dex as a hollow-stub carrier (the family-2 shape: a legal native lifecycle override cannot exist — the template-method contract requires the super chain). Unless `--allow-hollow` (escape hatch for triage/debug — the stub ships and dies on the first lifecycle call), repair picks the shell .so from the packed APK (`assets/*.so`, ELF64 AArch64, largest — `lib/` carries the app's legal JNI and is never selected) and runs the embedded four-step fill (hollowfill.py: static JNINativeMethod-table locate → jnitrace → trace2smali → baksmali/splice/smali reassembly), seeding jnitrace with the other ship dexes (`--seed-dex`); the filled dex replaces the hollow one in its channel, order preserved. The fill set is ALL native methods of the dex — the family translates whole classes, and filling only lifecycle names leaves the next crash point. Missing deps (unicorn / dexlib2) or a locate failure = a structured error naming every suspect method — never a silent hollow ship. Output JSON gains `hollow_filled`.

Stages (all embedded in the binary; output JSON reports counts per stage):

| Stage | Tool | What it does |
|---|---|---|
| doctor | dexdoctor | triage & heal dump pathologies (sabotaged checksums, wiped map_off, page padding, map section anomalies P0–P11) |
| clean | dexclean | drop shell/foreign class_defs (reachability from manifest components; R8-obfuscation aware) |
| deweave | deweave | restore shell-woven bytecode in place (bridge invokes → the framework calls they replaced; probes → nops) |
| restore | dexlib2 Restore | merge method bodies for shell-extracted stubs (native+no-code), nop-wall bodies (extraction+nop-fill family) and pure forwarding shells (the family's gutted-callback shape: exactly one invoke + one return, optional move-result plumbing) from every source that carries them (§ sources below); donor admissibility is by INFORMATION, not shape (finding #11): a nop-wall source body never donates (wall over wall restores nothing), an instruction-identical source body is skipped (grafting it would only fake the count), and a source body whose references dangle against the shippable-class universe + boot classpath is rejected (a packer bridge call must never be imported — better an honest wall than a NoSuchMethodError); shell-SHAPED one-line delegates DO donate — a wall target is already proof of extraction |
| stubsafe | dexlib2 StubSafe | synthesize contract-equivalent bodies for lethal stubs no source could fill (native lifecycle stubs; nop-wall lifecycle bodies on framework-carrier classes; nop-wall CONSTRUCTORS — a wall `<init>` never verifies: "Constructor returning without calling superclass constructor" is a load-time VerifyError shell-free, so the minimal legal `this()/super()` + `return-void` body is synthesized); final standard-layout re-serialization |
| surgery | axmltool+repair | remove `<application android:name="WRAPPER">`, strip shell asset entries, swap classes.dex |
| sign | sign2 | fresh APK v2 signature (RSASSA-PKCS1+SHA2-256) + zipalign semantics (4-byte aligned entries, resources.arsc STORED) |

**Method-body sources, in order** (shell extraction freezes methods as `native + no code_item` — the body lived in the runtime hook; once the shell is gone such a stub dies with UnsatisfiedLinkError):

- `--dump <dex>` (repeatable) — third-party dumps / earlier unpack-stage output. THE PRODUCTION PATH: a dump taken at the right moment carries decrypted bodies; several dumps are complementary (each source is tried; any source carrying a body wins).
- `--reference <dex>` — the unpacked original. INTERNAL TESTING ONLY (production has no original; same merge mechanism as `--dump`).
- no source — StubSafe fallback: `native + framework-lifecycle name` is the shell's tell (a legal native lifecycle override cannot exist — the template-method contract requires the super chain). The extraction+nop-fill family (爱加密-style) leaves the twin tell: a LEGAL code_item whose body is a zero wall (instructions exclusively nops / zero-literal consts / returns, ≥1 return — nop padding NOT required, finding #12: a getter-sized carve is a bare zero-return stub with no nop at all; a genuine zero-shaped body is donor-decidable — identical-skip keeps it byte-exact — and donorless it verifies and stays). A residual try table does not disqualify, this family guts handler code to nops too. StubSafe synthesizes the contract-equivalent minimal body (`invoke-super {pN}, Super.sameSignature` + return, ACC_NATIVE cleared) for native lifecycle stubs AND for nop-wall lifecycle bodies on framework-carrier classes (the superclass chain must reach an external non-`Object` ancestor — a lifecycle NAME on a POJO is not the tell, and delegating there would reference a nonexistent super). Everything else native is KEPT — a legal JNI declaration backed by a `.so` still in the APK is a necessary, side-effect-free leftover we reuse rather than re-invent; non-lifecycle nop walls are likewise kept — with ONE exception: the nop-wall constructor. A wall `<init>` returns without calling any this/super constructor, which the ART verifier rejects outright ("[0x0] Constructor returning without calling superclass constructor") — in the packed app the wall is invisible (the shell re-materializes the body before class load, so verification only ever sees the real body), but shell-free it is a load-time VerifyError landmine, and dexopt's rejection cascades to every subclass. StubSafe synthesizes the minimal legal body for it (`invoke-direct {p0, dummy...}` + `return-void`): prefer a REAL sibling ctor (this-call reuses the original init sequence), else the cheapest accessible ctor found by walking the direct-superclass chain (the ref always names the DIRECT super — resolution walks up on its own; an in-dex super that declares no ctor is legal, Object terminates every chain; a level whose ctors are all too wide for the register plan does not end the search), else the cheapest dex-wide invoke-site reference to an external super's `<init>` (signature proven to exist on-device), else an assumed no-arg super call logged loudly as `ctor-stub-assumed-noarg` (always right for system-instantiated component classes; never worse than the wall it replaces). Dummies are zero/null consts; registers: 35c with fresh locals when ≤5 words, else 3rc over p0..p0+k overwriting the stub's own unused params. Other kept walls verify as no-ops — only a body-carrying source truly refills them (the coverage-debt loop, covdebt/fart_plan/fart_sweep, is exactly that source factory; covdebt counts synthesized ctor stubs in a separate `ctor_stub` bucket so they exit the debt list without inflating `real`).
- dex2c-translate source (trackb/jnitrace.py + trackb/trace2smali.py) — for the translate-to-JNI family (§8 family 2): the body exists as JNI C++ in the shell .so, so it IS recoverable without any dump. jnitrace runs the native function under the trackb emulator against a fake JNIEnv and records the JNI call sequence (= the original method's behavioral skeleton); trace2smali compiles that sequence into a straight-line smali body, spliced over the hollow stub. Operator knowledge is automated: `--init` warms the runtime first (DT_INIT_ARRAY + JNI_OnLoad — runtime-built strings/globals); `--seed-dex` scans any dump for `<clinit>` sput-object targets and pre-seeds those static object fields non-null (the device truth for such fields, derivable from any dump); `--arms`/`--arms-max` enumerate null-guard points on fake tokens (CBZ/CBNZ — JNI results that are environment-state-dependent on device) and write one extra trace per guard with that producer forced null (single-flip v1: guards discovered only on a flipped arm are not recursively enumerated); TLS-built strings materialize offline via the emulator's emutls contract emulation (`__emutls_get_address`/`__cxa_thread_atexit`); trace2smali `--sigs-dex` imports native-method descriptors straight from the hollow-stub dex (translated methods keep their original protos). Synthesized bodies must satisfy three ART-verifier format facts earned from a device VerifyError (2026-10-22): (a) jvalue ints print hex in traces — treat small `0x…` tokens as literals, never as addresses (an address-keyed register that no traced instruction produced is an UNDEFINED register: VerifyError `copy1 vN<-vM type=Undefined`); (b) a receiver whose traced producer type differs from the callee owner (e.g. `getDecorView():View` feeding `ViewGroup.addView`) needs `check-cast` to the owner — sound because GetMethodID succeeded at runtime; (c) 35c/22c forms carry 4-bit registers — copy operands through a low scratch band (v0..vN) with `move*/from16`, escalate to `/range` past arity 5; interface owners need `invoke-interface`.

**Known semantic boundary (honest)**: a contract-equivalent body satisfies the framework contract (installs, launches, no crash) but carries no business logic. If `onCreate` was extracted and NO source carries its body, the activity shows a blank UI — the body is simply not present in any accessible carrier (method-level lazy decryption never writes it back; 32 fulldump dexes verified zero hits on the reference corpus). Body recovery requires a source; the contract body guarantees survival. For the dex2c source the boundary is different: bodies are straight-line modulo `--arms` dual-arm enumeration, and runtime strings depending on live device state surface as `const-string ""` placeholders flagged in the report (TLS-encoded ones materialize offline).

**Runtime prerequisites** (heavy deps stay user-side, apktool-style — the repo ships source only): system `python3`; `java` + dexlib2 jars + `Restore.class`/`StubSafe.class`/`DonorMerge.class` under `EXUVIA_DEXLIB` (default `/workspace/tools/dexlib`; `tools/dexlib/*.java` sources ship in-repo — compile with the same classpath the other tools use). Absent dexlib2 → the pipeline degrades honestly (stubsafe/repack skipped, patched dump layout kept; the run reports it).

Output JSON carries: `doctor_fixes`, `deweave_restored`, `restore_count` (bodies merged from sources), `stubsafe_count` (contract bodies synthesized), `surgery_removed`, `shell_assets_removed`, `hollow_filled` (auto-fill records, one per filled dex), `final_size`, full `log`.

**Acceptance gate (user-side, trackb/verify_all.py — ALL GREEN before any device confirmation)**: V1 zip layer (integrity, 4-byte alignment, resources.arsc STORED) → V2 dexdoctor pathology audit P0–P11 CLEAN → V3 dexlib2 strict full decode → V4 content residue zero (woven invokes restored, components self-contained; multi-dex union — manifest components may live in classes2.dex..classesN.dex) → V5 apksigtool full v2 verification. Repair once, verify locally in full; the device is only the final confirmation, never the debugger.

**Coverage-debt loop (the extraction family's lazy restoration, closed)**: after restore, every remaining nop wall is COVERAGE DEBT — the dump session never executed that method, so no donor could carry its body (family-3 truth: the packer re-materializes a body only at execution time, and materialization precedes the first instruction — so a forced invocation with dummy args plus swallowed exceptions suffices; the call must only START, never succeed). trackb/covdebt.py turns the repaired product dex into a structured debt JSON (class/name/proto/access/kind per wall; the pure-Python wall predicate is Restore.isNopWall semantics-for-semantics, calibrated to dexlib2 counts on the family-3 sample); trackb/fart_plan.py compiles debt into a FART-style invocation plan (static → reflect on a null receiver; instance → `Unsafe.allocateInstance` receiver, no ctor side effects, no no-arg ctor required; `<init>` → construct through that very constructor; `<clinit>` → `Class.forName(name, true, loader)`; abstract classes honestly skipped; hot walls — debt reachable from real code, direct invoke reference or virtual-override dispatch (finding #13) — sort first, manifest components next); trackb/fart_sweep.{js,py} is the device arm — a thin Frida executor that reflection-invokes every entry swallowing ALL exceptions (an NPE inside the target is a success: it proves real code ran), plus the adb runner emitting sweep_report.json. Re-dump after the sweep and feed the new dumps via `--dump` — the wall count shrinks measurably every round (multi-donor restore chains work since 1.10.3). A sweep round produces THOUSANDS of per-dump dexes (one restore pass each would be hours): collapse them first with `DonorMerge merged.dex <dump-dir>` (parallel scan, first donor wins on conflict, walls never survive the merge, shell-shaped genuine delegates survive — Restore's universe gate handles bridge impostors at graft time), then a single `--dump merged.dex` restores everything in one pass. The device half is maintainer-run; the offline half is anchored in selftest (synthetic dex walk + predicate cases + plan actions/tiering).

## 8. Profile fence

```toml profile
# anchor: info string "toml profile". Rust extracts + parses at startup;
# TOML syntax error = installation-broken.
# growth rules (binding): sections and fields earned from implementation need
# only (a need x3, including section names); family knowledge only after
# maintainer-validated research, vendor names forbidden (technical-family
# naming); knowledge/value additions = minor, methodology/format = major
# (human confirmation). current state: two family entries on record —
# Battle 1 (maintainer-confirmed 2026-10-20), Battle 2 (device-confirmed
# 2026-10-21/22).

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
    "desktop recipe, in order: (1) rebuild every dex from the tail container — binary-side: `exuvia hunt --carrier classes.dex --aes-cbc <key> --aes-iv <iv>` (trailer-anchored, header-block length and sub-containers self-decided, dex#1 + sub-dex hits); Python-side dual: trackb/dexcontainer.py (profile-driven, per-dex sha1+adler oracle — cannot false-positive); the two are byte-identical dual implementations of aes128cbc-tail-v1, and the booking debt is mechanical (file_size vs data-section-end gap ≥0x70 on a parse-healthy classes*.dex); (2) signatures come from the hollow stubs themselves — trace2smali --sigs-dex imports native-method descriptors (translated methods keep their original protos; the JNINativeMethod-like name/sig/fn table in the .so stays the fallback locator); (3) jnitrace.py per function — fake JNIEnv, token world, numeric Call results return 0 to select the cold-start path, field reads keep unique sentinels for dataflow linking; automation: --init runs DT_INIT_ARRAY + JNI_OnLoad first, --seed-dex pre-seeds clinit-initialized static object fields non-null from any dump (the device truth for such fields), --arms/--arms-max enumerates null-guard forks one flipped trace per guard, TLS-built strings materialize offline via emutls contract emulation; (4) trace2smali.py compiles traces to smali (ART-verifier rules: hex jvalues are literals, check-cast on receiver-type mismatch, low scratch band vs 4-bit register forms, invoke-interface for interface owners); (5) splice over hollow stubs, assemble, repack, v2-sign; acceptance = verify_all.py V1-V5 (V4 audits the multi-dex union — components may live in classes2..N)",
    "honest boundaries: straight-line bodies modulo --arms dual-arm enumeration (single-flip v1 — guards found only on a flipped arm are not recursively enumerated; --arms exports each alternative arm as an extra trace); runtime strings needing live device state surface as const-string \"\" placeholders flagged in the report (TLS-encoded ones materialize offline); the cold-path convention fixes which branch a repaired fresh launch takes",
    "cross-validation when a baseline exists (internal calibration only): synthesized sequences matched the baseline nearly 1:1 including exact constants",
]
```

## 9. Dynamic extraction doctrine（动态脱壳理念）

2026-10-24 maintainer 拍板：exuvia 从纯静态扩展为**双引擎**。静态引擎是重资产——每壳都付 token 税（KDF、容器格式、加载链逐壳逆向）；它降级为**侦察 + 修复**：家族分类、工单生成、env-gate 情报，以及两引擎共享的 DonorMerge / `exuvia repair`。动态引擎是轻资产、壳家族无关：壳再硬，最终必须把合法 dex 交给 ART——族 3 实证：爱加密运行时 rodata 含 `openInMemoryDexFilesNative` / `openDexFileNative` / `dvmRawDexFileOpenArray` / 四重载 `ClassLinker::VerifyClassUsingOatFile`——挂住 ART 标准入口即挂住所有壳；且真机环境天然通过全部 env-gate，静态侧的门答案推导问题在动态线整体消失。

**采集器六铁律**（maintainer 原话决定，违反即设计错误）：

1. root 是硬前提——无 root 即不可用，样本应交有 root 的操作者采集；
2. 不重签名——目标默认带强签名校验，重打包路线否决；
3. 采集器是**独立二进制**（独立发行物、独立版本号），exuvia 仅产出它的参数（采集工单 JSON）——两物的唯一耦合是版本化契约（采集工单 / manifest / 工件卫生三件套）；
4. 自包含运行环境（frida 等）；不得不落盘的目录与文件名一律随机（随机长度 + 随机字符），或放应用层无权访问处；
5. 无 adb——用户手动安装、手动回传采集结果；
6. 非 APK——包名注册表项即 IOC；形态 = 裸静态 ELF（Termux + su 执行）。

**隐身分级（tell-surface 思维）**：L0 纯用户态（随机工件 + 环回 + 错过 init 窗口 attach）→ L1 用户态强化（去 TCP、注入即分离、GOT/PLT-only 挂钩）→ L2 内核辅助。定律：进程内扫描者对进程内 agent 有主场优势（每条用户态隐藏手段本身就是新痕迹），耐久隐身必须比观察者高一个权限层级——观察者在用户态，故 L2 = 内核。反不对称约束升级节奏：采集是**一次性**（拿到字节即赢，所需隐身时长秒级），外挂是持续对抗（月级）——故 L0 先行，L2 是保险不是地基。内核侧纪律：zero-sample 延伸到内核——KPM 只做壳无关原语（/proc 过滤、跨进程内存读写、进程隐藏），一切壳特征逻辑留在用户态。

**L2 参考实现已入库**：ditPro KPM 1.4.2（mumulin；读写覆盖内核 4.4–6.12，内置 BTF 解析器自适配结构偏移，故长期免更新）。接口已逆向存档：钩 `lookup_dcookie`(18) / `quotactl`(60) 两个死 syscall，`"nomi"` 握手 + 指纹令牌；命令集 = 按 pid 物理内存读（单点/批量）/写、进程隐藏/解除、按名查 pid、模块基址查询（输入事件隐藏与采集无关）。红利：被动采集（加载期整 dex 解密族）可无 frida 全内核侧完成——目标进程零痕迹。缺口：目标进程自身 maps 视图过滤它不管——靠 agent 随机化缓解，远期以自研零逻辑 KPM 补齐（ditPro 即 ABI 参考）。集成面冻结为 kpm_client 四动词：`probe`（nomi 握手 + 版本）/ `protect`（注册保护：pid + 区域 + 通道）/ `release`（注销）/ `status`（回读实际生效通道，写入 manifest）；工单要求 L2 而握手失败 = 大声拒绝运行——静默降级 = 裸奔，比不采更糟。

## 10. Collector contracts — DRAFT v0（采集契约三件套）

三个版本化协议物是 exuvia 与采集器之间的**唯一耦合面**（§9 铁律 3：独立二进制、独立发行、独立版本号）。流向：exuvia 静态侦察产出**采集工单**（10.1）→ 采集器执行后回传 **manifest**（10.2）+ 工件（tar.gz）；**工件卫生目录**（10.3）是双方共享的 tell-surface 基准——工单按它声明策略与版本对齐，manifest 按它登记残余。机器字段只用技术族名（§8 围栏规则延伸到采集线：厂商名永不出现在本节任何字段）。转正条件：首个采集器版本完成 passive + active 双回路真机验证。生成/解析接线随采集器 epic 落地；本节先立格式，fixture 即锚定。

**10.1 workorder.json（exuvia → 采集器）**

| Field | Semantics |
|---|---|
| `$schema` | literal `"exuvia.collector.workorder"` |
| `workorder_version` | `1` |
| `order_id` | opaque string；manifest 原样回显（建议取工单正文 sha256 派生） |
| `target.package` | 已安装加壳包名 |
| `target.apk_sha256` | exuvia 分析对象锚——采集器动作前必须核对已安装应用，不符 = 大声拒绝 |
| `target.launch_activity` | nullable；null = 操作者手动启动（铁律 5 无 adb） |
| `family.id` | §8 技术族 id（如 `family-3-extract-nop`）；未知 = `"unknown"` |
| `family.evidence` | 分类依据事实串（如 rodata 符号命中），无判断 |
| `extraction.mode` | `"passive"`（加载期整 dex 解密族，零进程内触发）/ `"active"`（FART 式方法触发） |
| `extraction.art_anchors` | 要挂的 ART 标准入口符号（§9 教义集）——只挂 ART，永不挂壳符号 |
| `extraction.seed_plan` | nullable，active 模式专用：`file`+`sha256` 引用 fart_plan 产物文件（与工单同包交付），`hot_first` = 热层先行（§7 fart_plan hot 层） |
| `env_gates[]` | 环境检查投喂表：`gate` 检查点标识 / `expected` 真机期望值 / `evidence` 侦察依据引用；采集器 preflight 记录用，不做强制 |
| `stealth.tier` | `"L0"`/`"L1"`/`"L2"` 最低档；可超档执行，禁止静默降档 |
| `stealth.kpm` | nullable，L2 必填；`required` 为 true 时握手失败 = 大声拒绝运行（§9 冻结面）；`channels` ⊆ `["phys_read","phys_write","hide_proc"]` |
| `hygiene.hygiene_version` | 生单时对齐的卫生目录版本（10.3） |
| `hygiene.random_artifacts` / `.no_tcp` / `.one_shot` | 铁律 4 与隐身教义落下的布尔策略约束 |
| `deliverables` | subset of `["dex","runtime-log","maps"]` |
| `result_channel.method` | `"manual-transfer"`（铁律 5） |
| `result_channel.archive` | `"tar.gz"`——二进制转储唯一传输形态 |

Example (CI fixture):

```json
{
  "$schema": "exuvia.collector.workorder",
  "workorder_version": 1,
  "order_id": "wo-20261024-001",
  "target": {
    "package": "com.example.app",
    "apk_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "launch_activity": null
  },
  "family": {
    "id": "family-3-extract-nop",
    "evidence": [
      "rodata: openInMemoryDexFilesNative present in shell runtime",
      "rodata: dvmRawDexFileOpenArray present in shell runtime",
      "assets: encrypted container with declared-length header"
    ]
  },
  "extraction": {
    "mode": "passive",
    "art_anchors": ["openInMemoryDexFilesNative", "openDexFileNative", "dvmRawDexFileOpenArray"],
    "seed_plan": null
  },
  "env_gates": [
    { "gate": "ro.debuggable", "expected": "0", "evidence": "recon: shell reads build props during init" }
  ],
  "stealth": {
    "tier": "L2",
    "kpm": { "required": true, "min_version": "1.4.2", "channels": ["phys_read", "hide_proc"] }
  },
  "hygiene": { "hygiene_version": 1, "random_artifacts": true, "no_tcp": true, "one_shot": true },
  "deliverables": ["dex", "runtime-log"],
  "result_channel": { "method": "manual-transfer", "archive": "tar.gz" }
}
```

**10.2 manifest.json（采集器 → exuvia）**

| Field | Semantics |
|---|---|
| `$schema` | literal `"exuvia.collector.manifest"` |
| `manifest_version` | `1` |
| `order_id` / `workorder_sha256` | 工单回显 + 所消费工单字节的 sha256 锚 |
| `collector.name` / `.version` | 采集器身份与独立版本号（铁律 3） |
| `device.abi` / `.android_release` / `.kernel` / `.root` | 运行事实；`root` 例：`"ksu-lkm"` / `"ksu"` / `"magisk"` |
| `stealth_tier_used` | 实际执行档（≥ 工单要求） |
| `kpm` | null 或 status 回读：`handshake` + `channels_used` = 实际生效通道（不是请求值，§9 status 动词落点） |
| `anchors_hit` | 实际命中的 ART 锚点——提取路径执行过的证据 |
| `env_gates[].gate` / `.passed` | preflight 观察结果 |
| `artifacts[]` | `{ name, kind, sha256, size_bytes }`；`kind` ∈ deliverables 集合 |
| `errors[]` | `{ code, detail }` |
| `residuals_accepted` | 本次运行适用的卫生目录通道 id（10.3 引用键） |

Example (CI fixture):

```json
{
  "$schema": "exuvia.collector.manifest",
  "manifest_version": 1,
  "order_id": "wo-20261024-001",
  "workorder_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "collector": { "name": "exuvia-collector", "version": "0.1.0" },
  "device": { "abi": "arm64-v8a", "android_release": "15", "kernel": "5.15.167", "root": "ksu-lkm" },
  "stealth_tier_used": "L2",
  "kpm": { "name": "ditpro-kpm-read/write", "version": "1.4.2", "handshake": true, "channels_used": ["phys_read", "hide_proc"] },
  "anchors_hit": ["openInMemoryDexFilesNative"],
  "env_gates": [{ "gate": "ro.debuggable", "passed": true }],
  "artifacts": [
    { "name": "classes_0xd0000000.dex", "kind": "dex", "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size_bytes": 4194304 },
    { "name": "collector.log", "kind": "runtime-log", "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size_bytes": 4096 }
  ],
  "errors": [],
  "residuals_accepted": ["kernel-hook-residual", "proc-visibility"]
}
```

**10.3 hygiene.json（工件卫生目录，双向基准）**

tell-surface 思维（§9）：一行 = 一个可观察面 = surface（能被看到什么）× observer（谁在看）× L0–L2 缓解 × residual（做满仍剩什么）× 裁定。工单按 `hygiene_version` 对齐目录版本，manifest 按通道 id 登记残余；改目录 = 协议变更，走版本升版。定律不变：进程内扫描者对进程内 agent 有主场优势，耐久隐身必须比观察者高一个权限层级。

| Field | Semantics |
|---|---|
| `$schema` | literal `"exuvia.collector.hygiene"` |
| `hygiene_version` | `1` |
| `channels[].id` | 通道标识（kebab-case，manifest.residuals_accepted 的引用键） |
| `channels[].surface` / `.observer` | 可观察内容 / 观察者位置 |
| `channels[].l0` / `.l1` / `.l2` | 各隐身档缓解手段（不适用 = `"n/a"`） |
| `channels[].residual` | 做满缓解后的残余痕迹 |
| `channels[].residual_accepted` / `.decision` | 残余是否已裁定；裁定原文 + 日期（无 = null） |

Example (CI fixture)——即当前目录全量内容：

```json
{
  "$schema": "exuvia.collector.hygiene",
  "hygiene_version": 1,
  "channels": [
    {
      "id": "fs-artifacts",
      "surface": "释放到文件系统的运行组件（采集器本体、frida-server/gadget、临时目录与文件名）",
      "observer": "in-process scanner + app-layer filesystem view",
      "l0": "目录与文件名随机（随机长度 + 随机字符），或放应用层无权限路径",
      "l1": "memfd 内存文件执行，零文件系统落盘",
      "l2": "内核侧加载执行，应用层无句柄",
      "residual": "memfd 句柄仍见于 /proc/self/fd（随机名承载）",
      "residual_accepted": true,
      "decision": null
    },
    {
      "id": "transport",
      "surface": "采集链路 IPC 痕迹（frida 默认端口、命名管道、socket 对）",
      "observer": "in-process scanner (connect/枚举)",
      "l0": "仅环回 + 随机端口",
      "l1": "去 TCP：注入即分离，控制面走内存通道",
      "l2": "内核死 syscall 通道（lookup_dcookie/quotactl），零 socket",
      "residual": "L2 下无独立残余（钩子残余归入 kernel-hook-residual）",
      "residual_accepted": true,
      "decision": null
    },
    {
      "id": "in-process-agent",
      "surface": "目标进程内 agent/gadget：maps 条目、额外线程、hook 痕迹",
      "observer": "in-process scanner（主场优势方）",
      "l0": "错过 init 窗口再 attach；maps 名随机化",
      "l1": "GOT/PLT-only 挂钩；dump 完成即分离，驻留秒级",
      "l2": "passive 模式零 agent（全内核侧读写）；active 模式 agent 仅触发，批量读走内核通道",
      "residual": "active 模式仍有秒级驻留窗口——一次性采集可承受（反不对称）",
      "residual_accepted": true,
      "decision": null
    },
    {
      "id": "proc-visibility",
      "surface": "采集器/frida-server 进程对目标与系统扫描可见（/proc walk、进程名）",
      "observer": "system-wide scanner + in-process /proc walk",
      "l0": "argv 随机化、短生命周期",
      "l1": "工作目录与父进程链清理",
      "l2": "KPM hide_proc 隐藏采集链全部进程",
      "residual": "ditPro 不过滤目标自身 /proc/self/maps 视图——agent 随机化承载，远期自研零逻辑 KPM 补齐",
      "residual_accepted": true,
      "decision": null
    },
    {
      "id": "kernel-hook-residual",
      "surface": "被钩的两个死 syscall：lookup_dcookie(18)、quotactl(60)",
      "observer": "理论信道：应用层对这两个号码做行为探测（构造参数观察返回值）",
      "l0": "n/a",
      "l1": "n/a",
      "l2": "非魔法参数原样透传，行为与未钩内核一致",
      "residual": "钩子本体在内核侧存在",
      "residual_accepted": true,
      "decision": "maintainer 裁定 2026-10-24：即使内核侧有残留，应用层也检测不到，不构成问题——无壳审计 syscall 行为"
    },
    {
      "id": "timing-window",
      "surface": "采集行为的时序暴露（CPU/IO 突刺、启动耗时变化）",
      "observer": "in-process 行为分析",
      "l0": "一次性采集：所需隐身窗口秒级",
      "l1": "错峰执行，错过 init 窗口",
      "l2": "内核侧读写，目标进程内零活动",
      "residual": "秒级窗口无法归零；持续对抗（月级暴露）的隐身标准不适用于一次性采集",
      "residual_accepted": true,
      "decision": null
    }
  ]
}
```

## 11. Version anchors

```text
SKILL_VERSION: 1.12.0
handoff_version: 1    goal_version: 1    proposal_version: 1
workorder_version: 1    manifest_version: 1    hygiene_version: 1
```

- File version = methodology + §8 fence snapshot. Format changes start in fixtures, serde types follow, CI binds both directions.
- 1.3.0: §7 repair-pipeline documentation added (product line b: `exuvia repair`); no protocol change.
- 1.4.0: §7 fourth method-body source (JNI-trace → smali synthesis) + §8 family 2 dex2c-translate entered (Battle-2 maintainer device-confirmed); no protocol change.
- 1.5.0: §7 dex2c source automation (--init/--seed-dex/--arms/--sigs-dex + offline TLS string materialization) + verify_all acceptance gate documented; §8 family-2 guidance synced to the automated recipe; §2 TOOLKIT inventory refreshed; doctor pathology range corrected to P0–P11; no protocol change.
- 1.6.0: hunt gains the block-chaining arm (`--aes-cbc/--aes-iv`, profile aes128cbc-tail-v1: trailer anchor, header-block length scan-verified, XOR-prefix sub-container walk) + fourth mechanical payload-debt source (parse-healthy dex with file_size vs data-section-end gap ≥0x70 — both battle families share the shape); §2 hunt entry + §8 family-2 recipe synced; no protocol change.
- 1.7.0: repair CLI gains the `--extra-dex` ship channel (pass-through dex appended as classes2..N, no re-serialization — for unpack-stage gate products; the positional/`--dump`/`--extra-dex` three-role contract documented in §7). Found by the tosks pipeline regression: a sub-dex routed via `--dump` is source-only and silently drops from the output APK; no protocol change.
- 1.7.1: §7 ship-channel completeness precondition (device-earned, tosks crash 2026-10-22): a raw container-recovered dex with `native` hollow stubs is not shippable — after surgery the shell runtime carrying the translated JNI bodies is gone and ART dies with UnsatisfiedLinkError on the first lifecycle call; family-2 translated classes must pass through the dex2c source (jnitrace → trace2smali) first, only the all-Dalvik synthesized dex goes to `--extra-dex`; no protocol change.
- 1.8.0: repair CLI gains the `--from-handoff` source channel — collects merge-gate products (`handoff/workspace/*/recovered.dex`) straight into the ship channels (sha256-dedup vs explicit channels; explicit positionals present → collected all go to `--extra-dex` in debt_id order; none → the largest collected dex promotes to the triaged positional, rest to `--extra-dex`; empty inputs = structured error). Closes the unpack→repair loop without manual file plumbing; §0/§7 usage synced; no protocol change.
- 1.9.0: repair gains hollow auto-fill (the completeness precondition's machine execution): ship-channel dexes are scanned for `native` lifecycle-name stubs (the family-2 tell — StubSafe's lifecycle table is the trigger set, verbatim), the shell .so is picked from the packed APK (`assets/*.so`, ELF64 AArch64, largest; `lib/` never selected), and the embedded four-step fill (hollowfill.py orchestrating jnitrace/trace2smali/baksmali/smali, now embedded with so_emulator.py) replaces the hollow dex in-channel before surgery — fill set = ALL native methods of the dex; `--allow-hollow` escape hatch (triage/debug only); missing deps (unicorn/dexlib2) or locate failure = structured error with the full suspect list, never a silent hollow ship; output JSON gains `hollow_filled`; no protocol change.
- 1.10.0: restore/stubsafe close the nop-wall gap (the extraction+nop-fill family shape — 爱加密-style: gutted bodies remain as LEGAL code_items of nops + zero-literal consts + return, so the old `implementation == null` fill predicate never saw them): Restore's fillable set gains nop-wall methods and its donor index rejects nop-wall source bodies (wall over wall = fake restore); StubSafe synthesizes contract bodies for nop-wall LIFECYCLE bodies on framework-carrier classes (superclass chain must exit the dex at a non-`Object` ancestor — a lifecycle name on a POJO is not the tell) and keeps non-lifecycle walls (verify as no-ops; only a source truly refills); residual try tables don't disqualify (handler code is gutted to nops too, and grafting replaces the implementation wholesale). Sample-validated: 8771/10290 walls on the 爱加密-free sample (85.1%), zero fake restores with an all-wall source, 44 lifecycle walls synthesized. No protocol change.
- 1.10.1: repair 清单手术盲区修复（族 3 爱加密实证）：wrapper 检测的兜底判定去掉 `com.` 前缀窄化——"类不在随包 dex 集内"本就是定案判据，与前缀无关（爱加密的壳 Application 在非 com 命名空间下逃过检测）；手术范围从单一 `android:name` 扩到全部启动期类属性（`android:name` + `android:appComponentFactory`，API 28+ 工厂劫持是族 3 的实际引导链），支持同一 `<application>` 元素多属性一次摘除（降序偏移删除 + 尺寸字段逐轮重读）；自检新增双属性合成锚点（正例双摘/兄弟属性保留/负例随包类不误伤）；无协议变更。
- 1.10.2: so_emulator 伪 libc 覆盖面扩充（族 3 爱加密实证）：真壳 import 面 150+ 个 libc 名，表外名字原先塌缩成匿名静默 return-0 桩——对"返回值被消费"的函数那不是良性默认，而是把壳的控制流推上错误分支（实证：爱加密 VMP 环境门 atoi(__system_property_get("ro.build.version.sdk")) 的 atoi 丢失 → 恒 0 → "上古设备"分派）。补齐约 110 个通用设备级语义（atoi/strtol 家族、str/mem 家族、_chk 变体、getauxval、pthread/sem/信号集、open/read/stat 家族（fd 层与 FILE 层共享 --fs 桥）、printf/scanf 家族（AAPCS64 va_list 读取器 + 变参扫描引擎）、qsort/dl_iterate_phdr/siglongjmp 以延迟调用记录输出、AAssetManager 桩）；表外名字改为具名计数桩，JSON 新增 unbound_imports（语义缺口清单，不是噪音）与 deferred_calls/once_pending；潜伏修复 f_memset 参数序（C 契约 dest/val/n——旧体写反，零值世界侥幸不显）与 __stack_chk_fail 大声停下（绝不静默落进下一函数）；自检新增六导入合成 ELF 锚点（atoi/strstr/strtok/sscanf 真语义 + memset 参数序 + 未绑定计数）；样本回归：VMP 环境门返回 1（sdk=30 分派正确），svc 事件流与修复前逐项一致。无协议变更。
- 1.10.3: repair 多供体恢复链修复（族 3 爱加密实证）：restore 逐供体暂存名 `.stage_next{dex}` 只按产物 dex 编号、不随供体编号——≥2 个 `--dump` 供体时自第二个起输入输出同名，成功后的上一步清理恰好删掉当前产物，后续供体与 StubSafe 连锁 FileNotFound、整脚本崩溃（实证：7 供体 mHook eBPF dump 回填，第一供体 375 条恢复成功后全链断裂；§7"several dumps are complementary"的多供体生产路径实际不可用）；暂存名补供体维度 `.stage_next{dex}_{src}`（`restore_stage_path(out, di, si)`）；自检新增多供体暂存名唯一性锚点（21 路径互异 + 与 stage/stage_final 不相撞）；样本回归：7 供体全链 5727 条恢复日志、nop 墙 8794→3240、五重验收门全绿；无协议变更。
- 1.10.4: restore 回填谓词纳入转发薄壳 + 供体诚实性修复（族 3 爱加密实证）：抽代码族对框架回调重写方法留纯转发薄壳（恰好 1 invoke + 1 return，可夹 move-result 值传递——8B 空壳顶包 104B 真身），非 nop 墙 → 旧谓词漏修（实证：74 薄壳中 31 处供体有真身，含启动路径 `Lyg;.onCreate` 8B→104B、`Lb4;.onAttachedToWindow` 8B→764B）；同时旧供体守卫把薄壳当真身——212 处 nop 墙被"回填"成 8B 薄壳仍记 restored（伪恢复，墙数照降、语义没回来）。谓词双侧对称放宽：目标可填 = nop 墙 ∨ 转发薄壳；供体资格 = 非空壳（墙与薄壳皆不供体）——对称性即安全证明：真空方法（开发者就写的 `super.onX()`）在供体侧同为薄壳被拒之门外，回填只在同签名供体携带真身时触发，同构建 dump 下这只能意味着目标被抽空。Restore 日志区分三种回填事由（nop-wall / forwarding-shell / body-merged）；新增 `Restore --selftest` 合成锚点（谓词六正反例 + 内存合成 dex 走真实 CLI 回填 e2e：墙与薄壳回填、真空供体被拒、真身不被触碰），自检在 dexlib 工具链可用时联动、否则大声 SKIP；样本回归：回填 5546（墙 5515 + 壳 31），净 nop 墙 8697→3182、薄壳 74→43、伪恢复 212 清零，`Lyg;.onCreate` 104B 真身实证；无协议变更。
- 1.10.5: 壳资产规则补族 3（爱加密实证）：家族模式表增收容载与运行时名（ijiami/.ajm/ijm_lib）、防篡改种子与签名块（af.bin/signed.bin）、植入标记文件（sign_verify.png/data_path_defualt_code.png）——均为打包器固定名（壳写的，不是应用写的），与 360 行同一契约；实证残留 5 项 660,851B 全清。规则仍纯名匹配、**刻意不加内容/magic 判据**——同一样本自证：应用自有 assets/icon|images/*.png 本就无 PNG magic（应用加密资源，含 0B 文件），内容判据会误伤真应用；assets/dexopt/baseline.prof{,m} 经评估保留（"pro\x00" magic 的 androidx ProfileInstaller 标准资产，应用侧构建产物）。自检新增壳资产规则锚点（壳 7 捕获 / 应用侧 8 豁免：加密资源、空文件、baseline profile、lib/ 下合法 .so）；样本回归：成品 398→393 条目，五重验收门全绿；无协议变更。
- 1.10.6: 覆盖率债务闭环三件套（族 3 爱加密"执行才重物化"机理的机器化执行，模式取自 FART 主动调用）：修复后残留的每堵 nop 墙都是覆盖率债务——dump 会话没执行过它，任何供体都不可能携带其真身；重物化先于首条指令执行，故哑参数 + 全吞异常即够，方法只需开始、无需成功。trackb/covdebt.py（成品 dex → 结构化债务 JSON，纯 Python 墙谓词与 Restore.isNopWall 语义逐条对齐，packed 8697 / 成品 3182 与 dexlib2 基准零误差校准）；trackb/fart_plan.py（债务 → 调用计划：静态反射直调 / Unsafe.allocateInstance 免构造接收器 / 构造器走 newInstance / <clinit> 走 forName 初始化 / 抽象类如实跳过；清单组件类前置为高价值层，支持层数裁剪 --limit）；trackb/fart_sweep.{js,py}（设备臂：Frida 薄执行器逐条反射调用、目标内 NPE 亦记成功——证明真代码已跑，adb 运行器产 sweep_report.json）。重脱后 --dump 追加，墙数逐轮可度量收敛（多供体恢复链 1.10.3 起可用）。自检新增合成锚点（含方法合成 dex 走查 + 谓词正反例 + 计划动作/分层/参数合成）；设备侧执行为维护者一键流程，本次未经真机验证（如实标注）；无协议变更。
- 1.10.7: 新增 trackb/upxunpack.py——纯 Python UPX 壳 ELF 解开器（族 3 实证：壳自己的 libexec.so 是 stock UPX，NRV2E_LE32 + arm64 过滤器 0x52）。解析 PackHeader（l_info/p_info/b_info 链），NRV2B/2D/2E × LE32/8/LE16 九种方法变体按 UCL 参考实现（n2b_d.c/n2d_d.c/n2e_d.c + getbit.h）逐语义移植，LZMA(14) 如实报错不猜测；arm64 过滤器 0x52 逆变换与 stock stub 逐指令核对（bits[30:26]==0b00101 → low26=(w-i)&0x3ffffff）。输出为各块解压拼接（原文件前缀），p_filesize 未覆盖尾部（运行期重建区，如壳自己的 RW/GOT）如实零填充并标注。自检锚点：合成 NRV2E 流（字面量+重复匹配+结束标记）/2B/2D 字面量流/过滤器逆变换/PackHeader e2e；样本回归：壳 .so 两块字节级尺寸全中（解压 0x3f25c/0x9cd94、消耗 0x13ef3/0x3aff8 与 b_info 完全一致），8067 处 B/BL 反过滤，JNI_OnLoad 恢复可读。无协议变更。
- 1.10.8: 发现 #10（族 3 爱加密真机实证）——nop 墙构造器是验证器地雷：爱加密的墙体对 `<init>` 是 `return-void + nop×3`、无 super/this 调用，ART verifier 硬性拒绝（"[0x0] Constructor returning without calling superclass constructor"）；带壳运行时壳在类加载前已回填真身，墙永不被验证，故原包无碍；去壳成品中每堵墙构造器都是加载期 VerifyError，dexopt 拒绝沿子类链级联（实证：v4 成品装机即崩，androidx.startup → ProcessLifecycleInitializer → x80 验证失败；packed 1501 条墙构造器，v4 残 673 条）。StubSafe 新增 ctor-stub 分支：为墙构造器合成最小合法体（invoke-direct 到 this/super 构造器 + return-void）——候选序：真身同胞构造器（this 链，免费复用原始初始化序列）→ 直接超类链逐层上溯的最便宜可访问构造器（ref 恒名直接超类，解析自行上溯；dex 内超类不声明构造器合法，Object 终结所有链；某层构造器全部超宽不终止搜索）→ 全 dex invoke 点收集的外部超类构造器引用（签名有设备存在性证据）→ 兜底假设无参 super 并大声记 `ctor-stub-assumed-noarg`（系统实例化组件类恒正确；错猜不劣于被替换的墙）。寄存器规划：≤5 字走 35c（哑元占新局部量 v0..），否则 3rc 覆写存根自身闲置参数；哑元一律零值/null const。非构造器墙处置不变（验证安全才保留）。covdebt 新增 ctor_stub 独立桶（合成构造器存根退出债务清单但不 inflate real；与天然空构造器字节级不可区分，如实并计）；自检新增 `StubSafe --selftest` 合成锚点（Object 超类 / 同胞 this 链 / 未声明构造器超类的直接超类 ref / 假设无参兜底 / 过宽超类落到链顶 / 非构造器墙保留）+ covdebt ctor_stub 锚点；样本回归：v5 成品 673 条墙构造器全部存根化（0 unresolved）、dexlib2 全量校验 1543 构造器 0 非法、2509 条保留墙全部验证安全（返回种类/寄存器/零值馈给逐项过）、packed dex 非构造器墙 0 条返回种类失配（早前 1540 例为手写解析器把 virtual 列表 method_idx_diff 当跨列表累积的误报——DEX 规范两列表各自从 0 重启）；无协议变更。
- 1.10.9: 发现 #11（族 3 爱加密真机实证，v5 闪退根因）——Restore 供体侧的转发壳外形拒收（`isHollowShell = 墙 || 转发壳`）会误杀真实的一行委托体：androidx 里大量真身恰好长成转发壳模样（单 invoke + return，如 `WindowInsetsControllerCompat$Api30Impl.getInsetsController(window)` = `invoke-virtual Window.getInsetsController; move-result-object; return-object`），被当作壳桥拒绝捐献 → 墙体残留 → v5 成品 `ia1.d` 返回 null → 控制器字段 null → `MainActivity.onCreate` 边缘到边缘路径 NPE 闪退（v5 dexopt 已全绿——#10 的 ctor-stub 生效，闪退是全新的覆盖欠债失效模式而非 VerifyError 回潮）。供体准入改为按信息量判、不按外形判：仅拒 (a) nop 墙（零信息）、(b) 与目标指令级全同（嫁接会虚增 restored 计数）、(c) 引用在可发货类全集 ∪ 引导类路径中悬空（壳桥调用永不得引入——NoSuchMethodError 风险）；外形像壳的真身委托照捐（墙目标本身已是被抽取的铁证）。新增 universe 门：repair_all 在 restore 前导出可发货类全集文件（镜像 is_boot_class 前缀豁免），Restore 逐供体核 `MethodReference`/`FieldReference` 定义类与 `TypeReference` 类型可解析，悬空即拒并大声记 `restore-skip-unresolved`；`toLForm` 单字符歧义修正——仅 `VZBSCIJFD` 算原始类型描述符，混淆后的单字母类名（"a"→"La;"）不是原始类型（首版误判致 210 条假悬空拒收、ctor-stub 反升 673→691）。新增 DonorMerge 工具：mHook/FART 扫荡产出数千个 per-dump dex（逐个跑 Restore 要数小时），两阶段坍缩 N 供体 → 1 合并供体 dex——阶段一并行扫描（ExecutorCompletionService 8 线程，边扫边并，全量驻留必 OOM：3062 供体 3.6GB RSS 撞 4GB 容器），同签名冲突取序号最小者（含乱序接管），墙永不胜出；阶段二只重开胜出供体，`ImmutableMethod.of` 深拷贝脱钩（防 mmap/FD 驻留）；`--universe` 过滤限制在可发货类（否则并集超 64k 类型引用写不出单 dex："Unsigned short value out of range: 66338"）；baseClass 取首个被重开的携类供体（类属性供体可能一无所获而永不重开，漏判会静默丢类）。实证：3062 供体（与 v5 的 7 供体同一会话，winners=14、0 冲突——尚无新增覆盖，收敛仍需 Test B 重扫）→ 1367 类 6913 体；packed+合并供体 graft 5758、23 全同跳过、0 悬空拒收；v6 对比 v5：墙 2509→2319、ctor-stub 673→651、债务 3182→2970，启动链 ia1.d/sa1.<init>/jr.b/cr.run/onCreate 全部真身。自检新增 `DonorMerge --selftest`（墙被丢、壳形委托被留、冲突首者胜）+ Restore 锚点（壳形真身委托可捐、悬空引用被拒、boot 前缀引用可捐）；无协议变更。
- 1.10.10: 发现 #12（族 3 爱加密真机实证，v6 闪退根因）——**墙体谓词的 nop 要求本身是盲区**：isNopWall 要求 `nops >= 1`，但抽取家族对 getter 尺寸的小方法不垫 nop——两指令挖空不需要填充，墙形就是裸零值存根（`const-wide/16 0; return-wide`，甚至孤 `return-void`）。实证：v6 越过 ia1.d NPE 后崩在 `MainActivity.onCreate:175`——Compose 快照 `readError`（"Reading a state that was created after the snapshot was taken…"），根因是 `Snapshot.getId`（lz0.g）是裸零值墙：恒返回 0 → StateRecord 盖上 0 号章（INVALID_SNAPSHOT）→ 第一次 `setValue` 读校验必炸。供体里明明有真身（3062 供体中 1 个，`iget-wide b; return-wide`），DonorMerge 也带上了——是 Restore 压根不把它当 graft 目标；covdebt/WallSafeCheck 同一谓词同样漏计。四处谓词语义级同步放宽：Restore.isNopWall / StubSafe.isNopWall / DonorMerge.isNopWall / covdebt.is_nop_wall 全部去掉 nop 要求（墙 = 指令集 ∈ {nop, 零值 const, return} 且 ≥1 return）。真身零值体（`return 0`、空回调）与墙同形、无供体不可分，但全链安全：全同供体触发 identical-skip（不虚增计数、字节不变），无供体则验证安全原样保留；真身 `<init>` 恒带 super/this invoke，永不落入此形（packed 实证 307 条零值墙 0 条构造器——ctor-stub 分支不受影响）；StubSafe 生命周期合成分支产物带 invoke，不构成墙。metrics 口径转为"无法证明为真的体皆债务"（真零值体计入墙桶，宁可多计不可漏计）。实证：packed 307 条零值墙此前全部隐形；v7 restore 5766 graft（+8，零值墙中有供体覆盖者）、DonorMerge 重建丢弃 310 条零形供体体（与目标墙字节相同，本就 identical-skip）1367→1304 类/6913→6603 体、快照启动链（sz0/lz0/dm0/l11/yz0/qz0/xx/fg0/y8）全真身、16 条"return this/参数"形墙验证安全（v6 dexopt PERFORMED 即实证）、CtorCheck 1543 构造器 0 非法；债务口径修正：v6 报告的 2970 漏算了 307 条零值墙，v7 诚实债务 = 2618 墙 + 651 ctor-stub = 3269。自检新增：Restore 谓词锚点（裸 const-wide 零值墙、孤 return-void 皆墙）+ graft e2e 锚点（零值墙从供体嫁接）；DonorMerge 锚点（低序号零值墙输给高序号真身）；covdebt 锚点翻转（bare return-void 计入墙）。无协议变更。
- 1.10.11: 发现 #13（族 3 爱加密真机实证，v7 倒计时结束闪退根因）——**被真代码可达的债务才是崩溃候选，而虚分派墙在 dex 里根本无名**。实证：v7 装机后无任何交互、倒计时归 0 瞬间确定性崩（启动后 30.4s，两次完全同点）：`ArrayIndexOutOfBoundsException: length=1280; index=-4`，链 `fz0.l ← gx.G ← gx.O ← gx.n ← … ← c7.doFrame`。根因不是谓词盲区而是供体覆盖缺口：Compose changelist 的 7 个结构性 `Operation.execute` 重写（dk0/ek0/kk0/sj0/vj0/wj0/yj0 `.a(Lrk0;La9;Ljz0;Lwr0;Lqk0;)V`）是无供体墙；槽位值更新走真身的 zj0，故前 30s 无恙——倒计时归 0 时同意按钮的 `if (countdown > 0) Text("…($countdown)") else Text("…")` 分支翻转是 App 的第一次**结构性**槽表编辑，真身执行循环 `sk0.B` 虚分派进墙，墙静默空转 → 槽表与 composer 状态发散 → 随后 `recomposeToGroupEnd` 祖先 walk（parentOf/hasMark 循环）越过根到组 −1 → `groups[-4]` 炸。教训落成工具：朴素引用扫描恰恰漏掉这类崩溃——虚分派重写者在 dex 内**从不被点名**（invoke 点只名基类 `pk0.a`）。covdebt 新增 `hot` 标记（墙体被 dex 内 invoke 点名 = 直接热；或与被点名方法同签名且其类的祖先闭包命中引用的定义类 = 分派热——墙体不含 invoke 指令，故任何引用者必为真代码，语义可靠；invoke-super 非虚分派的过近似刻意保留——多扫荡几堵墙、绝不漏崩溃候选）+ 每条目 `method_idx` + `stats['hot']`；fart_plan 新增 hot 层排在 component/rest 之前、summary 增 hot/by_tier。潜伏修复：dex 扫描 opcode 长度表补 0xfa–0xff（invoke-polymorphic/custom、const-method-handle/type——真机 dex 反同步曾致引用扫描 IndexError）+ 引用 midx 越界防护。实证：v7 债务 2618 墙中 hot=1737，7 条肇事墙全部命中 hot 层（计划位次 235–1553，冷界 1737）；HomeCompose 门脸（sz，供体整类缺席）与 CompositionContext（gi，9 墙）等同因缺口同被 hot 捕获。自检新增：合成 dex 三锚点——直接热（invoke-static 点名墙）/ 分派热（同体墙仅基类被 invoke-virtual 点名）/ 同形冷墙（字节全同但无引用，可达性而非外形定热）；fart_plan 热层排序锚点。设备侧修复路径不变：对 v7 跑 fart_sweep（热层先行）→ 重 dump → `repair_all --dump` → v8。无协议变更。
- 1.11.0: 理念增订（无协议变更）——新增 §9 动态脱壳理念：双引擎分工（静态 = 侦察 + 修复，动态 = 提取主力；挂钩 ART 标准入口故壳家族无关，族 3 rodata 四符号实证）；采集器六铁律（root 硬前提 / 不重签名 / 独立二进制仅工单耦合 / 自包含 + 随机工件 / 无 adb / 非 APK 裸 ELF）；隐身 L0–L2 分级与"比观察者高一层"定律、一次性采集 vs 持续对抗的升级节奏约束、内核侧 zero-sample 纪律；ditPro KPM 1.4.2 接口入库（lookup_dcookie/quotactl 双死 syscall 钩、nomi 握手 + 指纹令牌、物理内存读写命令集——被动采集可无 frida，maps 自视图过滤缺口记录在案）；kpm_client 四动词接口面冻结（L2 握手失败 = 大声拒绝，不静默降级）。原 §9 Version anchors 顺延为 §10；工具链行为零变化。
- 1.12.0: 协议变更——新增 §10 采集契约三件套（DRAFT v0，fixture 即锚定，生成/解析接线随采集器 epic 落地）：**workorder.json**（exuvia→采集器：目标 package+apk_sha256 锚定——不符大声拒绝；family 仅技术族 id + 证据，§8 围栏规则延伸到采集线；extraction 双模式 passive/active + ART 锚点集 + fart_plan 种子文件引用（file+sha256+hot_first）；env-gate 投喂表；stealth.tier 最低档禁止静默降档 + kpm(required/min_version/channels⊆phys_read/phys_write/hide_proc)；卫生策略布尔集对齐目录版本；deliverables ⊆ dex/runtime-log/maps；manual-transfer + tar.gz 唯一回传形态）；**manifest.json**（采集器→exuvia：order_id+workorder_sha256 回显；采集器/设备事实（root 形态在档）；stealth_tier_used + kpm.status 回读实际生效通道——非请求值；anchors_hit 命中证据；工件 sha256 清单；errors；residuals_accepted 挂接卫生目录）；**hygiene.json**（工件卫生目录，六通道 tell-surface 基准：fs-artifacts / transport / in-process-agent / proc-visibility / kernel-hook-residual / timing-window，每通道 surface×observer×L0–L2 缓解×残余×裁定；kernel-hook-residual 落档 maintainer 2026-10-24 裁定——应用层无法检测内核侧残留，非魔法参数原样透传，接受）。CI 三向锚定照 §3/§4 模式：新增 src/protocol/collector.rs（三 serde 类型 + 共用枚举，deny_unknown_fields + JsonSchema）；tests/skill_doc.rs 三新臂（kinds 63→511）+ 锚点循环扩三常量；version.rs 新增 WORKORDER/MANIFEST/HYGIENE_VERSION=1，protocol_line 与 --version JSON 同步扩展。原 §10 Version anchors 顺延为 §11（测试 split 串同步）。采集器本体不在本仓——契约先立，实现另起（铁律 3）。
- Before adapting to a new environment, compare `exuvia --version` against these.
