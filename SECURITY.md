# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| main    | ✓        |

## Reporting a Vulnerability

**Please use private channels only — do not open a public issue for
security reports.** Use GitHub Security Advisories (the private
*Report a vulnerability* button on the Security tab of this repository).

Include: affected file/function, reproduction steps (for gate breaks: the
proposal package layout and the exact error code path; for parser defects:
the crafted input's structure — **do not attach real commercial packed
samples to public reports**, the zero-sample policy applies to reports
too), and expected vs. actual behavior.

- Response target: within 7 days
- If the vulnerability is accepted, you will be credited in the
  advisory (unless you prefer to remain anonymous)
- If it is declined, a written explanation will be provided

## Scope — What Counts as a Vulnerability

This project processes **hostile input by design** and executes
**untrusted code in a sandbox by design**. Its security invariants are
the ones below; breaks in them count:

- **Memory-safety defects in the parsers.** The DEX / ELF / zip parsing
  paths consume guaranteed-hostile input through a single Rust entry
  point. Any out-of-bounds access, unvalidated-size allocation (the
  bounds-check-before-allocation discipline exists precisely because of
  a forged 126-GB table-size attack), or undefined behavior reachable
  from a crafted APK counts.

- **Sandbox escape or resource-limit defeat.** A `proposal/` artifact
  that escapes the `python3 -I` + cleared-environment + rlimit regime
  (writes to disk, touches the network, spawns processes, or defeats
  the CPU / address-space / fd limits in a way that damages the host)
  counts. The sandbox is the enforcement boundary for the project's
  core rule: *the verdict stays in Rust*.

- **Gate-integrity breaks.** Any path where a proposal that should be
  rejected still settles debt: claiming debt ids outside the work
  package's scope gate, passing with bytes that do not match the
  declared hashes, an `equivalent` claim routing around
  `accepts_equivalent`, or a fabricated verdict ending up in
  `attempts.log` / the debt ledger counts. The four merge gates and the
  dual anchor (structural assertion on the trusted side × numeric tests
  in the sandbox — never both dependent on the untrusted layer at once)
  are the product's core invariants.

- **Fake-interpreter acceptance.** The installation probe exists to
  catch missing or fake `python3` executables (including Windows
  `python.exe` impostors); a probe bypass that lets a broken or forged
  interpreter be accepted as a healthy installation counts.

## Out of Scope — By-Design Behavior

- **Exuvia unpacks hardened apps; hardening detecting Exuvia is not a
  vulnerability.** A packer adding anti-Exuvia checks is the expected
  arms race, not a security bug — the architecture deliberately does
  not depend on accumulated fingerprints for its value.

- **Dual-use misuse is not a vulnerability.** Using the recovered code
  for piracy or redistribution-infringing purposes is misuse of a
  research tool; the tool does what it is documented to do.

- **Text-level import-whitelist bypasses without an actual escape.**
  The whitelist is a first line against *misuse*; the security boundary
  is OS-level isolation plus the Rust-side verdict. Bypassing the text
  filter while remaining confined inside the sandbox is not a
  vulnerability.

- **A compromised host environment.** `-I` isolation blocks the
  realistic injection surfaces (PYTHONPATH, user site-packages,
  sitecustomize). A directly tampered interpreter or root-level
  compromise of the analysis machine is outside any analysis tool's
  threat model — IDA and Ghidra die the same death. This is why the
  documentation prescribes a disposable snapshot environment.

- **The quality of recovered output.** An incomplete dissection with
  honest debt is a deliverable by design, not a security issue.
