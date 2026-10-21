# Exuvia Repair Task Protocol v1.0

A unified exchange format between UNPACKERS, REPAIRERS, and INTELLIGENT AGENTS.
Every phase reads a task.json and writes one back. The flow:

    unpacker ──writes──> task.json ──read by──> repairer
    repairer ──writes──> task.json (status=running|pending_decisions|complete|failed)
    if pending_decisions: AGENT reads decisions[] and fills in the answers
    repairer ──rereads──> task.json (answers filled) ──> continues ──> complete

## task.json schema

```json
{
  "format_version": "1.0",
  "task_id": "<uuid>",

  "source": {
    "packed_apk": "<path to the packed/shell APK>",
    "dump_files": ["<paths to dumped .dex files>"],
    "reference_dex": "<path to an unpacked original / prior version .dex, or null>",
    "reference_apk": "<path to the unpacked original .apk, or null>"
  },

  "status": "running | pending_decisions | complete | failed",

  "decisions": [
    {
      "id": "<unique-d>",
      "type": "<see decision types below>",
      "question": "<human-readable description of what needs to be decided>",
      "context": "<supporting data: shell class names, method signatures, etc.>",
      "options": [
        {"value": "<machine-readable answer>", "description": "<what this means>"}
      ],
      "default": "<value used if the agent doesn't answer>",
      "answered": false,
      "answer": null
    }
  ],

  "report": {
    "pathologies": ["P1", "P7", ...],
    "weaving_sites": 14,
    "weaving_bridges": 12,
    "weaving_probes": 2,
    "native_stubs": 1,
    "native_stubs_restored": 0,
    "notes": ["free-form findings the agent should know about"]
  },

  "artifacts": {
    "restored_apk": "<path to the final APK, only set when status=complete>",
    "repair_log": "<path to the detailed repair log>"
  },

  "error": "<set when status=failed>"
}
```

## Decision types

| type | when raised | who should answer |
|---|---|---|
| `dump_selection` | multiple dump files exist and no single one covers the app | agent picks the best one or supplies multiple |
| `bridge_semantics` | a shell-woven method has a known name but the bridge target isn't in the built-in table | agent identifies the framework call the shell's bridge delegates to |
| `native_stub_reference` | methods are shell-frozen native stubs and no reference DEX was provided | agent supplies a reference path or opts for minimal_stub |
| `shell_class_prefix` | shell class prefixes weren't in the built-in table | agent identifies the packer family and provides the prefix |
| `unknown_pathology` | a structural anomaly the doctor can't auto-repair | agent diagnoses and prescribes a manual patch |

## Invariants

- The repairer NEVER asks the agent to write code. Decisions are data.
- Every decision has a `default` — the pipeline can always proceed conservatively
  without the agent, at reduced fidelity.
- The agent's answers are auditable (the task.json is the audit trail).
- New shell families adapt by: answering a decision once → the repairer learns
  → next time the same family is fully automatic.
