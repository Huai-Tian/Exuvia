#!/usr/bin/env python3
"""exuvia_repair.py — the protocol-compliant repair entry point.

Reads a task.json (written by the unpacker or carried over from a previous
repair attempt), runs the repair pipeline, and writes the task.json back.

Flow:
  1. First run: reads source+artifacts, starts the pipeline.
     If any DECISION is raised (bridge semantics unknown, native stub without
     reference, etc.) → status=pending_decisions, writes the task back, exits.
  2. The agent reads decisions[], fills in answers, reruns this script.
  3. Second run: sees answered decisions → uses them → completes.

Every decision has a conservative default; the pipeline can always proceed
without the agent at reduced fidelity (probes→nop, unknown bridges→nop,
stubs→minimal). The agent's job is to RAISE fidelity, not unblock the flow.

Usage:
  exuvia_repair.py <task.json>        # read, repair, write back
"""
import json
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def raise_decision(decisions, dtype, question, context, options, default):
    """Record a decision. If already answered in the existing list, return
    the answer; otherwise add a pending one and return the default."""
    for d in decisions:
        if d['type'] == dtype and d['question'] == question:
            if d.get('answered'):
                return d['answer']
            return d['default']
    decisions.append({
        'id': 'd%d' % (len(decisions) + 1),
        'type': dtype,
        'question': question,
        'context': context,
        'options': options,
        'default': default,
        'answered': False,
        'answer': None,
    })
    return default


def main():
    if len(sys.argv) < 2:
        print('usage: exuvia_repair.py <task.json>')
        sys.exit(2)
    task_path = os.path.abspath(sys.argv[1])
    task = json.load(open(task_path))

    if 'task_id' not in task:
        task['task_id'] = str(uuid.uuid4())
    task.setdefault('status', 'running')
    decisions = task.setdefault('decisions', [])
    report = task.setdefault('report', {'pathologies': [], 'notes': []})
    task.setdefault('artifacts', {})

    src = task.get('source', {})
    packed_apk = src.get('packed_apk')
    dump_files = src.get('dump_files', [])
    reference_dex = src.get('reference_dex')

    if not packed_apk or not dump_files:
        task['status'] = 'failed'
        task['error'] = 'source.packed_apk and source.dump_files are required'
        json.dump(task, open(task_path, 'w'), indent=2)
        print('FAILED: %s' % task['error'])
        sys.exit(1)

    # ── dump selection ──
    import dexclean
    if len(dump_files) == 1:
        dump_dex = dump_files[0]
    else:
        # pick the one with the highest overlap with the packed APK's manifest
        # components; if tie or uncertain, raise a decision
        best, best_score = None, 0
        comps, pkg = dexclean.manifest_classes_from_apk(packed_apk)
        for f in dump_files:
            try:
                dx = dexclean.Dex(open(f, 'rb').read())
                cs = set(n for _, n, _ in dx.class_defs())
                score = len([c for c in comps if c in cs])
                if score > best_score:
                    best, best_score = f, score
            except Exception:
                pass
        if best:
            dump_dex = best
            report['notes'].append('auto-selected dump: %s (overlap %d/%d manifest components)'
                                   % (os.path.basename(best), best_score, len(comps)))
        else:
            dump_dex = raise_decision(decisions, 'dump_selection',
                'Multiple dump files provided; none overlaps the manifest components cleanly',
                'Files: %s' % ', '.join(os.path.basename(f) for f in dump_files),
                [{'value': f, 'description': 'use this dump'} for f in dump_files],
                dump_files[0])

    # ── native stub detection (pre-flight) ──
    # if there are native+no-code methods and no reference, raise a decision
    import subprocess
    repack_dir = os.environ.get('EXUVIA_DEXLIB', '/workspace/tools/dexlib')
    native_stub_count = 0
    native_stub_examples = []
    if os.path.exists(os.path.join(repack_dir, 'dexlib2-2.5.2.jar')):
        # quick check: use dexlib2 to count native stubs in the dump
        r = subprocess.run(['java', '-cp', 'dexlib2-2.5.2.jar:util-2.5.2.jar:guava-31.1-jre.jar:.',
                            'StubCheck', dump_dex],
                           cwd=repack_dir, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            try:
                info = json.loads(r.stdout.strip())
                native_stub_count = info.get('native_stubs', 0)
                native_stub_examples = info.get('examples', [])
            except (ValueError, AttributeError):
                pass
    if native_stub_count > 0 and not reference_dex:
        ref_answer = raise_decision(decisions, 'native_stub_reference',
            '%d native-stub methods detected (shell-frozen entry hooks); no reference DEX provided' % native_stub_count,
            'Stubs: %s' % ', '.join(native_stub_examples[:5]),
            [
                {'value': 'minimal_stub', 'description': 'generate minimal stubs calling super (app starts, entry may misbehave)'},
                {'value': 'skip', 'description': 'leave as-is (app will crash on those entries)'},
            ],
            'minimal_stub')
        if ref_answer and ref_answer != 'minimal_stub' and ref_answer != 'skip':
            reference_dex = ref_answer  # agent supplied a path

    # ── run the engine ──
    out_apk = os.path.join(os.path.dirname(task_path), 'restored.apk')
    cmd = [sys.executable, os.path.join(HERE, 'repair_all.py'),
           packed_apk, dump_dex, '-o', out_apk]
    if reference_dex:
        cmd += ['--reference', reference_dex]
    print('[engine] %s' % ' '.join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)

    # parse the engine's output for pathologies and weaving stats
    for line in (r.stdout + r.stderr).split('\n'):
        line = line.strip()
        if line.startswith('[doctor]'):
            for p in ('P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9', 'P10', 'P11'):
                if p in line:
                    report['pathologies'].append(p)
        if line.startswith('[deweave]'):
            if 'woven sites restored' in line:
                report['weaving_sites'] = int(''.join(c for c in line.split(':')[1].split('(')[0] if c.isdigit()))
        if line.startswith('[restore]'):
            if 'methods merged' in line:
                report['native_stubs_restored'] = int(''.join(c for c in line.split(':')[1].split('methods')[0] if c.isdigit()))

    if r.returncode != 0:
        task['status'] = 'failed'
        task['error'] = r.stderr[-500:] if r.stderr else 'engine returned %d' % r.returncode
        task['artifacts']['repair_log'] = r.stdout + r.stderr
        json.dump(task, open(task_path, 'w'), indent=2)
        print('FAILED: %s' % task['error'])
        sys.exit(1)

    # ── verify ──
    verify_cmd = [sys.executable, os.path.join(HERE, 'verify_all.py'),
                  out_apk, '--repacked']
    vr = subprocess.run(verify_cmd, capture_output=True, text=True)
    all_green = 'ALL GREEN' in vr.stdout
    if not all_green:
        task['status'] = 'failed'
        task['error'] = 'verification failed:\n%s' % vr.stdout
        task['artifacts']['restored_apk'] = out_apk
        json.dump(task, open(task_path, 'w'), indent=2)
        print('FAILED: verification gate')
        print(vr.stdout)
        sys.exit(1)

    # ── done ──
    if any(not d.get('answered') for d in decisions):
        task['status'] = 'pending_decisions'
        print('PENDING: %d decision(s) need answers (see task.json); rerun after filling them in'
              % sum(1 for d in decisions if not d.get('answered')))
    else:
        task['status'] = 'complete'
        task['artifacts']['restored_apk'] = out_apk
        print('COMPLETE: %s' % out_apk)

    json.dump(task, open(task_path, 'w'), indent=2)


if __name__ == '__main__':
    main()
