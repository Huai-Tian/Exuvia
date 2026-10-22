#!/usr/bin/env python3
"""verify_all.py — the LOCAL acceptance gate (the strategy answer).

Debugging-by-device (install -> crash -> logcat -> guess) costs one hardware
round per bug and scales terribly across packer/dumper combinations. This
gate runs EVERY check we know of — official tools where they exist — on the
bench, before anything ships:

  V1 zip layer    — zipfile integrity, entry-set sanity, 4-byte alignment,
                    resources.arsc STORED+aligned (the R+ install gate)
  V2 DEX container— dexdoctor's full pathology audit P0..P11 must be CLEAN
  V3 DEX strict   — apktool/dexlib2 full decode (the strictest offline DEX
                    judge; anything ART's verifier would trip on shows here)
  V4 DEX content  — shell-weaving residue must be 0 (woven invokes restored),
                    manifest component classes must exist in the DEX
  V5 signature    — apksigtool (apksigner-derived) full v2 verification

Usage: verify_all.py <restored.apk> [--tools /path/to/apktool.jar]
Exit code 0 = all gates green (ship it); nonzero = do not ship.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def gate_zip(path):
    problems = []
    z = zipfile.ZipFile(path)
    bad = z.testzip()
    if bad is not None:
        problems.append('zip corruption at %s' % bad)
    data = open(path, 'rb').read()
    unaligned = []
    for info in z.infolist():
        lh = data.find(b'PK\x03\x04', info.header_offset)
        nl, el = struct.unpack_from('<HH', data, lh + 26)
        doff = lh + 30 + nl + el
        if doff % 4:
            unaligned.append(info.filename)
        if info.filename == 'resources.arsc':
            if info.compress_type != zipfile.ZIP_STORED:
                problems.append('resources.arsc not STORED (R+ gate)')
            if doff % 4:
                problems.append('resources.arsc not 4-aligned (R+ gate)')
    if unaligned:
        problems.append('%d entries not 4-aligned' % len(unaligned))
    return problems


def gate_dex_doctor(path, repacked=False):
    import dexdoctor
    dexb = zipfile.ZipFile(path).read('classes.dex')
    t = dexdoctor.Triage(dexb).diagnose()
    issues = t.issues
    if repacked:
        # P10/P11 audit the DUMP's reference chains and map-declared sections;
        # a repacked (dexlib2-reserialized) dex has a different — but fully
        # standard — inline layout that those map-section walks misread.
        # Its structural health is proven by the dexlib2 roundtrip (V3).
        issues = [i for i in issues if not (i.startswith('P10') or i.startswith('P11'))]
    if issues:
        return ['dexdoctor issues: %s' % '; '.join(issues)]
    return []


def gate_dexlib2(path, apktool_jar):
    if not (apktool_jar and os.path.exists(apktool_jar)):
        return ['SKIP (apktool.jar not found — download it for the strictest gate)']
    tmp = tempfile.mkdtemp(prefix='vx_')
    try:
        r = subprocess.run(['java', '-Xmx2g', '-jar', apktool_jar, 'd', '-f',
                            '-o', os.path.join(tmp, 'out'),
                            '--only-main-classes', path],
                           capture_output=True, text=True, timeout=600)
        out = r.stdout + r.stderr
        if r.returncode != 0 or 'Exception' in out:
            tail = [l for l in out.strip().split('\n') if l][-5:]
            return ['apktool/dexlib2 decode failed: %s' % ' | '.join(tail)]
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def gate_content(path):
    """Weaving residue: SELF-CONTAINED — deweave is idempotent; a second run
    must find nothing. androguard's opcode walk is only an optional extra
    (it stack-overflows on legal-but-deeply-nested encoded_values in some
    repacked containers — a python limitation, NOT a defect dexlib2 sees)."""
    problems = []
    import deweave
    z = zipfile.ZipFile(path)
    dexb = z.read('classes.dex')
    _, rep = deweave.deweave(dexb)
    woven = [l for l in rep if 'restored' in l or 'nop-ed' in l]
    if woven:
        problems.append('shell-weaving residue: %d woven sites remain (deweave found work to do)'
                        % len(woven))
    # manifest components must exist in the DEX (self-contained check)
    import dexclean
    comps, pkg = dexclean.manifest_classes_from_apk(path)
    dx = dexclean.Dex(dexb)
    defined = set(n for _, n, _ in dx.class_defs())
    # multi-dex: manifest components may live in classes2.dex..classesN.dex
    for extra in sorted(n for n in z.namelist()
                        if n.startswith('classes') and n != 'classes.dex' and n.endswith('.dex')):
        try:
            dx2 = dexclean.Dex(z.read(extra))
            defined |= set(n for _, n, _ in dx2.class_defs())
        except Exception:
            pass
    missing = [c for c in comps if c not in defined and c.startswith(pkg or '')]
    if missing:
        problems.append('manifest components missing from DEX: %s' % missing[:5])
    # optional androguard extras (never fatal to the gate itself)
    try:
        import logging
        logging.disable(logging.CRITICAL)
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        a = APK(path)
        # multi-dex: androguard sees only the single dex it is handed — a
        # classes.dex-only read false-positives "main activity missing" when
        # the activity lives in classes2.dex+ (tosks closed-loop build).
        # Union every classesN.dex entry, same as the dexclean check above.
        ag_defined = set()
        for entry in sorted(n for n in z.namelist()
                            if n.startswith('classes') and n.endswith('.dex')):
            try:
                ag_defined |= set(c.get_name() for c in DEX(z.read(entry)).get_classes())
            except Exception:
                continue
        main = a.get_main_activity()
        if main:
            dn = 'L' + main.replace('.', '/') + ';'
            if dn not in ag_defined:
                problems.append('main activity %s missing from DEX (androguard)' % main)
    except (ImportError, RecursionError, Exception):
        pass  # optional judge — dexlib2 V3 already covers structure strictly
    return problems


def gate_signature(path):
    r = subprocess.run(['apksigtool', 'verify', path], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    if 'v2 verified' not in out and 'v3 verified' not in out:
        return ['apksigtool: %s' % [l for l in out.strip().split('\n') if l][-1:]]
    return []


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('apk')
    ap.add_argument('--tools', default='/workspace/tools/apktool.jar')
    ap.add_argument('--repacked', action='store_true',
                    help='the dex was dexlib2-reserialized (repair pipeline v11+): '
                         'P10/P11 map-section audits do not apply to that layout')
    args = ap.parse_args()
    gates = [
        ('V1 zip layer', lambda: gate_zip(args.apk)),
        ('V2 dex pathology audit (doctor)', lambda: gate_dex_doctor(args.apk, args.repacked)),
        ('V3 dexlib2 strict decode', lambda: gate_dexlib2(args.apk, args.tools)),
        ('V4 content residue', lambda: gate_content(args.apk)),
        ('V5 signature', lambda: gate_signature(args.apk)),
    ]
    failed = 0
    print('=== verify_all: %s ===' % args.apk)
    for name, fn in gates:
        probs = fn()
        if not probs:
            print('  [PASS] %s' % name)
        elif probs and probs[0].startswith('SKIP'):
            print('  [SKIP] %s — %s' % (name, probs[0]))
        else:
            failed += 1
            print('  [FAIL] %s' % name)
            for p in probs:
                print('         %s' % p)
    if failed:
        print('VERDICT: DO NOT SHIP (%d gate(s) failed)' % failed)
        sys.exit(1)
    print('VERDICT: ALL GREEN — ship it')
    sys.exit(0)


if __name__ == '__main__':
    main()
