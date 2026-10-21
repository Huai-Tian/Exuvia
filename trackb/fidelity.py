#!/usr/bin/env python3
"""fidelity.py — dump-vs-reference fidelity report (the industry question).

Dumpers hand you a DEX and nobody can tell you WHAT it is: is it the app's
real code, or polluted, or rewired? The corpus (and any user who still owns
the original build) has the ground truth — this tool diffs the dump against
the reference DEX at every level the DEX format exposes, and prints a
structured verdict a human (or an agent) can act on:

  LEVELS (cheap -> deep):
    L0 bytes:  sha256 / size (rewritten dumps never match; that is expected)
    L1 header: table sizes (string/type/proto/field/method/class_defs)
    L2 sets:   class-set diff (THE core fidelity question)
    L3 pools:  string-pool diff (injected shell hooks show up here)
    L4 tables: field/method semantic tables (class.name[.shorty])

  VERDICT: one of
    IDENTICAL-CLASSSET  — the dump IS the app (what a clean dumper gives you)
    PARTIAL             — superset/subset: pollution or missing components
    DIVERGENT           — different app entirely

Usage:
  fidelity.py dumped.dex --ref original.dex [--json] [--verbose]
"""
import argparse
import hashlib
import json
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexclean import Dex, uleb128


def _tables(dx):
    """Semantic tables: methods (cls,name,shorty), fields (cls,name,type)."""
    strs = dx.strings()
    shortys = [strs[struct.unpack_from('<I', dx.d, dx.proto_ids_off + i * 12)[0]]
               for i in range(dx.proto_ids_size)]
    methods = []
    for i in range(dx.method_ids_size):
        m = dx.method_ids_off + i * 8
        cls_idx, proto_idx = struct.unpack_from('<HH', dx.d, m)
        name_idx = struct.unpack_from('<I', dx.d, m + 4)[0]
        methods.append((dx.type_name(cls_idx, strs), strs[name_idx], shortys[proto_idx]))
    fields = []
    for i in range(dx.field_ids_size):
        f = dx.field_ids_off + i * 8
        cls_idx, type_idx = struct.unpack_from('<HH', dx.d, f)
        name_idx = struct.unpack_from('<I', dx.d, f + 4)[0]
        fields.append((dx.type_name(cls_idx, strs), strs[name_idx], dx.type_name(type_idx, strs)))
    return methods, fields


def _class_members(dx, methods, fields):
    """per-class declared members, keyed semantically (shorty-based).
    Returns (dict, walkable): walkable=False when any class_data could not be
    decoded without index overruns (039-family layouts) — the member sets
    are then incomplete and comparisons unreliable."""
    out = {}
    walkable = True
    strs = dx.strings()
    for i in range(dx.class_defs_size):
        off = dx.class_defs_off + i * 32
        ci, _a, _s, _if, _src, _ann, cdo, _sv = struct.unpack_from('<IIIIIIII', dx.d, off)
        mem = set()
        if cdo:
            p = cdo
            nsf, p = uleb128(dx.d, p); nif, p = uleb128(dx.d, p)
            ndm, p = uleb128(dx.d, p); nvm, p = uleb128(dx.d, p)
            try:
                fid = 0
                for _ in range(nsf + nif):
                    delta, p = uleb128(dx.d, p); _acc, p = uleb128(dx.d, p)
                    fid += delta
                    if fid >= dx.field_ids_size:
                        raise IndexError('field')
                    mem.add(('F',) + fields[fid])
                mid = 0
                for _ in range(ndm + nvm):
                    delta, p = uleb128(dx.d, p); _acc, p = uleb128(dx.d, p); _code, p = uleb128(dx.d, p)
                    mid += delta
                    if mid >= dx.method_ids_size:
                        raise IndexError('method')
                    mem.add(('M',) + methods[mid])
            except (IndexError, struct.error):
                walkable = False
        out[dx.type_name(ci, strs)] = mem
    return out, walkable


def report(dump_path, ref_path):
    dump = Dex(open(dump_path, 'rb').read())
    ref = Dex(open(ref_path, 'rb').read())
    rep = {'dump': dump_path, 'ref': ref_path}

    # L0 bytes
    db, rb = bytes(dump.d), bytes(ref.d)
    rep['bytes'] = {'dump_sha256': hashlib.sha256(db).hexdigest(),
                    'ref_sha256': hashlib.sha256(rb).hexdigest(),
                    'dump_size': len(db), 'ref_size': len(rb),
                    'identical': db == rb}

    # L1 header tables
    rep['header'] = {
        'dump_magic': bytes(dump.d[4:8]).decode('latin1'),
        'ref_magic': bytes(ref.d[4:8]).decode('latin1'),
        'string_ids': (dump.string_ids_size, ref.string_ids_size),
        'type_ids': (dump.type_ids_size, ref.type_ids_size),
        'proto_ids': (dump.proto_ids_size, ref.proto_ids_size),
        'field_ids': (dump.field_ids_size, ref.field_ids_size),
        'method_ids': (dump.method_ids_size, ref.method_ids_size),
        'class_defs': (dump.class_defs_size, ref.class_defs_size),
    }

    # L2 class set — the core question
    dc = set(n for _, n, _ in dump.class_defs())
    rc = set(n for _, n, _ in ref.class_defs())
    rep['classes'] = {'dump': len(dc), 'ref': len(rc),
                      'common': len(dc & rc), 'dump_only': sorted(dc - rc), 'ref_only': sorted(rc - dc)}

    # L3 string pools
    ds, rs = set(dump.strings()), set(ref.strings())
    rep['strings'] = {'dump': len(ds), 'ref': len(rs),
                      'dump_only': sorted(ds - rs), 'ref_only': sorted(rs - ds)}

    # L4 semantic tables
    dm, df = _tables(dump)
    rm, rf = _tables(ref)
    from collections import Counter
    dm_c, rm_c = Counter(dm), Counter(rm)
    df_c, rf_c = Counter(df), Counter(rf)
    rep['methods'] = {'dump': len(dm), 'ref': len(rm),
                      'dump_only': [list(x) for x in (dm_c - rm_c).elements()],
                      'ref_only': [list(x) for x in (rm_c - dm_c).elements()]}
    rep['fields'] = {'dump': len(df), 'ref': len(rf),
                     'dump_only': [list(x) for x in (df_c - rf_c).elements()],
                     'ref_only': [list(x) for x in (rf_c - df_c).elements()]}

    # L5 members (best-effort; 039-family class_data layouts may be unwalkable
    # — an unwalkable side makes its member sets incomplete and the diff
    # UNRELIABLE. Track walkability per side and say so.)
    try:
        dmem, dwalk = _class_members(dump, dm, df)
        rmem, rwalk = _class_members(ref, rm, rf)
        memdiff = {'common_same': 0, 'common_diff': 0, 'diff_classes': [],
                   'reliable': dwalk and rwalk}
        for n in set(dmem) & set(rmem):
            if dmem[n] == rmem[n]:
                memdiff['common_same'] += 1
            else:
                memdiff['common_diff'] += 1
                if len(memdiff['diff_classes']) < 8:
                    memdiff['diff_classes'].append(n)
        rep['members'] = memdiff
    except Exception as e:
        rep['members'] = {'error': str(e), 'reliable': False}

    # verdict
    if dc == rc:
        verdict = 'IDENTICAL-CLASSSET'
    elif dc & rc and (len(dc & rc) > max(len(dc), len(rc)) * 0.5):
        verdict = 'PARTIAL'
    else:
        verdict = 'DIVERGENT'
    rep['verdict'] = verdict
    return rep


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('dump')
    ap.add_argument('--ref', required=True, help='the reference DEX (the original build)')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    rep = report(args.dump, args.ref)
    if args.json:
        print(json.dumps(rep, default=str))
        return
    print('=== FIDELITY REPORT: %s vs %s ===' % (args.dump, args.ref))
    print('VERDICT: %s' % rep['verdict'])
    print('L0 bytes : dump %d B / ref %d B — identical: %s' % (
        rep['bytes']['dump_size'], rep['bytes']['ref_size'], rep['bytes']['identical']))
    print('L1 header: magic dump=%s ref=%s | strings %s | types %s | protos %s | fields %s | methods %s | classes %s'
          % (rep['header']['dump_magic'], rep['header']['ref_magic'],
             rep['header']['string_ids'], rep['header']['type_ids'], rep['header']['proto_ids'],
             rep['header']['field_ids'], rep['header']['method_ids'], rep['header']['class_defs']))
    c = rep['classes']
    print('L2 classes: common=%d dump=%d ref=%d | dump_only=%d ref_only=%d' % (
        c['common'], c['dump'], c['ref'], len(c['dump_only']), len(c['ref_only'])))
    s = rep['strings']
    print('L3 strings: dump_only=%d ref_only=%d' % (len(s['dump_only']), len(s['ref_only'])))
    if args.verbose or len(s['dump_only']) <= 12:
        for x in s['dump_only'][:12]:
            print('    + %r' % x)
        for x in s['ref_only'][:12]:
            print('    - %r' % x)
    m, f = rep['methods'], rep['fields']
    print('L4 method refs: dump_only=%d ref_only=%d | field refs: dump_only=%d ref_only=%d' % (
        len(m['dump_only']), len(m['ref_only']), len(f['dump_only']), len(f['ref_only'])))
    if args.verbose:
        for x in m['dump_only'][:10]:
            print('    +M %s' % (x,))
        for x in m['ref_only'][:10]:
            print('    -M %s' % (x,))
    mm = rep.get('members', {})
    if 'error' not in mm:
        rel = 'RELIABLE' if mm.get('reliable') else 'UNRELIABLE (039-family class_data: member walk incomplete)'
        print('L5 members: same=%d diff=%d — %s' % (mm['common_same'], mm['common_diff'], rel))
        if mm.get('diff_classes') and args.verbose and mm.get('reliable'):
            for n in mm['diff_classes']:
                print('    ! %s' % n)
    # loud warnings
    if c['ref_only']:
        print('WARNING: classes present in the REFERENCE but missing from the dump (app code lost):')
        for x in c['ref_only'][:10]:
            print('  !', x)
    if c['dump_only']:
        print('NOTE: classes in the dump not in the reference (shell runtime / pollution):')
        for x in c['dump_only'][:10]:
            print('  ?', x)


if __name__ == '__main__':
    main()
