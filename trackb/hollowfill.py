#!/usr/bin/env python3
"""Exuvia Track B: hollow native-stub auto-fill orchestrator (dex2c family).

A dex recovered from a shell container can still carry `native` hollow stubs —
the bodies live in the shell's .so as translated JNI C++, and repair surgery
removes that .so, so shipping the dex as-is dies with UnsatisfiedLinkError on
the first call (tosks device crash, 2026-10-22). This orchestrator refills
every native stub it can locate, one hollow dex in -> one all-Dalvik dex out:

  locate    static scan of the shell .so for the JNINativeMethod-like table:
            find the method-name string's VA reference at X, then validate
            content-wise (zero hardcoded layout): a pointer X+d1 whose target
            parses as the method's descriptor, and a pointer X+d2 landing in
            an executable PT_LOAD. Two layouts on record: (name,sig,fn) plain
            triple (stride 8) and the (ptr,aux,tag) row form (stride 0x18).
  trace     jnitrace.py per located function (--init --seed-dex --arms)
  synth     trace2smali.py per hollow class (--sigs-dex imports protos)
  assemble  baksmali the hollow dex, splice synthesized .method blocks over
            the native stubs (match on name+descriptor, extras appended),
            smali reassemble

Deps stay user-side (README_AGENT heavy-deps rule): unicorn for jnitrace;
baksmali/smali + dexlib2 jars under EXUVIA_DEXLIB (default
/workspace/tools/dexlib), invoked as plain -cp org.jf.* entrypoints.

Usage:
  python3 hollowfill.py hollow.dex --so shell_arm64.so --out filled.dex \
      [--seed-dex any_dump.dex] [--workdir /tmp/hf]

Stdout: one JSON report {filled, classes, located:{name+sig: va},
unlocated:[...], placeholders, notes}. Exit: 0 filled (unlocated may be
non-empty — caller decides); 2 dependency missing; 3 locate produced zero
entries; 4 assembly failed.
"""

import argparse
import glob
import json
import os
import re
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- dex parse

def _uleb(b, p):
    r = s = 0
    while True:
        v = b[p]; p += 1
        r |= (v & 0x7f) << s
        if not (v & 0x80):
            return r, p
        s += 7


def parse_dex_classes(dex):
    """DEX bytes -> {class_desc: {'super': desc, 'natives': {name: sig}}}.

    Only classes carrying at least one native method are kept — those are the
    hollow classes this tool exists for."""
    if dex[:4] != b'dex\n':
        raise ValueError('not a dex')
    string_ids_off = struct.unpack_from('<I', dex, 0x3c)[0]
    type_ids_off = struct.unpack_from('<I', dex, 0x44)[0]
    proto_ids_off = struct.unpack_from('<I', dex, 0x4c)[0]
    method_ids_off = struct.unpack_from('<I', dex, 0x5c)[0]
    class_defs_size, class_defs_off = struct.unpack_from('<II', dex, 0x60)

    def sget(i):
        p = struct.unpack_from('<I', dex, string_ids_off + i * 4)[0]
        while dex[p] & 0x80:
            p += 1
        p += 1
        return dex[p:dex.index(b'\x00', p)].decode('utf-8', 'replace')

    def tget(i):
        return sget(struct.unpack_from('<I', dex, type_ids_off + i * 4)[0])

    def sig_of(proto_idx):
        _shorty, ret, params_off = struct.unpack_from(
            '<III', dex, proto_ids_off + proto_idx * 12)
        params = ''
        if params_off:
            n = struct.unpack_from('<I', dex, params_off)[0]
            params = ''.join(tget(struct.unpack_from('<H', dex, params_off + 4 + 2 * k)[0])
                             for k in range(n))
        return '(' + params + ')' + tget(ret)

    out = {}
    for ci in range(class_defs_size):
        (class_idx, _acc, super_idx, _if, _src, _ann,
         class_data_off, _sv) = struct.unpack_from('<8I', dex, class_defs_off + ci * 32)
        cls = tget(class_idx)
        sup = tget(super_idx) if super_idx != 0xffffffff else 'Ljava/lang/Object;'
        natives = {}
        if class_data_off:
            p = class_data_off
            sf, p = _uleb(dex, p); inf, p = _uleb(dex, p)
            dm, p = _uleb(dex, p); vm, p = _uleb(dex, p)
            for _ in range(sf + inf):
                _, p = _uleb(dex, p); _, p = _uleb(dex, p)
            # method_idx_diff 按表重启：direct/virtual 两列表各自首项为绝对索引
            # （dex 格式事实——跨表累积会把 virtual 表索引全部带偏）
            for n_list in (dm, vm):
                prev = 0
                for _ in range(n_list):
                    diff, p = _uleb(dex, p); acc, p = _uleb(dex, p); _, p = _uleb(dex, p)
                    prev += diff
                    if acc & 0x100:  # ACC_NATIVE
                        _c, proto, name_i = struct.unpack_from('<HHI', dex, method_ids_off + prev * 8)
                        natives[sget(name_i)] = sig_of(proto)
        if natives:
            out[cls] = {'super': sup, 'natives': natives}
    return out


# ---------------------------------------------------------------- locate

def _loads(so):
    if so[:4] != b'\x7fELF' or so[4] != 2:
        raise ValueError('not an ELF64')
    phoff = struct.unpack_from('<Q', so, 0x20)[0]
    pnum = struct.unpack_from('<H', so, 0x38)[0]
    out = []
    for i in range(pnum):
        t, fl, o, v, _, fs, _, _ = struct.unpack_from('<IIQQQQQQ', so, phoff + i * 56)
        if t == 1:
            out.append((o, v, fs, fl))
    return out


def locate_table(so, wanted):
    """JNINativeMethod-like table scan. wanted: {name: sig}.
    Returns ({(name,sig): fn_va}, [unlocated names]).

    Zero hardcoded layout: a candidate is a file offset X holding the name
    string's VA; it validates iff within the next 0x40 bytes there is (i) a
    pointer to a string that parses as THIS method's descriptor and (ii) a
    pointer into an executable PT_LOAD. On record: plain (name,sig,fn) triple
    (+8/+0x10) and the (ptr,aux,tag) row form (+0x18/+0x30)."""
    loads = _loads(so)

    def off2va(off):
        for o, v, s, _ in loads:
            if o <= off < o + s:
                return v + (off - o)
        return None

    def va2off(va):
        for o, v, s, _ in loads:
            if v <= va < v + s:
                return o + (va - v)
        return None

    def cstr(va):
        off = va2off(va)
        if off is None or off >= len(so):
            return None
        end = so.find(b'\x00', off)
        if end < 0 or end - off > 200:
            return None
        try:
            return so[off:end].decode()
        except UnicodeDecodeError:
            return None

    execs = [(v, v + s) for o, v, s, f in loads if f & 1]

    def plaus_fn(va):
        # ARM64 函数指针机械判据：落在可执行 PT_LOAD、4B 对齐、越过文件头区
        # （段标志挡不住行结构里的 tag 小常量——本样本首段 R+X 覆盖表区，
        #   0x403 之类的行标签靠对齐+下限两条件排除）
        return (va >= 0x1000 and va & 3 == 0
                and any(a <= va < b for a, b in execs))

    def str_va(text):
        i = so.find(text.encode() + b'\x00')
        return off2va(i) if i >= 0 else None

    located, unlocated = {}, []
    for name, sig in wanted.items():
        nva = str_va(name)
        if nva is None:
            unlocated.append(name)
            continue
        pat = struct.pack('<Q', nva)
        fn = None
        i = so.find(pat)
        while i >= 0 and fn is None:
            # 窗口内找 (sig 指针, exec 指针) 对——descriptor 形态校验兜底
            for d1 in range(8, 0x41, 8):
                cand = struct.unpack_from('<Q', so, i + d1)[0] if i + d1 + 8 <= len(so) else 0
                if cstr(cand) != sig:
                    continue
                for d2 in range(d1 + 8, 0x49, 8):
                    f = struct.unpack_from('<Q', so, i + d2)[0] if i + d2 + 8 <= len(so) else 0
                    if plaus_fn(f):
                        fn = f
                        break
                if fn is not None:
                    break
            i = so.find(pat, i + 1)
        if fn is None:
            unlocated.append(name)
        else:
            located[(name, sig)] = fn
    return located, unlocated


# ---------------------------------------------------------------- subprocess

def _run(cmd, what):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError('%s failed (rc=%d): %s' % (what, r.returncode,
                                                      (r.stderr or r.stdout)[-400:]))
    return r


def _dexlib_dir():
    d = os.environ.get('EXUVIA_DEXLIB', '/workspace/tools/dexlib')
    jars = sorted(glob.glob(os.path.join(d, '*.jar')))
    if not any('baksmali' in j for j in jars) or not any('smali' in j for j in jars):
        raise FileNotFoundError(
            'baksmali/smali jars not found under %s (EXUVIA_DEXLIB)' % d)
    return d, ':'.join(jars)


# ---------------------------------------------------------------- splice

_METHOD_HEAD = re.compile(r'^\.method\s+.*?\s*(<?[\w$-]+>?)(\([^)]*\)\S+)\s*$')


def _blocks(lines):
    """split a smali file into (pre, [(head_line, block_lines)], post)."""
    pre, methods, post = [], [], []
    i = 0
    while i < len(lines) and not lines[i].startswith('.method'):
        pre.append(lines[i]); i += 1
    while i < len(lines):
        if lines[i].startswith('.method'):
            blk = [lines[i]]; i += 1
            while i < len(lines) and lines[i].strip() != '.end method':
                blk.append(lines[i]); i += 1
            blk.append(lines[i]); i += 1
            methods.append(blk)
        else:
            post.append(lines[i]); i += 1
    return pre, methods, post


def splice(class_smali, synth_inc):
    """Replace native stubs in class_smali with synthesized bodies.
    Match on (name, descriptor) — overload-safe. Synthesized methods with no
    stub counterpart are appended. Returns (text, replaced, added)."""
    with open(synth_inc) as f:
        synth = f.read()
    syn_blocks = [b.strip('\n') for b in synth.split('\n\n') if b.strip().startswith('.method')]
    by_key = {}
    for b in syn_blocks:
        m = _METHOD_HEAD.match(b.splitlines()[0])
        if not m:
            raise ValueError('synthesized block head unparsable: %r' % b.splitlines()[0])
        by_key[(m.group(1), m.group(2))] = b

    with open(class_smali) as f:
        lines = f.read().splitlines()
    pre, methods, post = _blocks(lines)
    replaced, added, used = 0, 0, set()
    out = list(pre)
    for blk in methods:
        m = _METHOD_HEAD.match(blk[0])
        key = (m.group(1), m.group(2)) if m else None
        if key in by_key:
            out.extend(by_key[key].splitlines())
            used.add(key)
            replaced += 1
        else:
            out.extend(blk)
    for key, b in by_key.items():
        if key not in used:
            out.append('')
            out.extend(b.splitlines())
            added += 1
    out.extend(post)
    return '\n'.join(out) + '\n', replaced, added


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('hollow', help='dex carrying native hollow stubs')
    ap.add_argument('--so', required=True, help='shell .so (arm64) holding the translated bodies')
    ap.add_argument('--out', required=True, help='filled dex output path')
    ap.add_argument('--seed-dex', action='append', default=[], metavar='DEX',
                    help='any dump for jnitrace --seed-dex (clinit statics)')
    ap.add_argument('--workdir', help='scratch dir (default: <out>.hf)')
    ap.add_argument('--no-arms', action='store_true', help='skip null-guard arm enumeration')
    args = ap.parse_args()

    report = {'filled': None, 'classes': {}, 'located': {}, 'unlocated': [],
              'notes': []}
    try:
        import unicorn  # noqa: F401 — jnitrace 的前置依赖，早报错
    except ImportError:
        print(json.dumps({'error': 'unavailable',
                          'detail': 'unicorn not installed (user-side dependency: pip install unicorn)'}))
        sys.exit(2)
    try:
        _, cp = _dexlib_dir()
    except FileNotFoundError as e:
        print(json.dumps({'error': 'unavailable', 'detail': str(e)}))
        sys.exit(2)

    dex = open(args.hollow, 'rb').read()
    so = open(args.so, 'rb').read()
    classes = parse_dex_classes(dex)
    if not classes:
        print(json.dumps({'error': 'no-hollow',
                          'detail': 'no native methods found — nothing to fill'}))
        sys.exit(3)

    work = args.workdir or args.out + '.hf'
    os.makedirs(work, exist_ok=True)
    smali_root = os.path.join(work, 'smali')
    traces = os.path.join(work, 'traces')
    os.makedirs(traces, exist_ok=True)

    # 1. locate：全类 native 集合一次静态表扫
    wanted = {}
    for cls, info in classes.items():
        for n, s in info['natives'].items():
            if n in wanted:
                report['notes'].append(
                    'overloaded/duplicate native name %s — trace naming is name-keyed, first wins' % n)
                continue
            wanted[n] = s
    located, unlocated = locate_table(so, wanted)
    report['unlocated'] = unlocated
    report['located'] = {'%s%s' % k: hex(v) for k, v in located.items()}
    if not located:
        print(json.dumps({'error': 'locate-failed',
                          'detail': 'no JNINativeMethod-like table entries matched',
                          'unlocated': unlocated}))
        sys.exit(3)

    # 2. trace：一次 jnitrace 跑全部定位到的函数
    fns, labels = [], []
    for (n, _s), va in sorted(located.items(), key=lambda kv: kv[1]):
        fns += ['--fn', hex(va)]
        labels += ['--label', n]
    cmd = [sys.executable, os.path.join(_HERE, 'jnitrace.py'), args.so] + fns + labels + \
        ['--init', '--out', traces]
    if not args.no_arms:
        cmd.append('--arms')
    for sd in args.seed_dex:
        cmd += ['--seed-dex', sd]
    # --this 取第一个 hollow 类（jnitrace 单 --this 契约；多类时按类分批）
    first_cls = next(iter(classes))
    cmd += ['--this', first_cls]
    _run(cmd, 'jnitrace')

    # 3. synth：逐 hollow 类 trace2smali
    per_class_inc = {}
    for cls, info in classes.items():
        inc = os.path.join(work, 'synth_%s.inc' % re.sub(r'[^\w]+', '_', cls))
        cmd = [sys.executable, os.path.join(_HERE, 'trace2smali.py'), traces,
               '--class', cls, '--super', info['super'],
               '--sigs-dex', args.hollow, '--out', inc]
        r = _run(cmd, 'trace2smali')
        per_class_inc[cls] = inc
        for line in (r.stderr or '').splitlines():
            if line.startswith('[note]'):
                report['notes'].append('%s %s' % (cls, line))

    # 4. assemble：baksmali → splice → smali
    _run(['java', '-cp', cp, 'org.jf.baksmali.Main', 'd', args.hollow,
          '-o', smali_root], 'baksmali')
    total_rep = total_add = 0
    for cls, inc in per_class_inc.items():
        rel = cls[1:-1] + '.smali'
        target = os.path.join(smali_root, rel)
        if not os.path.exists(target):
            print(json.dumps({'error': 'assemble-failed',
                              'detail': 'baksmali output misses %s' % rel}))
            sys.exit(4)
        text, rep, add = splice(target, inc)
        with open(target, 'w') as f:
            f.write(text)
        total_rep += rep; total_add += add
    _run(['java', '-cp', cp, 'org.jf.smali.Main', 'a', smali_root,
          '-o', args.out], 'smali')

    # 完整性回读：填后产物里 hollow 类不应再有 native 残留
    remaining = parse_dex_classes(open(args.out, 'rb').read())
    if remaining:
        report['remaining_hollow'] = {c: sorted(i['natives']) for c, i in remaining.items()}

    for cls in classes:
        report['classes'][cls] = len(classes[cls]['natives'])
    report['filled'] = args.out
    report['spliced'] = {'replaced': total_rep, 'added': total_add}
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
