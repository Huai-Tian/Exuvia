#!/usr/bin/env python3
"""Exuvia Track B: JNI-trace -> smali body synthesizer (de-native-ization).

jnitrace.py turns a native-ized method back into its behavioral skeleton (a
JNI call sequence with owners, signatures and argument values). This module
compiles that sequence into a straight-line Dalvik body in smali text form:

  AllocObject + <init>              -> new-instance + invoke-direct
  CallNonvirtual* on this           -> invoke-super {p0, params}
  CallObject/Int/Boolean/...Method* -> invoke-virtual + move-result
  CallStatic*                       -> invoke-static + move-result
  GetStatic*/SetStatic*Field        -> sget/sput
  Get*/Set*Field                    -> iget/iput
  NewStringUTF                      -> const-string
  numeric jvalues                   -> const/const4

Scope & honesty boundaries (format facts, not aspirations):
  - STRAIGHT-LINE bodies only: one emulation run walks one path; branches the
    trace never took are absent. Lifecycle/UI-boot methods are overwhelmingly
    straight-line — the class of methods this exists for.
  - Runtime-built strings the emulator could not materialize (encrypted config
    needing device state) surface as const-string "" — flagged in the report.
  - Return type V assumed unless the trace proves otherwise; wide returns
    rejected with a note.
  - A trace whose only substantive op is "ThrowNew NullPointerException" is a
    Kotlin Intrinsics null-check artifact of the emulator's null arguments —
    the synthesizer emits the contract body (super-call) instead.

Usage:
  python3 trace2smali.py traces_dir/ --class Ldetect/screenshot/MainActivity; \
      --super Lyg; --out synthesized.smali.inc
  python3 trace2smali.py traces_dir/ --class Lx; --super Ly; \
      --sigs-dex hollow.dex --out synthesized.smali.inc   # sigs from stubs
Output: one '.method' block per traced method, splice-ready over baksmali
hollow stubs (same name+signature).
"""

import argparse
import os
import re
import struct
import sys

WIDE = ('J', 'D')

# invoke-virtual on an interface method fails ART verification — JNI traces
# don't distinguish (CallBooleanMethodA works for both). JNI-level format fact:
# dispatch kind must come from the owner's flags, resolvable when the class is
# in the rebuilt dex (--dex) or in this framework-interface set.
KNOWN_INTERFACES = {
    'Landroid/content/SharedPreferences;', 'Landroid/content/SharedPreferences$Editor;',
    'Ljava/lang/Runnable;', 'Ljava/lang/Iterable;', 'Ljava/lang/Comparable;',
    'Ljava/lang/CharSequence;', 'Ljava/util/List;', 'Ljava/util/Map;',
    'Ljava/util/Set;', 'Ljava/util/Collection;', 'Ljava/util/Iterator;',
    'Ljava/util/Map$Entry;', 'Ljava/util/concurrent/Executor;',
}

# Name(0xADDR) [mid-text] -> 0xRET [desc]   (mid-text may be empty; the arrow
# split is greedy-safe because ret is a fixed-shape hex/0 group)
LINE_RE = re.compile(r'^(\w+)\((0x[0-9a-f]+)\)\s+(.*)\s*->\s+(0x[0-9a-f]+|0)(?:\s+(.*))?$')
ARGS_RE = re.compile(r'args=\[(.*?)\]')
REF_RE = re.compile(r'(mid|fid|smid|sfid):class:(.*?)->(.*)$')


def parse_sig(sig):
    """'(IILmw;)V' -> (['I','I','Lmw;'], 'V')"""
    inner = sig[sig.index('(') + 1:sig.index(')')]
    ret = sig[sig.index(')') + 1:]
    out, i = [], 0
    while i < len(inner):
        c = inner[i]
        if c == 'L':
            j = inner.index(';', i); out.append(inner[i:j + 1]); i = j + 1
        elif c == '[':
            j = i
            while inner[j] == '[':
                j += 1
            if inner[j] == 'L':
                j = inner.index(';', j)
            out.append(inner[i:j + 1]); i = j + 1
        else:
            out.append(c); i += 1
    return out, ret


def parse_ref(tokdesc):
    """'class:sn->D()V' / 'class:sn->TZ' -> ('Lsn;', 'D', '()V') / ('Lsn;', 'T', 'Z').
    Field form: name and single-letter type are concatenated after '->'."""
    m = REF_RE.match(tokdesc)
    if not m:
        return None
    _kind, owner, rest = m.groups()
    owner = owner if owner.startswith('L') else 'L' + owner + ';'
    if '(' in rest:  # method
        name = rest[:rest.index('(')]
        sig = rest[rest.index('('):]
        return owner, name, sig
    t = re.match(r'^(.*?)(L[^;]*;|\[.*|[ZBCSIJFD])$', rest)
    if not t:
        return None
    return owner, t.group(1), t.group(2)


class RegFile:
    def __init__(self):
        self.next = 0
        self.map = {}       # key -> vN (int)
        self.reg_ty = {}

    def alloc(self, key, ty=None):
        if key in self.map:
            return self.map[key]
        r = self.next
        self.next += 1
        self.map[key] = r
        if ty:
            self.reg_ty[r] = ty
        return r

    def get(self, key):
        return self.map.get(key)


def split_args(s):
    if not s or not s.strip():
        return []
    out, cur = [], ''
    for ch in s:
        if ch == ',':
            out.append(cur.strip()); cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def synth(trace_path, mname, msig, super_cls, cls=None):
    lines = [l.rstrip('\n') for l in open(trace_path)]
    ops = []
    for l in lines:
        m = LINE_RE.match(l)
        if m:
            ops.append(m)

    substantive = [m for m in ops if m.group(1) not in
                   ('NewLocalRef', 'NewGlobalRef', 'DeleteLocalRef', 'DeleteGlobalRef',
                    'ExceptionCheck', 'FindClass', 'GetMethodID', 'GetFieldID',
                    'GetStaticMethodID', 'GetStaticFieldID', 'IsInstanceOf')]
    if (any('ThrowNew' in m.group(1) for m in substantive) and
            not any(m.group(1).startswith('Call') for m in substantive)):
        return {'contract_only': True, 'notes': ['kotlin null-check artifact -> contract body']}

    params, ret_ty = parse_sig(msig)
    # Dalvik 35c (invoke list) and 22c (iget/iput) forms carry registers in
    # 4-bit nibbles — v0-v15 only. Reserve a low scratch band v0..v{SCRATCH-1};
    # every invoke/iget/iput copies operands there via move*/from16, leaving
    # token registers free to grow past v15. invoke*/range kicks in at arity>5.
    max_arity = 2
    for m0 in ops:
        nm0 = m0.group(1)
        if nm0.startswith('Call'):
            am0 = ARGS_RE.search(m0.group(3))
            na0 = len(split_args(am0.group(1))) if am0 else 0
            if nm0.startswith('CallStatic'):
                ar0 = na0
            elif nm0.startswith('CallNonvirtual'):
                ar0 = len(params) + 1
            else:
                ar0 = na0 + 1
            max_arity = max(max_arity, ar0)
    SCRATCH = max_arity
    rf = RegFile()
    rf.next = SCRATCH
    body = []
    notes = []
    this_addr = None
    alloc_ty = {}    # ret-addr -> class type (AllocObject awaiting <init>)
    ns_ctr = [0]         # null-static-read counter (fresh register keys)
    nullstatic = [None]  # (vreg, field type) of the last null static read

    def preg(k):
        return f'p{k}'

    def vreg_of(addr, ty=None):
        return rf.alloc('a' + addr, ty)

    def reg_label(addr, ty=None):
        if this_addr and addr == this_addr:
            return 'p0'
        return f'v{vreg_of(addr, ty)}'

    def emit_value(tok, ty, argaddr=None):
        """tok: an args[] element — number / null / token-desc. Returns reg label."""
        if tok in ('null', '0', '0x0'):
            # A static object field the tracer never saw written reads back
            # null in the trace; downstream uses of that value ALSO print as
            # null. Rebind them to the field's sget register — but only when
            # the parameter type matches the field type exactly (obfuscated
            # dexes pass the field itself). The type gate is what tells this
            # zero from a genuine null literal, and it keeps the verifier
            # safe by construction (a bound register always satisfies the
            # parameter type).
            if nullstatic[0] and ty.startswith(('L', '[')) and nullstatic[0][1] == ty:
                return f'v{nullstatic[0][0]}'
            key = 'zero:' + ('Z' if ty == 'Z' else 'o')
            r = rf.get(key)
            if r is None:
                r = rf.alloc(key)
                body.append(f"    {'const/4' if r <= 15 else 'const/16'} v{r}, 0x0")
            return f'v{r}'
        # hex/decimal literal — jvalue ints print as-is (e.g. '0x1'); they are
        # NOT addresses. Addresses in the fake world are >= 0x100000 (heap
        # 0x5000_0000_0000, sentinels 0x51E0_0000) and always trace-produced.
        mnum = re.fullmatch(r'-?(0x[0-9a-fA-F]+|\d+)', tok)
        if mnum and (tok.lstrip('-').isdigit() or int(tok, 0) < 0x100000):
            v = int(tok, 0)
            if ty == 'Z':
                v &= 1
            key = f'c{v}:{ty if ty in "ZBCSIJ" else "I"}'
            r = rf.get(key)
            if r is None:
                r = rf.alloc(key, ty)
                lit = hex(v) if v >= 0 else '-0x%x' % -v
                if -8 <= v <= 7 and r <= 15:
                    body.append(f'    const/4 v{r}, {lit}')
                elif -32768 <= v <= 32767:
                    body.append(f'    const/16 v{r}, {lit}')
                else:
                    body.append(f'    const v{r}, {lit}')
            return f'v{r}'
        # object token '0xADDR=desc' or bare '0xADDR' — key on the address
        maddr = re.match(r'(0x[0-9a-f]+)(?:=(.*))?$', tok)
        if maddr:
            addr = maddr.group(1)
            if addr == '0x0':
                key = 'zero:o'
                r = rf.get(key)
                if r is None:
                    r = rf.alloc(key)
                    body.append(f"    {'const/4' if r <= 15 else 'const/16'} v{r}, 0x0")
                return f'v{r}'
            if this_addr and addr == this_addr:
                return 'p0'
            r = rf.get('a' + addr)
            if r is not None:
                return f'v{r}'
            # fallthrough: token referenced but never produced in this trace —
            # emitting a bare register reference here synthesizes an UNDEFINED
            # register and ART rejects the class (VerifyError copy1 vN<-vM).
            notes.append(f'untracked token {tok!r} ({ty}) -> null')
        else:
            notes.append(f'unresolved value token {tok!r} ({ty}) -> null')
        key = 'zero:o'
        r = rf.get(key)
        if r is None:
            r = rf.alloc(key)
            body.append(f"    {'const/4' if r <= 15 else 'const/16'} v{r}, 0x0")
        return f'v{r}'

    def emit_invoke(kind, pairs, target, this_cast=None):
        """pairs: [(label, ty), ...] including implicit 'this' for non-static.
        this_cast: owner class of the callee — when the traced producer gave
        the receiver a DIFFERENT declared type (e.g. getDecorView():View vs
        ViewGroup.addView), the register's inferred type won't satisfy the
        verifier; insert check-cast (sound: GetMethodID succeeded at runtime,
        so the object IS an instance of the owner class)."""
        n = len(pairs)
        if n == 0:
            body.append(f'    {kind} {{}}, {target}')
            return
        for i, (lab, ty) in enumerate(pairs):
            mv = 'move-object/from16' if ty.startswith(('L', '[')) else 'move/from16'
            body.append(f'    {mv} v{i}, {lab}')
            if i == 0 and this_cast and ty.startswith('L') and ty != this_cast:
                body.append(f'    check-cast v{i}, {this_cast}')
        regs = ', '.join(f'v{i}' for i in range(n))
        if n <= 5:
            body.append(f'    {kind} {{{regs}}}, {target}')
        else:
            body.append(f'    {kind}/range {{v0 .. v{n - 1}}}, {target}')

    def emit_iget(op, dest_r, obj_lab, fieldref, fty):
        body.append(f'    move-object/from16 v1, {obj_lab}')
        body.append(f'    {op} v0, v1, {fieldref}')
        mv = 'move-object/from16' if fty.startswith(('L', '[')) else 'move/from16'
        body.append(f'    {mv} v{dest_r}, v0')

    def emit_iput(op, val_lab, val_ty, obj_lab, fieldref):
        mv = 'move-object/from16' if val_ty.startswith(('L', '[')) else 'move/from16'
        body.append(f'    {mv} v0, {val_lab}')
        body.append(f'    move-object/from16 v1, {obj_lab}')
        body.append(f'    {op} v0, v1, {fieldref}')

    for m in ops:
        name, x1, midtxt, retaddr, retdesc = m.groups()
        reftok = midtxt.split(' args=')[0].strip()
        am = ARGS_RE.search(midtxt)
        argstr = am.group(1) if am else None

        if name == 'NewLocalRef' and retdesc and not retdesc.startswith(('0x', 'class:')) and retdesc.startswith('L'):
            # the first NewLocalRef carrying a 'L...;' desc is `this`
            if this_addr is None and retdesc.endswith(';'):
                this_addr = retaddr
                rf.alloc('a' + retaddr)  # reserve identity (mapped to p0 via reg_label)
            continue
        if name in ('NewLocalRef', 'NewGlobalRef', 'DeleteLocalRef', 'DeleteGlobalRef',
                    'ExceptionCheck', 'FindClass', 'GetMethodID', 'GetFieldID',
                    'GetStaticMethodID', 'GetStaticFieldID', 'IsInstanceOf', 'GetObjectClass'):
            continue

        if name == 'AllocObject':
            if retdesc and retdesc.startswith('alloc:class:'):
                ty = 'L' + retdesc[len('alloc:class:'):] + ';'
                alloc_ty[retaddr] = ty
                rf.alloc('a' + retaddr, ty)
            continue

        if name == 'NewStringUTF':
            sm = re.search(r'"(.*?)"', midtxt)
            content = sm.group(1) if sm else ''
            if content == '':
                notes.append('runtime-string not materialized -> const-string ""')
            r = vreg_of(retaddr, 'Ljava/lang/String;')
            esc = content.replace('\\', '\\\\').replace('"', '\\"')
            body.append(f'    const-string v{r}, "{esc}"')
            continue

        if name.startswith('GetStatic') and 'Field' in name:
            ref = parse_ref(reftok)
            if not ref:
                continue
            owner, fname, fsig = ref
            if retaddr in ('0', '0x0'):
                # Null in the fake world (static object field never written in
                # this run). Keep the sget — it carries the class-init side
                # effect and yields the register that type-matched downstream
                # nulls rebind to. A FRESH key is mandatory: the shared 'a0'
                # key would alias every null static read to one register and
                # silently drop later sgets.
                ns_ctr[0] += 1
                r = rf.alloc('ns%d' % ns_ctr[0], fsig)
                nullstatic[0] = (r, fsig) if fsig.startswith(('L', '[')) else None
                notes.append(f'static field {owner}->{fname}:{fsig} null in trace '
                             f'(never written in run) — sget kept, type-gated binding armed')
            else:
                r = vreg_of(retaddr, fsig)
            op = 'sget-object' if fsig.startswith(('L', '[')) else 'sget'
            body.append(f'    {op} v{r}, {owner}->{fname}:{fsig}')
            continue

        if name.startswith('Get') and 'Field' in name and not name.startswith('GetStatic'):
            ref = parse_ref(reftok)
            if not ref:
                continue
            owner, fname, fsig = ref
            r = vreg_of(retaddr, fsig)
            op = 'iget-object' if fsig.startswith(('L', '[')) else 'iget'
            emit_iget(op, r, reg_label(x1), f'{owner}->{fname}:{fsig}', fsig)
            continue

        if name.startswith('SetStatic') and 'Field' in name:
            # Static writes have NO object register — the instance iput path
            # would burn the class token as the object. sput is 22c: one
            # 4-bit value register + 16-bit field ref, so the value goes
            # through the v0 scratch slot like iget/iput operands do.
            vm = re.search(r'\s=\s(0x[0-9a-f]+|\d+)(?:=\S*)?\s*$', midtxt)
            val = vm.group(1) if vm else '0'
            reftok2 = midtxt[:vm.start()] if vm else reftok
            ref = parse_ref(reftok2.strip())
            if not ref:
                continue
            owner, fname, fsig = ref
            rv = emit_value(val, fsig)
            op = ('sput-object' if fsig.startswith(('L', '['))
                  else 'sput-boolean' if fsig == 'Z' else 'sput')
            mv = 'move-object/from16' if fsig.startswith(('L', '[')) else 'move/from16'
            body.append(f'    {mv} v0, {rv}')
            body.append(f'    {op} v0, {owner}->{fname}:{fsig}')
            continue

        if name.startswith('Set') and 'Field' in name:
            vm = re.search(r'\s=\s(0x[0-9a-f]+|\d+)(?:=\S*)?\s*$', midtxt)
            val = vm.group(1) if vm else '0'
            reftok2 = midtxt[:vm.start()] if vm else reftok
            ref = parse_ref(reftok2.strip())
            if not ref:
                continue
            owner, fname, fsig = ref
            rv = emit_value(val, fsig)
            op = ('iput-object' if fsig.startswith(('L', '['))
                  else 'iput-boolean' if fsig == 'Z' else 'iput')
            emit_iput(op, rv, fsig, reg_label(x1), f'{owner}->{fname}:{fsig}')
            continue

        if name.startswith('Call'):
            ref = parse_ref(reftok)
            args = split_args(argstr) if argstr is not None else []
            if ref is None:
                # CallNonvirtual lines carry only 'class:X' — the method is the
                # traced method itself (super call of the same signature)
                if name.startswith('CallNonvirtual'):
                    owner, mnm, csig = super_cls, mname, msig
                else:
                    notes.append(f'unparseable call target {reftok!r} — skipped')
                    continue
            else:
                owner, mnm, csig = ref
            cparams, cret = parse_sig(csig)
            if cret in WIDE:
                notes.append(f'wide return unsupported: {mnm}{csig}')
                continue
            arg_labels = []
            for k, a in enumerate(args):
                ty = cparams[k] if k < len(cparams) else 'I'
                arg_labels.append(emit_value(a, ty))
            arg_tys = [cparams[k] if k < len(cparams) else 'I' for k in range(len(arg_labels))]
            if name.startswith('CallNonvirtual'):
                pairs = [('p0', 'L')] + [(preg(k + 1), params[k]) for k in range(len(params))]
                emit_invoke('invoke-super', pairs, f'{super_cls}->{mnm}{csig}')
            elif name.startswith('CallStatic'):
                emit_invoke('invoke-static', list(zip(arg_labels, arg_tys)), f'{owner}->{mnm}{csig}')
            else:
                if mnm == '<init>':
                    ty = alloc_ty.get(x1) or owner
                    body.append(f'    new-instance {reg_label(x1, ty)}, {ty}')
                    emit_invoke('invoke-direct', [(reg_label(x1), 'L')] + list(zip(arg_labels, arg_tys)),
                                f'{ty}-><init>{csig}')
                else:
                    op = 'invoke-interface' if owner in KNOWN_INTERFACES else 'invoke-virtual'
                    x1_ty = (cls if (this_addr and x1 == this_addr)
                             else rf.reg_ty.get(rf.map.get('a' + x1)))
                    emit_invoke(op, [(reg_label(x1), x1_ty or owner)] + list(zip(arg_labels, arg_tys)),
                                f'{owner}->{mnm}{csig}', this_cast=owner)
            if cret != 'V' and mnm != '<init>':
                r = vreg_of(retaddr, cret)
                op = 'move-result-object' if cret.startswith(('L', '[')) else 'move-result'
                body.append(f'    {op} v{r}')
            continue

    return {'contract_only': False, 'body': body, 'notes': notes, 'n_regs': rf.next}


def render(mname, msig, res, super_cls):
    params, ret = parse_sig(msig)
    if res.get('contract_only'):
        pregs = ', '.join(f'p{k}' for k in range(len(params) + 1))
        return '\n'.join([
            f'.method public final {mname}{msig}',
            '    .locals 0',
            f'    invoke-super {{{pregs}}}, {super_cls}->{mname}{msig}',
            '    return-void',
            '.end method'])
    lines = [f'.method public final {mname}{msig}', f'    .locals {res["n_regs"]}']
    lines += res['body']
    lines.append('    return-void')
    lines.append('.end method')
    return '\n'.join(lines)


def extract_native_sigs(dex, cls_desc):
    """DEX bytes -> {name: descriptor} for native methods of cls_desc.

    The hollow stub dex carries the translated methods as native stubs with
    their original protos — exactly the signature set jnitrace can have
    traced. Zero-sample: no hardcoded names; overloads (same name, several
    protos) keep the first — the {name: sig} map shape can't hold more.
    """
    if dex[:4] != b'dex\n':
        return {}
    ssz, soff = struct.unpack_from('<II', dex, 0x38)
    tsz, toff = struct.unpack_from('<II', dex, 0x40)
    psz, poff = struct.unpack_from('<II', dex, 0x48)
    msz, moff = struct.unpack_from('<II', dex, 0x58)
    csz, coff = struct.unpack_from('<II', dex, 0x60)

    def string(i):
        o = struct.unpack_from('<I', dex, soff + i * 4)[0]
        p = o
        while dex[p] & 0x80:
            p += 1
        p += 1
        e = dex.index(b'\x00', p)
        return dex[p:e].decode('utf-8', 'replace')

    def tname(i):
        return string(struct.unpack_from('<I', dex, toff + i * 4)[0])

    def proto_desc(i):
        _shorty, ret, params_off = struct.unpack_from('<III', dex, poff + i * 12)
        out = ['(']
        if params_off:
            n = struct.unpack_from('<I', dex, params_off)[0]
            for k in range(n):
                out.append(tname(struct.unpack_from('<H', dex, params_off + 4 + k * 2)[0]))
        out.append(')')
        out.append(tname(ret))
        return ''.join(out)

    def uleb(p):
        r = s = 0
        while True:
            b = dex[p]
            p += 1
            r |= (b & 0x7F) << s
            if not b & 0x80:
                return r, p
            s += 7

    for ci in range(csz):
        cidx = struct.unpack_from('<I', dex, coff + ci * 32)[0]
        if tname(cidx) != cls_desc:
            continue
        cdata = struct.unpack_from('<I', dex, coff + ci * 32 + 24)[0]
        if not cdata:
            break
        p = cdata
        nsf, p = uleb(p)
        nif, p = uleb(p)
        ndm, p = uleb(p)
        nvm, p = uleb(p)
        for _ in range(nsf + nif):
            _, p = uleb(p)
            _, p = uleb(p)
        out = {}
        for nm_ in (ndm, nvm):
            midx = 0  # each method list restarts with an absolute index diff
            for _ in range(nm_):
                d_, p = uleb(p)
                midx += d_
                flags, p = uleb(p)
                _code, p = uleb(p)
                if flags & 0x100 and midx < msz:  # ACC_NATIVE
                    _c, proto_i, name_i = struct.unpack_from('<HHI', dex, moff + midx * 8)
                    out.setdefault(string(name_i), proto_desc(proto_i))
        return out
    return {}


def main():
    ap = argparse.ArgumentParser(description='Compile jnitrace JNI traces into smali bodies')
    ap.add_argument('traces', help='directory with trace_<name>.txt files')
    ap.add_argument('--class', dest='cls', required=True)
    ap.add_argument('--super', dest='sup', required=True)
    ap.add_argument('--sigs', help='JSON {name: signature}; defaults cover the lifecycle set')
    ap.add_argument('--sigs-dex', action='append', default=[], metavar='DEX',
                    help='hollow stub dex(es): import {name: descriptor} of the '
                    'native methods of --class (translated methods keep their '
                    'original protos in the stubs). Merges over the built-in '
                    'defaults; --sigs JSON still wins on conflicts; repeatable')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    sigs = {
        'onCreate': '(Landroid/os/Bundle;)V', 'onDestroy': '()V', 'onResume': '()V',
        'onStop': '()V', 'onWindowFocusChanged': '(Z)V',
        'onMultiWindowModeChanged': '(ZLandroid/content/res/Configuration;)V',
        'onPictureInPictureModeChanged': '(ZLandroid/content/res/Configuration;)V',
    }
    for dex_path in args.sigs_dex:
        got = extract_native_sigs(open(dex_path, 'rb').read(), args.cls)
        sigs.update(got)
        print(f'[sigs-dex] {dex_path}: {len(got)} native signature(s) of {args.cls}',
              file=sys.stderr)
    if args.sigs:
        import json
        sigs.update(json.load(open(args.sigs)))

    blocks = []
    for fn in sorted(os.listdir(args.traces)):
        if not fn.startswith('trace_'):
            continue
        mname = fn[6:-4]
        msig = sigs.get(mname)
        if not msig:
            print(f'[skip] no signature for {mname}', file=sys.stderr)
            continue
        res = synth(os.path.join(args.traces, fn), mname, msig, args.sup, cls=args.cls)
        blocks.append(render(mname, msig, res, args.sup))
        for n in res.get('notes', []):
            print(f'[note] {mname}: {n}', file=sys.stderr)
        print(f'[synth] {mname}{msig}: ' + ('contract body' if res.get('contract_only')
                                           else f"{len(res['body'])} insns"), file=sys.stderr)
    with open(args.out, 'w') as f:
        f.write('\n\n'.join(blocks) + '\n')
    print(f'-> {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
