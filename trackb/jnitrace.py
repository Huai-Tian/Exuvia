#!/usr/bin/env python3
"""Exuvia Track B: JNI-semantics tracer for native-ized app methods.

Some shells don't extract method bodies into a store — they TRANSLATE them
into JNI C++ (then usually flatten the CFG). The original Dalvik bytecode is
nowhere in the package, so no static search can recover it. But the semantics
survive: every translated body is a sequence of JNI calls. This module runs
such a native function under the trackb emulator with a fully-tracing fake
JNIEnv and records the JNI call sequence, which IS the original method's
behavioral skeleton (super-call, field r/w, object construction, invoke
chain). Feed the trace to a synthesizer (or a human) to rebuild an equivalent
Dalvik body.

Family-agnostic: no sample-specific values — the function address is a CLI
argument, the JNIEnv world follows the JNI 1.6 spec (233-slot table).

Usage:
  python3 jnitrace.py shell.so --fn 0x98408 --label onCreate
  python3 jnitrace.py shell.so --fn 0x98408 --fn 0x9bae0 --out traces/
  python3 jnitrace.py shell.so --fn 0x98408 --seed-dex dump.dex   # clinit seed
  python3 jnitrace.py shell.so --fn 0x98408 --arms --out traces/  # fork null arms

Exit codes: 0 = trace captured; 2 = unicorn missing; 3 = ELF parse error.
"""

import argparse
import importlib.util
import json
import os
import struct
import sys

_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'so_emulator.py')
spec = importlib.util.spec_from_file_location('emu_base', _BASE)
emu_base = importlib.util.module_from_spec(spec)
sys.modules['emu_base'] = emu_base
try:
    spec.loader.exec_module(emu_base)  # main() is __name__-guarded
except SystemExit:
    pass

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_FP, UC_ARM64_REG_LR,
        UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0,
    )
except ImportError:
    print('{"error":"unavailable","detail":"unicorn not installed (user-side dependency)"}')
    sys.exit(2)

PAGE = 0x1000
STACK, STACKSZ = 0x7F0000000000, 0x400000
HEAP, HEAPSZ = 0x500000000000, 0x8000000
TLS = 0x510000000000
STUB = 0x600000000000
STUBSZ = 0x10000
JNIF = 0x620000000000

# JNI 1.6 JNINativeInterface slot names (spec order; index = slot number)
JNI_SLOTS = [
    "reserved0", "reserved1", "reserved2", "reserved3",
    "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField",
    "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw",
    "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError",
    "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
    "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject",
    "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf",
    "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA", "CallBooleanMethod",
    "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
    "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV",
    "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod",
    "CallLongMethodV", "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA",
    "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV",
    "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV",
    "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV",
    "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV",
    "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV",
    "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV",
    "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV",
    "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV",
    "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV",
    "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV",
    "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV",
    "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField",
    "GetCharField", "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField",
    "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField",
    "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID",
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA",
    "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
    "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
    "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod",
    "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV",
    "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV",
    "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
    "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField",
    "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField",
    "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField",
    "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString",
    "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength",
    "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray",
    "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray",
    "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements",
    "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements",
    "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion",
    "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion",
    "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
    "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion",
    "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives",
    "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
    "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
    "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
    "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
    "GetObjectRefType",
]

VOID_CALLS = {61, 62, 63, 91, 92, 93, 141, 142, 143}      # Call*VoidMethod family
OBJ_CALLS = {34, 35, 36, 64, 65, 66, 114, 115, 116}       # object-returning Call family
ID_GETTERS = {33: 'mid', 94: 'fid', 113: 'smid', 144: 'sfid'}


class Tracer:
    """Token-passing fake world: every returned jobject is a labelled token so
    later calls print 'ret:mid:getWindow()...' instead of a bare address."""

    def __init__(self, uc):
        self.uc = uc
        self.next_tok = 0x1000
        self.toks = {}
        self.trace = []
        self.sent_ctr = 0x51E00000   # sentinel base for primitive JNI results
        self.sent = {}               # sentinel -> producer description
        self.sstatic = {}            # static-object field key -> written token
        self.null_tokens = set()     # tok() hands these out as 0 (flipped-arm runs)
        self.seed_tokens = set()     # clinit seeds: device-true non-null, never forked
        self.guards = []             # null-guard points on fake tokens (--arms)
        self._guard_seen = set()

    def sentinel(self, producer):
        """Numeric JNI results (Get*Field/CallInt/...) must be UNIQUE tokens:
        a fixed value (0/34) silently merges distinct dataflow edges and
        hardcodes fake constants into any downstream synthesis."""
        self.sent_ctr += 0x10
        self.sent[self.sent_ctr] = producer
        return self.sent_ctr

    def tok(self, desc):
        t = HEAP + self.next_tok
        self.next_tok += 0x10
        self.toks[t] = desc
        if t in self.null_tokens:
            # flipped arm: this producer's result is null on the explored path
            # (allocation order is deterministic, so the token identity is
            # stable across re-runs up to the guard that consumes it)
            return 0
        return t

    def cstr(self, a):
        try:
            return bytes(self.uc.mem_read(a, 256)).split(b'\0')[0].decode('utf-8', 'replace')
        except Exception:
            return '?'

    def desc(self, t):
        return self.toks.get(t, hex(t) if t else 'null')

    @staticmethod
    def sig_params(sig):
        """'(IILmw;)V' -> ['I','I','Lmw;']"""
        try:
            inner = sig[sig.index('(') + 1:sig.index(')')]
        except ValueError:
            return []
        out, i = [], 0
        while i < len(inner):
            c = inner[i]
            if c == 'L':
                j = inner.index(';', i)
                out.append(inner[i:j + 1]); i = j + 1
            elif c == '[':
                j = i
                while inner[j] == '[':
                    j += 1
                if inner[j] == 'L':
                    j = inner.index(';', j)
                out.append(inner[i:j + 1]); i = j + 1
            else:
                out.append(c); i += 1
        return out

    def jvals(self, mid_tok, arr):
        """Parse a jvalue[] per the mid/smid token's signature."""
        desc = self.toks.get(mid_tok, '')
        if ':' not in desc or not arr:
            return ''
        params = self.sig_params(desc.split(':', 1)[1])
        vals = []
        for k, ty in enumerate(params):
            try:
                raw = struct.unpack('<Q', bytes(self.uc.mem_read(arr + k * 8, 8)))[0]
            except Exception:
                vals.append('?')
                continue
            if ty in 'ZBCSIJ':
                if raw in self.sent:
                    vals.append(f'{hex(raw)}={self.sent[raw]}')
                else:
                    vals.append(str(raw & 0xFFFFFFFFFFFFFFFF if ty == 'J' else raw & 0xFFFFFFFF))
            elif ty in 'FD':
                vals.append(hex(raw))
            else:
                vals.append('null' if raw == 0 else f'{hex(raw)}={self.desc(raw)}')
        return ', '.join(vals)


# --- clinit static-object-field seed scan (--seed-dex) ----------------------
#
# The fake-world null policy for static OBJECT fields ("never written in this
# run -> null") is the device truth for method-lazy fields (er.c) but LIES
# for fields the class's own <clinit> initializes: clinit has already run by
# the time any traced method executes, so those reads are non-null on device
# (device-verified inverse-amputation: zg.a LayoutParams, clinit-written,
# read null in trace -> the translated guard steered off the device path).
# The seed set is DERIVABLE FROM ANY DUMP DEX — no operator knowledge: scan
# every <clinit> for sput-object targets and pre-seed them. Fields a method
# writes in-run still override the seed via the normal write path.

_SEED_TOKEN_BASE = 0x5000000000F0  # below the tracer heap/token start


def _uleb(d, p):
    r = s = 0
    while True:
        b = d[p]
        p += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, p
        s += 7


def scan_clinit_object_seeds(dex):
    """dex bytes -> {seed_key: token} for every static object field any
    <clinit> writes via sput-object. Seed key matches the tracer's field
    descriptor form 'sfid:class:OWNER->NAMESIG' (both the 'zg' and 'Lzg;'
    owner spellings are registered — translators vary)."""
    import struct as _s
    if dex[:4] != b'dex\n':
        return {}
    ssz, soff = _s.unpack_from('<II', dex, 0x38)
    tsz, toff = _s.unpack_from('<II', dex, 0x40)
    fsz, foff = _s.unpack_from('<II', dex, 0x50)
    msz, moff = _s.unpack_from('<II', dex, 0x58)
    csz, coff = _s.unpack_from('<II', dex, 0x60)

    def string(i):
        o = _s.unpack_from('<I', dex, soff + i * 4)[0]
        _, p = _uleb(dex, o)
        e = dex.index(b'\x00', p)
        return dex[p:e].decode('utf-8', 'replace')

    def tname(i):
        return string(_s.unpack_from('<I', dex, toff + i * 4)[0])

    # Dalvik opcode -> length in 16-bit units (formats with variable payloads
    # handled in the walk). Only exactness matters; unknown -> abort method.
    LEN = {}
    for op in range(0x100):
        LEN[op] = 1
    for op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1F, 0x20,
               0x22, 0x23, 0x29, 0xFE, 0xFF):
        LEN[op] = 2
    for op in range(0x2D, 0x3E):
        LEN[op] = 2
    for op in range(0x44, 0x60):
        LEN[op] = 2
    for op in range(0x60, 0x6E):
        LEN[op] = 2
    for op in range(0x90, 0xB0):
        LEN[op] = 2
    for op in range(0xD0, 0xE3):
        LEN[op] = 2
    for op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A,
               0x2B, 0x2C, 0xFC, 0xFD):
        LEN[op] = 3
    for op in range(0x6E, 0x73):
        LEN[op] = 3
    for op in range(0x74, 0x79):
        LEN[op] = 3
    LEN[0x18] = 5
    LEN[0xFA] = LEN[0xFB] = 4

    seeds = {}
    for ci in range(csz):
        off = coff + ci * 32
        cdata = _s.unpack_from('<I', dex, off + 24)[0]
        if not cdata:
            continue
        p = cdata
        nsf, p = _uleb(dex, p)
        nif, p = _uleb(dex, p)
        ndm, p = _uleb(dex, p)
        nvm, p = _uleb(dex, p)
        for _ in range(nsf + nif):
            _, p = _uleb(dex, p)
            _, p = _uleb(dex, p)
        # direct_methods and virtual_methods are separate sorted lists; each
        # restarts with an ABSOLUTE method_idx diff (no cross-list chaining).
        for nm_ in (ndm, nvm):
            midx = 0
            for _ in range(nm_):
                d_, p = _uleb(dex, p)
                midx += d_
                _fl, p = _uleb(dex, p)
                code_off, p = _uleb(dex, p)
                if midx >= msz:
                    break  # anomalous class in the dump — abandon it, keep scanning
                name_i = _s.unpack_from('<I', dex, moff + midx * 8 + 4)[0]
                if (string(name_i) != '<clinit>' or not code_off
                        or code_off + 16 > len(dex)):
                    continue
                insns_size = _s.unpack_from('<I', dex, code_off + 12)[0]
                if insns_size > (len(dex) - code_off - 16) // 2:
                    continue
                base = code_off + 16
                pos = 0
                while pos < insns_size:
                    unit = _s.unpack_from('<H', dex, base + pos * 2)[0]
                    op = unit & 0xFF
                    if op == 0 and unit == 0 and pos + 1 < insns_size:
                        sig = _s.unpack_from('<H', dex, base + (pos + 1) * 2)[0]
                        if sig == 0x0100:  # packed-switch payload
                            size = _s.unpack_from('<H', dex, base + (pos + 2) * 2)[0]
                            pos += 4 + size * 2
                            continue
                        if sig == 0x0200:  # sparse-switch payload
                            size = _s.unpack_from('<H', dex, base + (pos + 2) * 2)[0]
                            pos += 2 + size * 4
                            continue
                        if sig == 0x0300:  # fill-array-data payload
                            w = _s.unpack_from('<H', dex, base + (pos + 2) * 2)[0]
                            size = _s.unpack_from('<I', dex, base + (pos + 4) * 2)[0]
                            pos += 4 + (w * size + 1) // 2
                            continue
                    if op == 0x69 and pos + 1 < insns_size:  # sput-object (21c)
                        fi = _s.unpack_from('<H', dex, base + (pos + 1) * 2)[0]
                        if fi < fsz:
                            cidx, tidx, nidx = _s.unpack_from('<HHI', dex, foff + fi * 8)
                            owner, sig_s, name = tname(cidx), tname(tidx), string(nidx)
                            if sig_s.startswith(('L', '[')):
                                body = 'sfid:class:%s->%s%s' % (owner.strip('L;'), name, sig_s)
                                seeds.setdefault(body, None)
                                seeds.setdefault('sfid:class:%s->%s%s' % (owner, name, sig_s), None)
                        pos += 2
                        continue
                    step = LEN.get(op)
                    if step is None:
                        break  # unknown opcode — abandon this clinit, keep the rest
                    pos += step
    return assign_seed_tokens(seeds)


def assign_seed_tokens(keys):
    """Field-key iterable -> {key: token}. Both owner spellings of the same
    field share one token; tokens never alias across fields, so merging the
    key sets of several --seed-dex scans is safe (re-run this on the union)."""
    out = {}
    canon = {}
    for k in sorted(keys):
        head, _, rest = k.partition('->')
        c = (head[len('sfid:class:'):].strip('L;'), rest)
        if c not in canon:
            canon[c] = _SEED_TOKEN_BASE + len(canon) * 0x10
        out[k] = canon[c]
    return out


def trace_function(so_path, fn, label='', this_desc='this', max_insn=2000000, run_init=False,
                   seeds=None, arms=False, null_tokens=(), guards_out=None):
    data = open(so_path, 'rb').read()
    elf = emu_base.Elf(data)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    maxv = max(v + f for _, v, f in elf.loads)
    uc.mem_map(0, (maxv + 0x4000000 + PAGE - 1) & ~(PAGE - 1))
    for off, vaddr, filesz in elf.loads:
        uc.mem_write(vaddr, data[off:off + filesz])
    for a, s in ((STACK, STACKSZ), (HEAP, HEAPSZ), (TLS, 0x2000), (STUB, STUBSZ)):
        base, end = a & ~(PAGE - 1), (a + s + PAGE - 1) & ~(PAGE - 1)
        uc.mem_map(base, end - base)
    uc.mem_map(JNIF, 0x80000)

    libc = emu_base.make_libc(uc, elf)
    libc.pop('_svc_hook', None)
    libc.pop('_svc_events', None)
    stub_addr = {}
    tags = elf.dynamic_tags()
    symtab_off = elf.va2off(tags.get(emu_base.DT_SYMTAB, 0))
    strtab_off = elf.va2off(tags.get(emu_base.DT_STRTAB, 0))

    i = 0
    for r_offset, rtype, symidx, addend in elf.relocations():
        if rtype in (emu_base.R_GLOB_DAT, emu_base.R_JUMP_SLOT) and symtab_off:
            name = elf.str_at(strtab_off, struct.unpack_from('<I', data, symtab_off + symidx * 24)[0])
            b = symtab_off + symidx * 24
            shndx, val = struct.unpack_from('<H', data, b + 6)[0], struct.unpack_from('<Q', data, b + 8)[0]
            if shndx and val:  # self-defined symbols run their real code
                uc.mem_write(r_offset, struct.pack('<Q', val))
                continue
            sa = STUB + 8 * i
            i += 1
            stub_addr[sa] = libc.get(name, lambda *a: 0)
            uc.mem_write(r_offset, struct.pack('<Q', sa))
        elif rtype == emu_base.R_RELATIVE:
            uc.mem_write(r_offset, struct.pack('<Q', addend))

    tr = Tracer(uc)
    tr.null_tokens = set(null_tokens)
    if seeds:
        # clinit-initialized static object fields are non-null on device by
        # the time any method runs (see scan_clinit_object_seeds); in-run
        # writes still override via the normal SetStaticObjectField path
        tr.sstatic.update(seeds)
        tr.seed_tokens = set(seeds.values())
        # keep tok() from re-issuing a seed token to an unrelated object
        hi = max(seeds.values()) - HEAP + 0x10
        if hi > tr.next_tok:
            tr.next_tok = hi
    env = JNIF + 0x2000
    uc.mem_write(env, struct.pack('<Q', JNIF))
    for slot in range(240):
        uc.mem_write(JNIF + 8 * slot, struct.pack('<Q', JNIF + 0x800 + 8 * slot))
    this_obj = tr.tok(this_desc)

    def jni_ret(idx, x0, x1, x2, x3):
        nm = JNI_SLOTS[idx] if idx < len(JNI_SLOTS) else f'slot{idx}'
        argd = ''
        ret = 0
        if idx == 239:  # fake JavaVM GetEnv — hand out our JNIEnv
            if x1:
                uc.mem_write(x1, struct.pack('<Q', env))
            ret = 0
        elif idx == 6:  # FindClass
            argd = f' "{tr.cstr(x1)}"'
            ret = tr.tok('class:' + tr.cstr(x1))
        elif idx in ID_GETTERS:
            name, sig = tr.cstr(x2), tr.cstr(x3)
            owner = tr.desc(x1)
            argd = f' cls={owner} "{name}" "{sig}"'
            ret = tr.tok(f'{ID_GETTERS[idx]}:{owner}->{name}{sig}')
        elif idx in VOID_CALLS:
            argd = f' {tr.desc(x2)}'
            if idx in (63, 93, 143):  # A variants: x3 = jvalue[] — parse per signature
                argd += ' args=[' + tr.jvals(x2, x3) + ']'
        elif idx in OBJ_CALLS:
            argd = f' {tr.desc(x2)}'
            if idx in (36, 66, 116):
                argd += ' args=[' + tr.jvals(x2, x3) + ']'
            ret = tr.tok('ret:' + tr.desc(x2))
        elif idx in (28, 29, 30):  # NewObject family — tie object to its class
            ret = tr.tok('new:' + tr.desc(x1))
        elif idx == 27:  # AllocObject
            ret = tr.tok('alloc:' + tr.desc(x1))
        elif idx == 25:  # NewLocalRef
            ret = x1
        elif idx == 21:  # NewGlobalRef — identity (keep the token chain alive)
            ret = x1
        elif idx in (22, 23, 24):
            ret = 0
        elif idx == 228:  # ExceptionCheck — must be 0 (non-zero reads as pending failure)
            ret = 0
        elif idx == 215:  # RegisterNatives — capture verbatim
            try:
                for k in range(min(x3, 64)):
                    nmp, sigp, f = struct.unpack('<QQQ', bytes(uc.mem_read(x2 + k * 24, 24)))
                    tr.trace.append(f'  [RegisterNatives] {tr.cstr(nmp)} {tr.cstr(sigp)} -> {hex(f)}')
            except Exception:
                pass
            ret = 0
        elif idx in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                     52, 53, 54, 55, 56, 57, 58, 59, 60,      # primitive Call*
                     67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
                     82, 83, 84, 85, 86, 87, 88, 89, 90,      # primitive CallNonvirtual*
                     117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
                     129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140):
            argd = f' {tr.desc(x2)}'
            if idx in (39, 42, 45, 48, 51, 54, 57, 60, 69, 72, 75, 78, 81, 84, 87, 90,
                       119, 122, 125, 128, 131, 134, 137, 140):  # A variants
                argd += ' args=[' + tr.jvals(x2, x3) + ']'
            # numeric CALL results steer branches (childCount, getBoolean…):
            # falsy = the cold-start path (fresh Activity launch), which is the
            # path a repaired app must get right. Field reads keep sentinels.
            ret = 0
        elif 95 <= idx <= 103:  # Get*Field — object gets token, number gets sentinel
            argd = f' {tr.desc(x2)}'
            ret = tr.sentinel('field:' + tr.desc(x2)) if idx >= 96 else tr.tok('field:' + tr.desc(x2))
        elif 104 <= idx <= 112:  # Set*Field — record the write (resolve sentinels/tokens)
            if x3 in tr.sent:
                val = f'{hex(x3)}={tr.sent[x3]}'
            elif idx == 104 and x3:
                val = f'{hex(x3)}={tr.desc(x3)}'
            else:
                val = hex(x3)
            argd = f' {tr.desc(x2)} = {val}'
            ret = 0
        elif 145 <= idx <= 153:  # GetStatic*Field (144 = GetStaticFieldID)
            argd = f' {tr.desc(x2)}'
            if idx == 145:
                # Fake-world TRUTH for static OBJECT fields: a field never
                # written in this run IS null. Returning a non-null token here
                # (old policy) makes every translated null-guard read false,
                # so null-guarded lazy-init branches are silently amputated
                # from the trace (device-verified root cause: er.c Lhr; read
                # non-null in trace, null on device -> NPE). Post-write reads
                # return the written token, keeping dataflow linked.
                ret = tr.sstatic.get(tr.desc(x2), 0)
            else:
                ret = tr.sentinel('sfield:' + tr.desc(x2))
        elif 154 <= idx <= 162:  # SetStatic*Field (154 = SetStaticObjectField;
            # the previous 155..163 range was off by one — 154 fell into the
            # GetStatic branch above, so static-object WRITES were never seen
            # as writes, and 163 (NewString) was misrouted here)
            if idx == 154:
                tr.sstatic[tr.desc(x2)] = x3  # record the write for later reads
                # print the value hex-prefixed like the instance setter does,
                # so trace2smali's value regex (hex[=desc]) resolves it
                val = f'{hex(x3)}={tr.sent.get(x3, tr.desc(x3))}' if x3 else '0'
            else:
                # sentinel values print hex=desc (same contract as above and
                # as the instance setter) so the downstream regex sees them
                val = f'{hex(x3)}={tr.sent[x3]}' if x3 in tr.sent else hex(x3)
            argd = f' {tr.desc(x2)} = {val}'
            ret = 0
        elif idx == 4:
            ret = 0x00010006
        elif idx == 171:  # GetArrayLength
            ret = 0
        elif idx == 176:  # NewByteArray
            ret = tr.tok(f'bytearray[{x1}]')
        elif idx == 169:  # GetStringUTFChars
            ret = 0
        elif idx == 167:  # NewStringUTF
            argd = f' "{tr.cstr(x1)}"'
            ret = tr.tok('str:' + tr.cstr(x1))
        else:
            ret = tr.tok(f'obj:{nm}')
        if 'Method' in nm and idx not in ID_GETTERS and not argd:
            argd = f' {tr.desc(x2)}'
        tr.trace.append(f'{nm}({hex(x1)}){argd} -> {hex(ret) if ret else 0} {tr.desc(ret) if ret else ""}'.rstrip())
        return ret

    def jni_hook(uc_, addr, size, user):
        idx = (addr - (JNIF + 0x800)) // 8
        x = [uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
        r = jni_ret(idx, *x)
        uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, jni_hook, begin=JNIF + 0x800, end=JNIF + 0x800 + 8 * 240)

    def hook_stub(uc_, addr, size, user):
        f = stub_addr.get(addr)
        if callable(f):
            x = [uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                           UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            r = f(*x)
            if r is not None:
                uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_stub, begin=STUB, end=STUB + STUBSZ)

    def hook_unmapped(uc_, access, addr, size, value, user):
        try:
            uc_.mem_map(addr & ~(PAGE - 1), PAGE * 16)
            return True
        except Exception:
            return False

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    if arms:
        # Null-guard discovery: a CBZ/CBNZ Xt whose tested value is a fake
        # token marks a branch the fake world steered arbitrarily. Only DATA
        # producers are forked — method-call results ('ret:') and instance
        # field reads ('field:') are genuinely nullable on device (e.g.
        # ViewGroup.getChildAt on a fresh launch). Resolution and allocation
        # results (class:/mid:/sfid:/new:/alloc:/this/…) are non-null on
        # device by JNI contract (failure raises instead), so their null
        # arms are error paths no replay can take; clinit seeds are
        # device-true non-null. Detection is value-based, so register copies
        # are covered; only the 64-bit CBZ/CBNZ forms are recognized
        # (translators emit them for null checks; cmp+b.eq chains are
        # future work).
        REG_X = ([UC_ARM64_REG_X0 + i for i in range(29)]
                 + [UC_ARM64_REG_FP, UC_ARM64_REG_LR])

        def hook_guard(uc_, addr, size, user):
            w = struct.unpack('<I', uc_.mem_read(addr, 4))[0]
            if (w >> 24) not in (0xB4, 0xB5):
                return
            rt = w & 0x1F
            if rt == 31:
                return
            v = uc_.reg_read(REG_X[rt])
            if (v in tr.toks and v not in tr.seed_tokens
                    and tr.toks[v].startswith(('ret:', 'field:'))
                    and v not in tr._guard_seen):
                tr._guard_seen.add(v)
                tr.guards.append({'pc': addr, 'token': v, 'desc': tr.toks[v],
                                  'kind': 'cbz' if (w >> 24) == 0xB4 else 'cbnz'})

        uc.hook_add(UC_HOOK_CODE, hook_guard, begin=0, end=maxv)

    uc.reg_write(UC_ARM64_REG_SP, STACK + STACKSZ - 0x100)
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)

    out = [f'=== trace {label or hex(fn)} @ {hex(fn)} ===']

    if run_init:
        # loaders run DT_INIT_ARRAY then JNI_OnLoad before any native is live;
        # runtime-built strings/globals exist only after that. Feed JNI_OnLoad
        # a fake JavaVM whose GetEnv hands out our JNIEnv.
        vm = JNIF + 0x40000
        uc.mem_write(vm, struct.pack('<Q', vm + 0x1000))
        uc.mem_write(vm + 0x1000 + 0x30, struct.pack('<Q', JNIF + 0x800 + 8 * 239))
        tags2 = elf.dynamic_tags()
        init_arr, init_sz = tags2.get(25), tags2.get(27, 0)
        if init_arr:
            off = elf.va2off(init_arr)
            for k in range(init_sz // 8):
                entry = struct.unpack('<Q', data[off + k * 8:off + k * 8 + 8])[0]
                if entry and entry < maxv:
                    try:
                        uc.reg_write(UC_ARM64_REG_LR, JNIF + 0x30000)
                        uc.emu_start(entry, JNIF + 0x30000, count=max_insn)
                    except Exception as e:
                        out.append(f'[init_array {hex(entry)} stop] {type(e).__name__}')
        for name, val, _sz in elf.dyn_symbols():
            if name == 'JNI_OnLoad':
                try:
                    uc.reg_write(UC_ARM64_REG_X0, vm)
                    uc.reg_write(UC_ARM64_REG_X1, 0)
                    uc.reg_write(UC_ARM64_REG_LR, JNIF + 0x30000)
                    uc.emu_start(val, JNIF + 0x30000, count=max_insn)
                    out.append('[JNI_OnLoad done]')
                except Exception as e:
                    out.append(f'[JNI_OnLoad stop] {type(e).__name__}: pc={hex(uc.reg_read(UC_ARM64_REG_PC))}')
                break

    uc.reg_write(UC_ARM64_REG_X0, env)
    uc.reg_write(UC_ARM64_REG_X1, this_obj)
    uc.reg_write(UC_ARM64_REG_X2, 0)
    uc.reg_write(UC_ARM64_REG_X3, 0)
    uc.reg_write(UC_ARM64_REG_LR, JNIF + 0x30000)  # return sentinel (unmapped -> stop)
    try:
        uc.emu_start(fn, JNIF + 0x30000, count=max_insn)
        out.append('(returned)')
    except Exception as e:
        out.append(f'[emu stop] {type(e).__name__}: pc={hex(uc.reg_read(UC_ARM64_REG_PC))}')
    out.append(f'=== {len(tr.trace)} JNI calls ===')
    out.extend(tr.trace)
    if guards_out is not None:
        guards_out.extend(tr.guards)
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description='Trace JNI semantics of a native-ized method')
    ap.add_argument('so')
    ap.add_argument('--fn', action='append', required=True, help='function VA (hex), repeatable')
    ap.add_argument('--label', action='append', default=[], help='label per --fn (same order)')
    ap.add_argument('--this', default='this', help='label for the x1 jobject (e.g. Lcom/app/MainActivity;)')
    ap.add_argument('--out', help='directory for per-function trace files (default: stdout)')
    ap.add_argument('--init', action='store_true', help='run DT_INIT_ARRAY + JNI_OnLoad first (runtime-built strings/globals)')
    ap.add_argument('--seed-dex', action='append', default=[], metavar='DEX',
                    help='dump dex to scan for clinit-initialized static object '
                    'fields (<clinit> sput-object targets) and pre-seed them '
                    'non-null in the fake world — the device truth for such '
                    'fields, derivable from any dump; repeatable')
    ap.add_argument('--arms', action='store_true',
                    help='enumerate null-guard points on fake object tokens '
                    '(CBZ/CBNZ on a token: the JNI producer result is '
                    'environment-state-dependent on device) and write one '
                    'extra trace per guard with that producer forced null; '
                    'requires --out. Single-flip v1: guards discovered only '
                    'on a flipped arm are not recursively enumerated')
    ap.add_argument('--arms-max', type=int, default=16,
                    help='max flipped-arm traces per function (default 16)')
    args = ap.parse_args()
    seed_keys = set()
    for dex_path in args.seed_dex:
        got = scan_clinit_object_seeds(open(dex_path, 'rb').read())
        seed_keys.update(got)
        print('[seed-dex] %s: %d clinit-initialized static object field(s)'
              % (dex_path, len(set(got.values()))), file=sys.stderr)
    # tokenize the UNION (per-dex scans each start at the token base —
    # merging their dicts directly would alias tokens across dexes)
    seeds = assign_seed_tokens(seed_keys)
    if args.seed_dex:
        print('[seed-dex] total: %d field(s) pre-seeded'
              % len(set(seeds.values())), file=sys.stderr)
    if args.arms and not args.out:
        ap.error('--arms requires --out (flipped-arm traces are written per guard)')
    for k, f in enumerate(args.fn):
        label = args.label[k] if k < len(args.label) else f
        guards = []
        text = trace_function(args.so, int(f, 16), label, args.this, run_init=args.init,
                              seeds=seeds or None, arms=args.arms,
                              guards_out=guards if args.arms else None)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, f'trace_{label or f}.txt'), 'w') as fh:
                fh.write(text + '\n')
            print(f'{label or f}: {text.count(chr(10))} lines -> {args.out}/trace_{label or f}.txt')
        else:
            print(text)
        if args.arms:
            with open(os.path.join(args.out, f'{label or f}.guards.json'), 'w') as fh:
                json.dump([{'i': i, 'pc': hex(g['pc']), 'token': hex(g['token']),
                            'kind': g['kind'], 'desc': g['desc']}
                           for i, g in enumerate(guards)], fh, indent=1)
            for i, g in enumerate(guards[:args.arms_max]):
                t2 = trace_function(args.so, int(f, 16), label, args.this,
                                    run_init=args.init, seeds=seeds or None,
                                    null_tokens={g['token']})
                with open(os.path.join(args.out, f'trace_{label or f}.null{i}.txt'), 'w') as fh:
                    fh.write(t2 + '\n')
                print(f'{label or f}.null{i}: null @ {g["desc"]} '
                      f'({t2.count(chr(10))} lines)')
            if len(guards) > args.arms_max:
                print(f'{label or f}: {len(guards) - args.arms_max} guard(s) not forked (--arms-max)')


if __name__ == '__main__':
    main()
