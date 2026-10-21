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

Exit codes: 0 = trace captured; 2 = unicorn missing; 3 = ELF parse error.
"""

import argparse
import importlib.util
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
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
        UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0,
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


def trace_function(so_path, fn, label='', this_desc='this', max_insn=2000000, run_init=False):
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
        elif 145 <= idx <= 154:  # GetStatic*Field
            argd = f' {tr.desc(x2)}'
            ret = (tr.sentinel('sfield:' + tr.desc(x2)) if idx != 145
                   else tr.tok('sfield:' + tr.desc(x2)))
        elif 155 <= idx <= 163:  # SetStatic*Field
            val = tr.sent.get(x3, tr.desc(x3)) if idx == 155 else tr.sent.get(x3, hex(x3))
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
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description='Trace JNI semantics of a native-ized method')
    ap.add_argument('so')
    ap.add_argument('--fn', action='append', required=True, help='function VA (hex), repeatable')
    ap.add_argument('--label', action='append', default=[], help='label per --fn (same order)')
    ap.add_argument('--this', default='this', help='label for the x1 jobject (e.g. Lcom/app/MainActivity;)')
    ap.add_argument('--out', help='directory for per-function trace files (default: stdout)')
    ap.add_argument('--init', action='store_true', help='run DT_INIT_ARRAY + JNI_OnLoad first (runtime-built strings/globals)')
    args = ap.parse_args()
    for k, f in enumerate(args.fn):
        label = args.label[k] if k < len(args.label) else f
        text = trace_function(args.so, int(f, 16), label, args.this, run_init=args.init)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, f'trace_{label or f}.txt'), 'w') as fh:
                fh.write(text + '\n')
            print(f'{label or f}: {text.count(chr(10))} lines -> {args.out}/trace_{label or f}.txt')
        else:
            print(text)


if __name__ == '__main__':
    main()
