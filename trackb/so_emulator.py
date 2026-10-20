#!/usr/bin/env python3
"""Exuvia Track B: offline black-box executor for shell .so files (user-side tool).

Product component (README_AGENT §3.1, Track B): runs a shell's own decrypt/decompress
routines without any Android environment — pure emulation on the analysis machine.
Heavy dependency (unicorn) is installed user-side by policy; absence = `unavailable`
capability semantics, same class as jadx/ghidra. No sample-specific values live here:
every address, key and symbol is a CLI argument.

Usage:
  python3 so_emulator.py shell.so --fn 0x7984 --arg x0=0x500000000000
  python3 so_emulator.py shell.so --fn 0x2c5b88 --java            # stub JavaVM/JNIEnv
  python3 so_emulator.py shell.so --fn 0x7984 --watch 0x7a04 --dump x0:32:out.bin

Mechanics (format facts only):
  - ELF64 PT_LOAD segments mapped at their declared vaddr (PIE base 0)
  - R_AARCH64_RELATIVE relocations applied; GLOB_DAT/JUMP_SLOT slots routed to
    built-in bionic libc semantics (malloc/free/mem*/str*/...) with a mapping table
  - GOT slots without a JMPREL entry (shell runtime-patched slots) are routed to
    malloc/memcpy semantics by default; override with --got slot:name
  - Relocations against symbols DEFINED in the so itself (st_shndx != 0) bind
    to the so's own VA — interpreter bridges, canary guards and self-provided
    natives must run their real code, not a return-0 stub; undefined imports
    (st_shndx == 0, including decoy defs decorated with a data address) keep
    bionic libc stub semantics
  - TLS canary (tpidr_el0) is materialized; stack/heap are scratch regions
  - Optional minimal JNI world: fake JavaVM/JNIEnv tables, every slot a stub
    (RegisterNatives captures the native-method table and prints it)

Exit codes: 0 = emulated return captured; 2 = unicorn missing; 3 = ELF parse error.
"""

import argparse
import struct
import sys
import json

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_TPIDR_EL0,
    )
except ImportError:
    print('{"error":"unavailable","detail":"unicorn not installed (user-side dependency, README_AGENT §3.1)"}')
    sys.exit(2)

PAGE = 0x1000
STACK, STACKSZ = 0x7F0000000000, 0x400000
HEAP, HEAPSZ = 0x500000000000, 0x8000000
TLS = 0x510000000000
STUB = 0x600000000000
STUBSZ = 0x10000
JNIF = 0x620000000000
SENTINEL = 0x630000000000

DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_SYMENT = 0, 4, 5, 6, 11
DT_GNU_HASH, DT_JMPREL = 0x6FFFFEF5, 23
R_RELATIVE, R_GLOB_DAT, R_JUMP_SLOT = 1027, 1025, 1026


class Elf:
    def __init__(self, data: bytes):
        self.d = data
        if not data.startswith(b'\x7fELF') or data[4] != 2:
            raise ValueError('not an ELF64')
        u16 = lambda o: struct.unpack_from('<H', data, o)[0]
        u32 = lambda o: struct.unpack_from('<I', data, o)[0]
        u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
        self.u16, self.u32, self.u64 = u16, u32, u64
        phoff, phentsize, phnum = u64(0x20), u16(0x36), u16(0x38)
        self.loads = []
        self.pt_dynamic = None
        for i in range(phnum):
            b = phoff + i * phentsize
            if u32(b) == 1:
                self.loads.append((u64(b+8), u64(b+16), u64(b+32)))
            elif u32(b) == 2:
                self.pt_dynamic = (u64(b+8), u64(b+32))
        if not self.loads:
            raise ValueError('no PT_LOAD')

    def va2off(self, va):
        for off, vaddr, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def dynamic_tags(self):
        if not self.pt_dynamic:
            return {}
        off, sz = self.pt_dynamic
        d = self.d
        tags = {}
        for i in range(sz // 16):
            t, v = struct.unpack_from('<QQ', d, off + i * 16)
            if t == DT_NULL:
                break
            tags.setdefault(t, v)
        return tags

    def str_at(self, strtab_off, name_off):
        start = strtab_off + name_off
        end = self.d.index(b'\0', start)
        return self.d[start:end].decode(errors='replace')

    def dyn_symbols(self):
        """(name, st_value, st_size) for defined dynsym entries, runtime view first."""
        tags = self.dynamic_tags()
        if DT_SYMTAB not in tags or DT_STRTAB not in tags:
            return []
        symtab = self.va2off(tags[DT_SYMTAB])
        strtab = self.va2off(tags[DT_STRTAB])
        d = self.d
        syment = tags.get(DT_SYMENT, 24)
        n = None
        if DT_HASH in tags:
            hoff = self.va2off(tags[DT_HASH])
            n = self.u32(hoff + 4)
        elif DT_GNU_HASH in tags:
            gh = self.va2off(tags[DT_GNU_HASH])
            nbuckets, symoffset = self.u32(gh), self.u32(gh + 4)
            bloom = self.u32(gh + 8)
            buckets = gh + 16 + bloom * 8
            mx = max((self.u32(buckets + i * 4) for i in range(nbuckets)), default=0)
            if mx:
                chain = buckets + nbuckets * 4
                i = mx
                while not (self.u32(chain + (i - symoffset) * 4) & 1):
                    i += 1
                n = i + 1
        if not n:
            return []
        out = []
        for i in range(n):
            b = symtab + i * syment
            if struct.unpack_from('<H', d, b + 6)[0] == 0:
                continue
            out.append((self.str_at(strtab, self.u32(b)), self.u64(b + 8), self.u64(b + 16)))
        return out

    def relocations(self):
        """All RELA entries as (r_offset, type, sym_idx, addend)."""
        tags = self.dynamic_tags()
        out = []
        for tkey in (7, DT_JMPREL):  # DT_RELA / DT_JMPREL
            if tkey not in tags:
                continue
            off, sz = self.va2off(tags[tkey]), tags.get(8 if tkey == 7 else 2, 0)
            for i in range(sz // 24):
                b = off + i * 24
                ro, ri, ad = struct.unpack_from('<QQq', self.d, b)
                out.append((ro, ri & 0xffffffff, ri >> 32, ad))
        return out


# bionic libc semantics (format-level behavior only; failures return 0 like stubs)
def make_libc(uc, elf):
    heap_ptr = [HEAP]
    heap_end = [HEAP + HEAPSZ]
    import zlib
    # file-system bridge state (fed by --fs CLI)
    global FS_MAP, FILES, FD
    if 'FS_MAP' not in globals():
        FS_MAP, FILES, FD = [{}], [{}], [0x100]

    def bump(sz):
        # r18: auto-extend the heap (real loaders parse big blobs; the initial
        # 128MB window is not a ceiling). Sane-capped: a request beyond the cap
        # fails as NULL like real malloc — callers check.
        HEAP_CAP = 0x40000000  # 1GB total
        if sz > HEAP_CAP or heap_ptr[0] + sz > HEAP + HEAP_CAP:
            return 0
        p = heap_ptr[0]
        heap_ptr[0] = (p + sz + 0x1F) & ~0xF
        if heap_ptr[0] > heap_end[0]:
            extra = (heap_ptr[0] - heap_end[0] + PAGE - 1) & ~(PAGE - 1)
            try:
                uc.mem_map(heap_end[0], extra)
            except Exception:
                pass  # already mapped by an earlier extension
            heap_end[0] += extra
        return p

    def rd(a, n):
        return bytes(uc.mem_read(a, n))

    def wr(a, b):
        uc.mem_write(a, bytes(b))

    def cstr(a):
        out = bytearray()
        while True:
            c = rd(a, 1)
            if c == b'\0':
                return bytes(out)
            out += c
            a += 1

    # zlib bridge (inflate family): the z_stream lives in emulated memory, the
    # decompression state machine lives here — keyed by the stream pointer.
    zlib_objs = {}

    def f_inflateInit_(x0, x1, x2, x3, x4=0, x5=0):
        zlib_objs[x0] = {'d': zlib.decompressobj(), 'pending': b''}
        return 0  # Z_OK

    def f_inflateEnd(x0, x1, x2, x3, x4=0, x5=0):
        zlib_objs.pop(x0, None)
        return 0

    def f_inflate(x0, x1, x2, x3, x4=0, x5=0):
        s = x0
        st = zlib_objs.setdefault(s, {'d': zlib.decompressobj(), 'pending': b''})
        next_in = struct.unpack_from('<Q', rd(s, 8))[0]
        avail_in = struct.unpack_from('<I', rd(s + 8, 4))[0]
        next_out = struct.unpack_from('<Q', rd(s + 0x18, 8))[0]
        avail_out = struct.unpack_from('<I', rd(s + 0x20, 4))[0]
        total_out = struct.unpack_from('<Q', rd(s + 0x28, 8))[0]
        data = st['pending'] + (rd(next_in, avail_in) if avail_in and next_in else b'')
        try:
            out = st['d'].decompress(data, avail_out)
            st['pending'] = st['d'].unconsumed_tail
        except zlib.error:
            return -3  # Z_DATA_ERROR
        consumed = len(data) - len(st['pending'])
        if next_out and out:
            wr(next_out, out)
        wr(s + 0x00, struct.pack('<Q', (next_in + consumed) & 0xFFFFFFFFFFFFFFFF))
        wr(s + 0x08, struct.pack('<I', len(st['pending'])))
        wr(s + 0x20, struct.pack('<I', max(avail_out - len(out), 0)))
        wr(s + 0x28, struct.pack('<Q', total_out + len(out)))
        return 1 if st['d'].eof else 0  # Z_STREAM_END / Z_OK

    def f_malloc(x0, x1, x2, x3, x4=0, x5=0):
        return bump(max(x0, 1))

    def f_calloc(x0, x1, x2, x3, x4=0, x5=0):
        p = bump(x0 * x1)
        if not p:
            return 0
        wr(p, b'\0' * (x0 * x1))
        return p

    def f_free(x0, x1, x2, x3, x4=0, x5=0):
        return 0

    def f_memcpy(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0, rd(x1, x2))
        return x0

    def f_memset(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0, bytes([x2 & 0xFF]) * x1)
        return x0

    def f_memcmp(x0, x1, x2, x3, x4=0, x5=0):
        a, b = rd(x0, x2), rd(x1, x2)
        return 0 if a == b else 1

    def f_strlen(x0, x1, x2, x3, x4=0, x5=0):
        return len(cstr(x0))

    def f_strcmp(x0, x1, x2, x3, x4=0, x5=0):
        return 0 if cstr(x0) == cstr(x1) else 1

    def f_noop(x0, x1, x2, x3, x4=0, x5=0):
        return 0

    threads_spawned = []

    def f_pthread_create(x0, x1, x2, x3, x4=0, x5=0):
        # 单线程模拟（r13）：线程入口是黑盒目标——记录 start_routine/arg，
        # 调用者随后 --fn 直入（unicorn 单线程不能并发，但入口语义完整保留）
        threads_spawned.append({'start': x2, 'arg': x3})
        return 0

    def f_errno(x0, x1, x2, x3, x4=0, x5=0):
        return TLS + 0x80

    # File-system bridge (Battle-1 r7-8): verification chains fopen() their own APK.
    fs_map = FS_MAP[0]
    files = FILES[0]

    def f_fopen(x0, x1, x2, x3, x4=0, x5=0):
        path = cstr(x0).decode(errors='replace')
        real = fs_map.get(path)
        if real is None:
            for k, v in fs_map.items():
                if path.startswith(k):
                    real = v
                    break
        if real is None:
            return 0
        fd = FD[0]
        FD[0] += 1
        files[fd] = open(real, 'rb')
        return fd

    def f_fread(x0, x1, x2, x3, x4=0, x5=0):
        # fread(buf, size, n, FILE*)
        f = files.get(x3)
        if not f:
            return 0
        blob = f.read(x1 * x2)
        wr(x0, blob)
        return len(blob) // max(x1, 1)

    def f_fclose(x0, x1, x2, x3, x4=0, x5=0):
        f = files.pop(x0, None)
        if f: f.close()
        return 0

    def f_fseek(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return -1
        f.seek(x1, x2)
        return 0

    def f_ftell(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        return f.tell() if f else 0

    # mmap bridge (Battle-1 r13): shells mmap a runtime file (their own APK /
    # released blob) — [0x2e40d0] composes an mmap-base pointer, and the SM4
    # engine (r12) consumes that region. fd from the --fs fopen bridge =>
    # file content is materialized into the mapping; anonymous => zero region.
    mmap_cursor = [HEAP + 0x6000000]
    mmap_regions = []

    def f_mmap(x0, x1, x2, x3, x4=0, x5=0):
        # r18: the mapping must be SELF-SUFFICIENT — the old stub relied on the
        # initial heap window covering the cursor, so a cursor past HEAPSZ wrote
        # to unmapped memory (mini-linker loads crash there). Absurd lengths now
        # fail as 0 (callers check), sane ones map their own region.
        length = x1 if x1 else 0x1000
        if length > 0x40000000:
            mmap_regions.append({'addr': 0, 'len': length, 'source': 'refused'})
            return 0
        addr = (mmap_cursor[0] + PAGE - 1) & ~(PAGE - 1)
        mmap_cursor[0] = addr + ((length + PAGE - 1) & ~(PAGE - 1))
        try:
            uc.mem_map(addr, (length + PAGE - 1) & ~(PAGE - 1))
        except Exception:
            pass  # already mapped (e.g. inside the initial heap window)
        f = files.get(x4)
        if f:
            f.seek(x5)
            blob = f.read(length)
            uc.mem_write(addr, blob)
            mmap_regions.append({'addr': addr, 'len': len(blob), 'source': 'fd:%s' % f.name})
        else:
            zero = b'\0' * min(length, 0x400000)
            uc.mem_write(addr, zero)
            mmap_regions.append({'addr': addr, 'len': length, 'source': 'anon'})
        return addr

    table = {
        'malloc': f_malloc, '_Znwm': f_malloc, '_Znam': f_malloc, 'calloc': f_calloc,
        'free': f_free, '_ZdlPv': f_free, '_ZdaPv': f_free,
        'memcpy': f_memcpy, 'memmove': f_memcpy, 'memset': f_memset,
        'memcmp': f_memcmp, 'strlen': f_strlen, '__strlen_chk': f_strlen,
        'strcmp': f_strcmp, 'strcpy': lambda x0, x1, x2, x3, x4=0, x5=0: (wr(x0, cstr(x1) + b'\0'), x0)[1],
        '__aarch64_sync_cache_range': f_noop, 'pthread_mutex_init': f_noop,
        'pthread_mutex_lock': f_noop, 'pthread_mutex_unlock': f_noop,
        'pthread_detach': f_noop, '__cxa_atexit': f_noop, '__cxa_finalize': f_noop,
        'time': lambda x0, x1, x2, x3, x4=0, x5=0: 1234, 'getpid': lambda x0, x1, x2, x3, x4=0, x5=0: 1234,
        'srand': f_noop, 'rand': lambda x0, x1, x2, x3, x4=0, x5=0: 42,
        'dladdr': lambda x0, x1, x2, x3, x4=0, x5=0: (wr(x1, struct.pack('<QQQQ', 0, 0, 0, 0)), 0)[1],
        'dlerror': f_noop, '__errno': f_errno, 'sysconf': lambda x0, x1, x2, x3, x4=0, x5=0: 4096,
        'inflate': f_inflate, 'inflateInit_': f_inflateInit_, 'inflateEnd': f_inflateEnd,
        'fopen': f_fopen, 'fread': f_fread, 'fclose': f_fclose,
        'fseek': f_fseek, 'ftell': f_ftell,
        'mmap': f_mmap, 'munmap': f_noop,
        'pthread_create': f_pthread_create,
    }
    table['_mmap_regions'] = mmap_regions  # main 侧 CLI 输出（非符号名，绑定循环不触碰）
    table['_threads_spawned'] = threads_spawned
    return table


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('so')
    ap.add_argument('--fn', required=True, help='target function VA (hex)')
    ap.add_argument('--arg', action='append', default=[], help='xN=VAL (register setup, hex)')
    ap.add_argument('--watch', action='append', default=[], help='VA to snapshot x0-x7/buffer at (hex)')
    ap.add_argument('--watch-write', action='append', default=[],
                    help='VA to trap memory WRITES at (hex) — records writer PC + value (materialization forensics)')
    ap.add_argument('--dump', action='append', default=[], help='x0:LEN:FILE — dump buffer on return')
    ap.add_argument('--dump-mem', action='append', default=[],
                    help='VA:LEN:FILE — dump a fixed memory region after the run (before-registered maps only; '
                         'materialization diagnostics: run twice, diff against the so file)')
    ap.add_argument('--got', action='append', default=[],
                    help='slot:name — override a GOT slot semantics (hex slot, libc name)')
    ap.add_argument('--java', action='store_true', help='stub JavaVM/JNIEnv (fake tables, RegisterNatives capture)')
    ap.add_argument('--poke', action='append', default=[],
                    help='addr:hex — write bytes into emulated memory before run (e.g. this-struct setup)')
    ap.add_argument('--load', action='append', default=[],
                    help='file:va — map an external file into emulated memory (cross-file black-box, e.g. a ciphertext container living in another file)')
    ap.add_argument('--fs', action='append', default=[],
                    help='path:realfile — bridge fopen()/fread()/lseek() to a real file (shell verification chains read their own APK; Battle-1 rounds 7-8)')
    ap.add_argument('--sig-file', action='append', default=[],
                    help='file — feed real signature bytes into the byte-array JNI semantics '
                         '(GetArrayLength/GetByteArrayElements serve this buffer instead of the zero region; '
                         'Battle-1 r10: runtime-derived keys read the signing chain — unsigned-corpus '
                         'faithfulness stops exactly at that wall; honest approximation: EVERY byte-array '
                         'call sees this buffer, function-level JNI cannot tell arrays apart)')
    ap.add_argument('--utf8-file', action='append', default=[],
                    help='file — feed real UTF-8 bytes into the string JNI semantics '
                         '(GetStringUTFChars/GetStringUTFLength serve this buffer; Battle-1 r10: '
                         'signature-key derivation mixes packageName+signature hashes — the string '
                         'side needs real bytes; same honest approximation as --sig-file)')
    ap.add_argument('--timeout', type=int, default=60, help='emulation timeout seconds')
    args = ap.parse_args()

    data = open(args.so, 'rb').read()
    try:
        elf = Elf(data)
    except ValueError as e:
        print(f'{{"error":"E_PARSE","detail":"{e}"}}')
        sys.exit(3)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    maxv = max(v + s for _, v, s in elf.loads)
    # r20: runtime slack past the image — shells keep runtime tables in the
    # post-image area (Battle-1 loader zeroes a ~4MB runtime region starting at
    # its soinfo [0x2fa00] and extending past the image end before populating);
    # real loaders provide that brk/slack space.
    RUNTIME_SLACK = 0x4000000
    uc.mem_map(0, (maxv + RUNTIME_SLACK + PAGE - 1) & ~(PAGE - 1))
    for off, vaddr, filesz in elf.loads:
        uc.mem_write(vaddr, data[off:off + filesz])
    for a, s in ((STACK, STACKSZ), (HEAP, HEAPSZ), (TLS, 0x2000), (STUB, STUBSZ)):
        base, end = a & ~(PAGE - 1), (a + s + PAGE - 1) & ~(PAGE - 1)
        uc.mem_map(base, end - base)

    libc = make_libc(uc, elf)
    # feed --fs map into the bridge before stub binding
    for spec in args.fs:
        p, real = spec.split(':', 1) if ':' in spec else (spec, spec)
        FS_MAP[0][p] = real
    stub_addr = {}
    # bind GOT slots: JMPREL/GLOB_DAT symbols, then RELATIVE relocations
    symtab_off = elf.va2off(elf.dynamic_tags().get(DT_SYMTAB, 0))
    strtab_off = elf.va2off(elf.dynamic_tags().get(DT_STRTAB, 0))

    def sym_def(idx):
        """(st_shndx, st_value) of a dynsym entry — defined-in-so iff shndx != 0."""
        b = symtab_off + idx * 24
        return struct.unpack_from('<H', data, b + 6)[0], struct.unpack_from('<Q', data, b + 8)[0]

    i = 0
    for r_offset, rtype, symidx, addend in elf.relocations():
        if rtype in (R_GLOB_DAT, R_JUMP_SLOT) and symtab_off:
            name = elf.str_at(strtab_off, struct.unpack_from('<I', data, symtab_off + symidx * 24)[0])
            # r15 Battle-1 lesson: symbols the so DEFINES itself (interpreter
            # bridges, self-natives, canary-guard objects) were previously routed
            # to callable stubs — silently returning 0 instead of dispatching real
            # code. Bind them to their own VA. Decoys (shndx == 0 with a data
            # address painted on) are imports — keep libc stub semantics.
            shndx, val = sym_def(symidx)
            if shndx and val:
                uc.mem_write(r_offset, struct.pack('<Q', val))
                continue
            sa = STUB + 8 * i
            i += 1
            stub_addr[sa] = libc.get(name, lambda x0, x1, x2, x3, x4=0, x5=0: 0)
            stub_addr[sa + 1] = name  # type tag for logging
            uc.mem_write(r_offset, struct.pack('<Q', sa))
    for r_offset, rtype, symidx, addend in elf.relocations():
        if rtype == R_RELATIVE:
            uc.mem_write(r_offset, struct.pack('<Q', addend))
    # unbound-slot defaults (shell runtime-patched slots → malloc/memcpy semantics)
    # r16 fix: each --got override gets its OWN stub slot — the old single shared
    # slot meant "a:malloc b:memcpy" silently collapsed to the last name and the
    # first call site executed the wrong semantics (Battle-1: decoy-GOT shells
    # need several overrides in one run).
    got_i = 0
    for slot, name in (map(lambda p: (int(p[0], 16), p[1]), (kv.split(':', 1) for kv in args.got))):
        sa = STUB + 0x8000 + 8 * got_i
        got_i += 1
        stub_addr[sa] = libc.get(name, lambda x0, x1, x2, x3, x4=0, x5=0: 0)
        uc.mem_write(slot, struct.pack('<Q', sa))
    sa = STUB + 0x9000
    stub_addr[sa] = libc['malloc']
    sa2 = STUB + 0x9008
    stub_addr[sa2] = libc['memcpy']

    if args.java:
        uc.mem_map(JNIF, 0x4000)
        env = JNIF + 0x2000
        uc.mem_write(env, struct.pack('<Q', JNIF))
        for slot in range(240):
            uc.mem_write(JNIF + 8 * slot, struct.pack('<Q', JNIF + 0x800 + 8 * slot))
        regs = {}
        fake_heap = [JNIF + 0x3000]
        # --sig-file: map real signature bytes (Battle-1 r10 — signing-chain key derivation)
        SIGBASE = JNIF + 0x10000
        sig_regions = []
        for k, sf in enumerate(args.sig_file):
            b = open(sf, 'rb').read()
            base = (SIGBASE + k * 0x10000) & ~(PAGE - 1)
            uc.mem_map(base, ((len(b) + PAGE - 1) & ~(PAGE - 1)) + PAGE)
            uc.mem_write(base, b)
            sig_regions.append((base, len(b)))
        # --utf8-file: map real UTF-8 bytes (packageName side of the derivation mix)
        utf8_regions = []
        for k, uf in enumerate(args.utf8_file):
            b = open(uf, 'rb').read()
            base = (JNIF + 0x20000 + k * 0x10000) & ~(PAGE - 1)
            uc.mem_map(base, ((len(b) + PAGE - 1) & ~(PAGE - 1)) + PAGE)
            uc.mem_write(base, b)
            utf8_regions.append((base, len(b)))
        # JavaVM fake world (InvokeJNI standard layout): feed --arg x0=<VM>.
        # JNI_OnLoad prologues do vm->GetEnv(vm, &env, ver) via table slot +0x30 (Battle-1 r10:
        # shells reached GetEnv before the JNIEnv world existed — productize the ladder).
        VM = JNIF + 0x30000
        GETENV_STUB = JNIF + 0x800 + 8 * 258  # idx 258: inside hook span, unused by JNIEnv semantics
        uc.mem_map(VM & ~(PAGE - 1), 0x4000)
        uc.mem_write(VM, struct.pack('<Q', VM + 0x1000))                  # [vm] = vmtable
        uc.mem_write(VM + 0x1000 + 0x30, struct.pack('<Q', GETENV_STUB))  # [vmtable+0x30] = GetEnv

        def fake_obj():
            p = fake_heap[0]
            fake_heap[0] += 16
            return p

        # Battle-1 earned JNI semantics (fake-world policy, shell-agnostic):
        #  - ExceptionCheck(228) MUST return 0 (non-zero reads as "pending exception" and fails every shell)
        #  - Call*Method family returns non-null fake objects (null trips failure paths)
        #  - GetStaticIntField(150) feeds a modern SDK_INT
        #  - default for unnamed slots: non-null fake object (Battle-1: null stubs caused the wall)
        def jni_ret(idx, x0, x1, x2, x3):
            if idx == 258:  # JavaVM GetEnv (vm-table slot +0x30) — *env = JNIEnv, JNI_OK
                if x1:
                    uc.mem_write(x1, struct.pack('<Q', env))
                return 0
            if idx == 228:  # ExceptionCheck
                return 0
            if idx == 215:  # RegisterNatives — capture verbatim
                try:
                    for k in range(min(x3, 64)):
                        nm, sig, fn = struct.unpack('<QQQ', bytes(uc.mem_read(x2 + k * 24, 24)))
                        name = bytes(uc.mem_read(nm, 128)).split(b'\0')[0].decode(errors='replace')
                        sigs = bytes(uc.mem_read(sig, 128)).split(b'\0')[0].decode(errors='replace')
                        regs[(name, sigs)] = fn
                except Exception:
                    pass
                return 0
            if idx == 150:  # GetStaticIntField — Build.VERSION.SDK_INT
                return 34
            if idx == 151:  # GetStaticLongField
                return 34
            if idx in (4,):  # GetVersion
                return 0x00010006
            if idx in (21, 22, 23):  # GlobalRef/LocalRef management
                return 0
            # Array semantics — STANDARD JNI table indexes, anchored by three Battle-1-verified
            # slots (150 GetStaticIntField / 215 RegisterNatives / 228 ExceptionCheck):
            #   168 GetStringUTFLength, 169 GetStringUTFChars,
            #   171 GetArrayLength, 172 NewObjectArray, 176 NewByteArray,
            #   184 GetByteArrayElements, 191-198 Release*ArrayElements (192 = ReleaseByteArray)
            # (r9's note "172/171" was an index mislabel — numbers-not-objects insight stands, slots corrected r10)
            if idx == 168:  # GetStringUTFLength — NUMBER
                if utf8_regions:
                    return utf8_regions[0][1]
                return 0
            if idx == 169:  # GetStringUTFChars — utf8-file injection > null
                if utf8_regions:
                    if x2:
                        uc.mem_write(x2, struct.pack('<Q', 0))
                    return utf8_regions[0][0]
                return 0
            if idx == 171:  # GetArrayLength — NUMBER, not object (r9 insight)
                if sig_regions:
                    return sig_regions[0][1]
                return 0
            if idx == 184:  # GetByteArrayElements — sig-file injection > deterministic zero region
                if sig_regions:
                    if x2:
                        uc.mem_write(x2, struct.pack('<Q', 0))
                    return sig_regions[0][0]
                z = HEAP + 0x7000000
                uc.mem_map(z & ~(PAGE - 1), 0x1000)
                uc.mem_write(z, b'\0' * 64)
                if x2:
                    uc.mem_write(x2, struct.pack('<Q', 0))
                return z
            if idx in (191, 192, 193, 194, 195, 196, 197, 198):  # Release*ArrayElements
                return 0
            # Call*/New*/Get*Object family + default: fake non-null object
            return fake_obj()

        def jni_hook(uc_, addr, size, user):
            idx = (addr - (JNIF + 0x800)) // 8
            x0, x1, x2, x3 = (uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3))
            r = jni_ret(idx, x0, x1, x2, x3)
            uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
            uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))
        uc.hook_add(UC_HOOK_CODE, jni_hook, begin=JNIF + 0x800, end=JNIF + 0x800 + 8 * 260)

    def hook_stub(uc_, addr, size, user):
        fn = stub_addr.get(addr)
        if callable(fn):
            x = [uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            r = fn(*x)
            if r is not None:
                uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_stub, begin=STUB, end=STUB + STUBSZ)

    watch_events = []

    def hook_watch(uc_, addr, size, user):
        x0 = uc_.reg_read(UC_ARM64_REG_X0)
        regs_all = {
            'x1': uc_.reg_read(UC_ARM64_REG_X1), 'x2': uc_.reg_read(UC_ARM64_REG_X2),
            'x3': uc_.reg_read(UC_ARM64_REG_X3), 'x4': uc_.reg_read(UC_ARM64_REG_X4),
            'x5': uc_.reg_read(UC_ARM64_REG_X5), 'x6': uc_.reg_read(UC_ARM64_REG_X6),
            'x7': uc_.reg_read(UC_ARM64_REG_X7),
        }
        try:
            buf = bytes(uc_.mem_read(x0, 32)).hex() if 0x1000 < x0 < 0x800000000000 else ''
        except Exception:
            buf = ''
        watch_events.append(json.dumps({
            'watch': '0x%x' % addr, 'x0': '0x%x' % x0,
            'x1': '0x%x' % regs_all['x1'], 'x2': '0x%x' % regs_all['x2'],
            'x3': '0x%x' % regs_all['x3'], 'x4': '0x%x' % regs_all['x4'],
            'x5': '0x%x' % regs_all['x5'], 'x6': '0x%x' % regs_all['x6'],
            'x7': '0x%x' % regs_all['x7'], 'buf': buf,
        }))

    for w in args.watch:
        uc.hook_add(UC_HOOK_CODE, hook_watch, begin=int(w, 16), end=int(w, 16))

    def hook_write(uc_, access, address, size, value, user):
        pc = uc_.reg_read(UC_ARM64_REG_PC)
        watch_events.append(json.dumps({'write': '0x%x' % address, 'pc': '0x%x' % pc,
                                        'size': size, 'value': '0x%x' % (value & 0xFFFFFFFFFFFFFFFF)}))
    from unicorn import UC_HOOK_MEM_WRITE
    for w in args.watch_write:
        if ':' in w:
            wa_s, wlen_s = w.split(':')
            wa, wlen = int(wa_s, 16), int(wlen_s, 0)
        else:
            wa, wlen = int(w, 16), 8
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=wa, end=wa + wlen)

    uc.mem_write(TLS + 0x28, b'\xDE\xAD\xBE\xEF\xCA\xFE\x00\x01')
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    for spec in args.load:
        path, va_s = spec.rsplit(':', 1)
        blob = open(path, 'rb').read()
        va = int(va_s, 0)
        base = va & ~(PAGE - 1)
        end = (va + len(blob) + PAGE - 1) & ~(PAGE - 1)
        try:
            uc.mem_map(base, end - base)
        except Exception:
            pass  # already mapped — plain write below
        uc.mem_write(va, blob)
    for spec in args.poke:
        addr_s, hexdata = spec.split(':', 1)
        uc.mem_write(int(addr_s, 0), bytes.fromhex(hexdata))
    uc.reg_write(UC_ARM64_REG_SP, STACK + STACKSZ // 2)
    for spec in args.arg:
        reg, val = spec.split('=')
        regmap = {'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2,
                  'x3': UC_ARM64_REG_X3, 'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
                  'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7}
        uc.reg_write(regmap[reg.lower()], int(val, 0))
    uc.reg_write(UC_ARM64_REG_LR, SENTINEL)

    fn_va = int(args.fn, 0)

    def dump_fixed_regions():
        # --dump-mem：跑完（无论成败）dump 固定区——物化诊断（数据段运行时解密/派生 key 落点）
        for spec in args.dump_mem:
            va_s, ln_s, path = spec.split(':')
            blob = bytes(uc.mem_read(int(va_s, 0), int(ln_s, 0)))
            open(path, 'wb').write(blob)

    try:
        uc.emu_start(fn_va, SENTINEL, timeout=args.timeout * 1000 * 1000)
    except Exception as e:
        # 错误路径也带上已观察到的 watch 事件——黑盒失败的现场属于证据（r10 诊断改进）
        # r20: 崩溃现场寄存器快照（x0-x7/sp/lr/pc）——深链故障定位刚需（装载器清零
        # 循环越界类崩溃的写入目标只能从这里读出）
        regs = {}
        from unicorn.arm64_const import (UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
                                         UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
                                         UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                                         UC_ARM64_REG_X28)
        for name, const in (('x0', UC_ARM64_REG_X0), ('x1', UC_ARM64_REG_X1),
                            ('x2', UC_ARM64_REG_X2), ('x3', UC_ARM64_REG_X3),
                            ('x4', UC_ARM64_REG_X4), ('x5', UC_ARM64_REG_X5),
                            ('x6', UC_ARM64_REG_X6), ('x7', UC_ARM64_REG_X7),
                            ('x19', UC_ARM64_REG_X19), ('x20', UC_ARM64_REG_X20),
                            ('x21', UC_ARM64_REG_X21), ('x22', UC_ARM64_REG_X22),
                            ('x23', UC_ARM64_REG_X23), ('x24', UC_ARM64_REG_X24),
                            ('x25', UC_ARM64_REG_X25), ('x26', UC_ARM64_REG_X26),
                            ('x27', UC_ARM64_REG_X27), ('x28', UC_ARM64_REG_X28),
                            ('sp', UC_ARM64_REG_SP), ('lr', UC_ARM64_REG_LR)):
            try:
                regs[name] = '0x%x' % uc.reg_read(const)
            except Exception:
                pass
        dump_fixed_regions()
        print(f'{{"error":"E_EMU","detail":"{e}","pc":"0x{uc.reg_read(UC_ARM64_REG_PC):x}",'
              f'"regs":{json.dumps(regs)},'
              f'"watch":{json.dumps(watch_events)}}}')
        sys.exit(1)

    ret = uc.reg_read(UC_ARM64_REG_X0)
    dump_fixed_regions()
    dumps = []
    for spec in args.dump:
        reg, ln, path = spec.split(':')
        a = uc.reg_read(UC_ARM64_REG_X0 if reg == 'x0' else UC_ARM64_REG_X1)
        blob = bytes(uc.mem_read(a, int(ln, 0)))
        open(path, 'wb').write(blob)
        dumps.append(path)
    out = {'return': f'0x{ret:x}', 'dumps': dumps, 'watch': watch_events}
    mmaps = libc.pop('_mmap_regions', [])
    if mmaps:
        out['mmap_regions'] = [{'addr': '0x%x' % m['addr'], 'len': m['len'], 'source': m['source']} for m in mmaps]
    threads = libc.pop('_threads_spawned', [])
    if threads:
        out['threads_spawned'] = [{'start': '0x%x' % t['start'], 'arg': '0x%x' % t['arg']} for t in threads]
    if args.java:
        out['registered_natives'] = {f'{k[0]}{k[1]}': f'0x{v:x}' for k, v in regs.items()}
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
