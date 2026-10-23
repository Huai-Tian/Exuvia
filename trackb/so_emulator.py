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
import os
import struct
import sys
import json

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_INTR
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_TPIDR_EL0,
    )
except ImportError:
    print('{"error":"unavailable","detail":"unicorn not installed (user-side dependency, README_AGENT §3.1)"}')
    sys.exit(2)

PAGE = 0x1000
STACK, STACKSZ = 0x7F0000000000, 0x400000
HEAP, HEAPSZ = 0x500000000000, 0x8000000

# libc emulations that must win even over symbols the so DEFINES itself
# (checked at both GOT-binding loops): their real code depends on
# pthread-key/TCB machinery the fake thread layer no-ops, so running it
# diverges — compiler-rt __emutls_get_address re-calloc's its control
# array on every call (pthread_setspecific is a no-op), per-var blocks
# never persist, and the whole thread_local class (TLS-guarded decoded
# strings) never materializes. The emulations implement the contract
# directly instead.
LIBC_FORCE = frozenset({'__emutls_get_address', '__cxa_thread_atexit'})
TLS = 0x510000000000
STUB = 0x600000000000
STUBSZ = 0x10000
JNIF = 0x620000000000
SENTINEL = 0x630000000000

DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_SYMENT = 0, 4, 5, 6, 11
DT_GNU_HASH, DT_JMPREL = 0x6FFFFEF5, 23
DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 25, 27
DT_INIT = 12
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
        # r32 latent fix: the old body wrote x1 copies of byte(x2) — the C
        # contract is memset(dest=x0, val=x1, n=x2). Value-0 calls looked
        # fine only because the fake world is zero-fresh.
        wr(x0, bytes([x1 & 0xFF]) * x2)
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

    # __emutls_get_address: one zeroed block per emutls object, cached by
    # object address (object header = {size, align}). Device semantics are
    # calloc-backed per-thread storage; the fake world's bump heap is
    # zero-fresh and never reused, so a plain dict gives exactly the same
    # observable behavior — including the guard byte a thread_local string
    # resolver flips after first initialization.
    emutls_vars = {}

    def f_emutls_get_address(x0, x1, x2, x3, x4=0, x5=0):
        p = emutls_vars.get(x0)
        if p is None:
            try:
                size = struct.unpack('<Q', rd(x0, 8))[0]
            except Exception:
                size = 0
            p = bump(min(max(size, 1), 0x100000))
            emutls_vars[x0] = p
        return p

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

    def f_lseek(x0, x1, x2, x3, x4=0, x5=0):
        # r22: the FS family lacked lseek — bit-stream readers seek past their
        # in-memory window into the source FILE (fd from the --fs bridge).
        f = files.get(x0)
        if not f:
            return -1
        f.seek(x1, x2 if x2 else 0)
        return f.tell()

    def f_ftell(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        return f.tell() if f else 0

    # dl bridge (r28): mini-linkers dlopen("")/their own libraries and resolve
    # self-symbols via dlsym — a NULL handle sends the shell into its embedded
    # INTERPRETER fallback (Battle-1: the interpreter_wrap_int64_t cascade was
    # exactly this — dlopen("") returns the SELF handle in a real process).
    DLOPEN_SELF = 0x530000000000

    def f_dlopen(x0, x1, x2, x3, x4=0, x5=0):
        return DLOPEN_SELF

    # r31: dlsym resolves against the whole emulated process, not only the
    # so's own exports — shells hand-resolve libc imports (dlopen("libc.so")
    # + dlsym) into cached runtime-table slots, and a 0 there becomes a null
    # function pointer (blr to 0) on first use. Known stub-table names bind
    # to FRESH slots in the upper STUB half, allocated lazily on first dlsym
    # and stable after (real dlsym: same name => same address); hook_stub
    # decodes them through _dlsym_rev. Unknown names return 0 — honest
    # "dlsym failed", callers check. (Three latent bugs fixed here: the
    # self-export loop unpacked 3-tuples as pairs — it raised on the first
    # defined symbol and the except swallowed it; the comparison was
    # str == bytes; and the old lazy path appended to an undefined
    # libc_names.)
    dlsym_slots = {}
    dlsym_rev = {}

    def f_dlsym(x0, x1, x2, x3, x4=0, x5=0):
        name = cstr(x1)
        try:
            for nm, val, _sz in elf.dyn_symbols():
                if nm.encode() == name and val:
                    return val
        except Exception:
            pass
        key = name.decode(errors='replace')
        if key not in dlsym_slots and callable(table.get(key)):
            sa = STUB + STUBSZ // 2 + 8 * len(dlsym_rev)
            dlsym_slots[key] = sa
            dlsym_rev[sa] = key
        return dlsym_slots.get(key, 0)

    # r31: fake-device property namespace (same philosophy as the getpid /
    # time / sysconf stubs: describes the emulated DEVICE, never any sample).
    # Unknown names answer len 0 = "property unset", like a real device.
    PROPS = {
        'ro.build.version.sdk': b'30',
        'ro.build.version.release': b'11',
        'ro.product.cpu.abi': b'arm64-v8a',
    }

    def f_prop_get(x0, x1, x2, x3, x4=0, x5=0):
        v = PROPS.get(cstr(x0).decode(errors='replace'), b'')
        wr(x1, v + b'\0')
        return len(v)

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
        # Battle-3 爱加密 lesson: a requested address is not noise. MAP_FIXED
        # (x3 & 0x10) is a hard contract — the caller requires exactly x0
        # (stage-2 decryptors remap their own .text span in place; land the
        # mapping anywhere else and the decrypted bytes never sit under the
        # PC — DT_INIT "completes" into still-encrypted code). A bare hint
        # (x0 != 0, no FIXED) is honored when the range is free, cursor
        # otherwise — kernel semantics both ways.
        length = x1 if x1 else 0x1000
        if length > 0x40000000:
            mmap_regions.append({'addr': 0, 'len': length, 'source': 'refused'})
            return 0
        span = ((x0 % PAGE) + length + PAGE - 1) & ~(PAGE - 1)
        addr = None
        if x0:
            cand = x0 & ~(PAGE - 1)
            if x3 & 0x10:  # MAP_FIXED — in-place remap: reuse the pages when
                addr = cand  # already mapped (unicorn world is RWX), else map
            else:
                try:
                    uc.mem_map(cand, span)
                    addr = cand  # hint honored
                except Exception:
                    addr = None  # busy — fall through to the cursor
        if addr is None:
            addr = (mmap_cursor[0] + PAGE - 1) & ~(PAGE - 1)
            mmap_cursor[0] = addr + span
        try:
            uc.mem_map(addr, span)
        except Exception:
            pass  # already mapped (initial heap window / in-place remap)
        f = files.get(x4)
        if f:
            f.seek(x5)
            blob = f.read(length)
            uc.mem_write(addr + (x0 % PAGE), blob)
            mmap_regions.append({'addr': addr, 'len': len(blob), 'source': 'fd:%s' % f.name})
        else:
            zero = b'\0' * min(length, 0x400000)
            uc.mem_write(addr + (x0 % PAGE), zero)
            mmap_regions.append({'addr': addr, 'len': length, 'source': 'anon'})
        return x0 if (x0 and (x3 & 0x10)) else addr

    # Raw-syscall bridge (r27, Battle-1 r26 discovery): modern shells carry their
    # own syscall stubs ('mov x8,#N; svc #0') to bypass libc hooks entirely —
    # PLT/GOT bridging never sees these calls. SVC raises UC_HOOK_INTR (intno=2);
    # the handler shares the --fs file table and fd counter with the fopen bridge,
    # so paths served to fopen() and openat() stay one world. Unknown numbers are
    # logged (forensics: which kernel surface the shell touches) and return 0.
    svc_events = []

    def _ret_errno(uc_, n):
        uc_.reg_write(UC_ARM64_REG_X0, (1 << 64) - n & 0xFFFFFFFFFFFFFFFF)

    def hook_svc(uc_, intno, ud):
        if intno != 2:
            # NOT an SVC: a synchronous CPU exception (undefined insn — e.g.
            # VMP/encrypted code executed before its runtime decrypt, or a
            # bogus entry point). unicorn re-executes the faulting insn when
            # the hook returns untouched, so a bare `return` spins the entry
            # into a silent full-timeout burn (Battle-3: SecLLVM-hardened
            # 爱加密 libexec.so — every init_array entry ate the whole
            # --timeout with zero diagnostics). Stop loud instead; the
            # caller raises on the marker and the run reports the scene.
            svc_events.append({'exception': intno,
                               'pc': '0x%x' % uc_.reg_read(UC_ARM64_REG_PC),
                               'lr': '0x%x' % uc_.reg_read(UC_ARM64_REG_LR),
                               'detail': 'sync CPU exception (not SVC) — undefined insn / encrypted code'})
            uc_.emu_stop()
            return
        x8 = uc_.reg_read(UC_ARM64_REG_X8)
        x0, x1, x2 = (uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
        if x8 == 56:  # openat(dirfd, pathname, flags, mode) — fs_map prefix semantics as fopen
            path = cstr(x1).decode(errors='replace')
            real = fs_map.get(path)
            if real is None:
                for k, v in fs_map.items():
                    if path.startswith(k):
                        real = v
                        break
            if real is None:
                svc_events.append({'svc': 'openat', 'path': path, 'ret': -2})
                _ret_errno(uc_, 2)  # -ENOENT
                return
            fd = FD[0]
            FD[0] += 1
            files[fd] = open(real, 'rb')
            svc_events.append({'svc': 'openat', 'path': path, 'fd': fd})
            uc_.reg_write(UC_ARM64_REG_X0, fd)
            return
        if x8 == 57:  # close(fd)
            f = files.pop(x0, None)
            if f:
                f.close()
            uc_.reg_write(UC_ARM64_REG_X0, 0)
            return
        if x8 == 62:  # lseek(fd, offset, whence) — signed offset, valid whence only
            f = files.get(x0)
            if not f:
                _ret_errno(uc_, 9)  # -EBADF
                return
            off = x1 - (1 << 64) if x1 >= (1 << 63) else x1
            try:
                f.seek(off, x2 if x2 in (0, 1, 2) else 0)
            except (ValueError, OSError):
                _ret_errno(uc_, 22)  # -EINVAL
                return
            uc_.reg_write(UC_ARM64_REG_X0, f.tell() & 0xFFFFFFFFFFFFFFFF)
            return
        if x8 == 63:  # read(fd, buf, count)
            f = files.get(x0)
            if not f:
                _ret_errno(uc_, 9)
                return
            blob = f.read(x2)
            wr(x1, blob)
            uc_.reg_write(UC_ARM64_REG_X0, len(blob))
            return
        if x8 == 64:  # write(fd, buf, count) — pretend success (no sink)
            uc_.reg_write(UC_ARM64_REG_X0, x2)
            return
        if x8 == 222:  # mmap(addr,len,prot,flags,fd,off) — f_mmap reads x1/x4/x5, same slots
            r = f_mmap(x0, uc_.reg_read(UC_ARM64_REG_X1), uc_.reg_read(UC_ARM64_REG_X2),
                       uc_.reg_read(UC_ARM64_REG_X3), uc_.reg_read(UC_ARM64_REG_X4),
                       uc_.reg_read(UC_ARM64_REG_X5))
            svc_events.append({'svc': 'mmap', 'req': '0x%x' % x0, 'len': x1,
                               'flags': '0x%x' % uc_.reg_read(UC_ARM64_REG_X3),
                               'ret': '0x%x' % (r & 0xFFFFFFFFFFFFFFFF)})
            uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
            return
        if x8 == 226:  # mprotect(addr,len,prot) — hardened shells flip their
            # freshly-decrypted .text R+X; the old fallthrough logged 'unknown'
            # and returned 0, hiding the whole stage-2 chain (Battle-3 爱加密).
            # Apply perms best-effort (never crash the run on protect itself).
            svc_events.append({'svc': 'mprotect', 'addr': '0x%x' % x0,
                               'len': x1, 'prot': x2})
            try:
                lo = x0 & ~(PAGE - 1)
                hi = (x0 + x1 + PAGE - 1) & ~(PAGE - 1)
                uc_.mem_protect(lo, hi - lo, x2 & 7 or 1)
            except Exception:
                pass
            uc_.reg_write(UC_ARM64_REG_X0, 0)
            return
        if x8 == 215:  # munmap(addr,len) — stage teardown (e.g. the stage-1
            # region after in-place decryption); keep pages (cheap), but the
            # event must be visible in the trace.
            svc_events.append({'svc': 'munmap', 'addr': '0x%x' % x0, 'len': x1})
            uc_.reg_write(UC_ARM64_REG_X0, 0)
            return
        if x8 in (93, 94):  # exit / exit_group — stop; x0 already holds the code
            svc_events.append({'svc': 'exit', 'code': x0})
            uc_.emu_stop()
            return
        # benign-noise surface (threads/time/robust/prctl/kill/…): succeed quietly
        if x8 == 96:  # set_tid_address returns a tid
            uc_.reg_write(UC_ARM64_REG_X0, 1234)
            return
        if x8 not in (57, 98, 99, 129, 135, 167, 215, 124, 172, 173, 174, 175, 178, 233):
            svc_events.append({'svc': 'unknown', 'nr': x8, 'x0': '0x%x' % x0,
                               'x1': '0x%x' % x1, 'x2': '0x%x' % x2})
        uc_.reg_write(UC_ARM64_REG_X0, 0)

    # printf engine (r30): shells build runtime strings (pref names, class
    # descriptors, tag keys) with sprintf/snprintf/__sprintf_chk — a return-0
    # stub leaves the buffer zeroed and every downstream consumer sees "".
    # AAPCS64 variadic: named args in x-regs, varargs continue in x-regs then
    # spill to the stack. FP varargs (v-regs) are rare in shell code — degrade
    # to 0 rather than crash.
    def _varg_reader(first_reg):
        """closure: nth vararg value, regs x{first_reg}..x7 then stack."""
        def nth(k):
            reg_idx = first_reg + k
            if reg_idx <= 7:
                reg = {2: UC_ARM64_REG_X2, 3: UC_ARM64_REG_X3, 4: UC_ARM64_REG_X4,
                       5: UC_ARM64_REG_X5, 6: UC_ARM64_REG_X6, 7: UC_ARM64_REG_X7}[reg_idx]
                return uc.reg_read(reg)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            return struct.unpack('<Q', bytes(uc.mem_read(sp + (reg_idx - 8) * 8, 8)))[0]
        return nth

    def _fmt_render(fmt_addr, nth):
        fmt = cstr(fmt_addr).decode('utf-8', 'replace')
        out = bytearray()
        ai = 0
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c != '%':
                out += c.encode(); i += 1; continue
            i += 1
            if i < len(fmt) and fmt[i] == '%':
                out += b'%'; i += 1; continue
            # flags/width/precision (consumed, honored only minimally)
            while i < len(fmt) and fmt[i] in '-+ #00123456789.':
                i += 1
            while i < len(fmt) and fmt[i] in 'hljztL':
                i += 1
            if i >= len(fmt):
                break
            spec = fmt[i]; i += 1
            v = nth(ai); ai += 1
            if spec in 'diu':
                out += str(v if spec == 'u' else
                            (v - (1 << 64) if v & (1 << 63) else v)).encode()
            elif spec in 'xX':
                out += (('%x' if spec == 'x' else '%X') % v).encode()
            elif spec == 'c':
                out += bytes([v & 0xFF])
            elif spec == 'p':
                out += ('0x%x' % v).encode()
            elif spec == 's':
                out += cstr(v) if v else b'(null)'
            else:
                out += ('%%%c' % spec).encode()
        return bytes(out)

    def _mk_printf(first_reg, dest_arg=0, size_arg=None):
        def f(x0, x1, x2, x3, x4=0, x5=0):
            args = (x0, x1, x2, x3, x4, x5)
            fmt_addr = args[first_reg - 1] if first_reg >= 2 else x1
            rendered = _fmt_render(fmt_addr, _varg_reader(first_reg))
            buf = args[dest_arg]
            if size_arg is not None:
                cap = args[size_arg]
                rendered = rendered[:max(0, cap - 1)]
            wr(buf, rendered + b'\0')
            return len(rendered)
        return f

    f_sprintf = _mk_printf(2)                      # sprintf(buf, fmt, ...)
    f_snprintf = _mk_printf(3, size_arg=1)         # snprintf(buf, n, fmt, ...)
    f_sprintf_chk = _mk_printf(4)                  # __sprintf_chk(buf, flag, slen, fmt, ...)
    f_snprintf_chk = _mk_printf(5, size_arg=1)     # __snprintf_chk(buf, n, flag, slen, fmt, ...)

    # r32: 伪 libc 覆盖面（libc surface）。真壳 import 面 150+ 个 libc 名；每个
    # 未实现的都塌缩成静默 return-0 桩 —— 对"返回值被消费"的函数那不是良性默认，
    # 而是把壳的控制流推上错误分支（Battle-3 爱加密：VMP 环境门做
    # atoi(__system_property_get(sdk)) 再按结果分派；atoi 缺失 => 0 => "上古设备"
    # => 引擎走 legacy 路径调用一张没人注册过的表槽 => blr 0）。以下语义全部是
    # 设备通用：该解析/扫描/拷贝的真做字节级语义，进程面（pid/tid/pagesize）给
    # 常量，只有诚实答案确实是"无副作用成功"的地方才静默（信号/锁/无内核世界）。
    # 真正做不到的（qsort 比较器、dl_iterate_phdr、longjmp —— unicorn 钩子内
    # 不可重入 emu_start）记录进 _deferred，绝不静默。
    deferred = []
    once_pending = []

    def _parse_int(a, base):
        s = cstr(a).decode(errors='replace')
        i = 0
        while i < len(s) and s[i] in ' \t\n\r\v\f':
            i += 1
        neg = False
        if i < len(s) and s[i] in '+-':
            neg = s[i] == '-'
            i += 1
        if base == 0:
            if s[i:i + 2].lower() == '0x':
                base, i = 16, i + 2
            elif s[i:i + 1] == '0':
                base = 8
            else:
                base = 10
        elif base == 16 and s[i:i + 2].lower() == '0x':
            i += 2
        v = 0
        while i < len(s):
            c = s[i].lower()
            d = ord(c) - 48 if '0' <= c <= '9' else (ord(c) - 87 if 'a' <= c <= 'f' else 99)
            if d >= base:
                break
            v = v * base + d
            i += 1
        return (-v if neg else v) & 0xFFFFFFFFFFFFFFFF, i

    def f_atoi(x0, x1, x2, x3, x4=0, x5=0):
        return _parse_int(x0, 10)[0]

    def f_strtol(x0, x1, x2, x3, x4=0, x5=0):
        v, n = _parse_int(x0, x2)
        if x1:
            wr(x1, struct.pack('<Q', x0 + n))
        return v

    def f_strchr(x0, x1, x2, x3, x4=0, x5=0):
        s = cstr(x0)
        c = x1 & 0xFF
        if c == 0:
            return x0 + len(s)  # strchr(s, 0) 指向结尾 NUL —— C 标准语义
        i = s.find(bytes([c]))
        return x0 + i if i >= 0 else 0

    def f_strrchr(x0, x1, x2, x3, x4=0, x5=0):
        s = cstr(x0)
        i = s.rfind(bytes([x1 & 0xFF]))
        return x0 + i if i >= 0 else 0

    def f_strstr(x0, x1, x2, x3, x4=0, x5=0):
        i = cstr(x0).find(cstr(x1))
        return x0 + i if i >= 0 else 0

    def f_strcasestr(x0, x1, x2, x3, x4=0, x5=0):
        i = cstr(x0).lower().find(cstr(x1).lower())
        return x0 + i if i >= 0 else 0

    def f_strspn(x0, x1, x2, x3, x4=0, x5=0):
        s, acc = bytes(cstr(x0)), set(bytes(cstr(x1)))
        n = 0
        while n < len(s) and s[n] in acc:
            n += 1
        return n

    def f_strcspn(x0, x1, x2, x3, x4=0, x5=0):
        s, rej = bytes(cstr(x0)), set(bytes(cstr(x1)))
        n = 0
        while n < len(s) and s[n] not in rej:
            n += 1
        return n

    def f_strncmp(x0, x1, x2, x3, x4=0, x5=0):
        a, b = rd(x0, x2), rd(x1, x2)
        for k in range(x2):
            if a[k] != b[k]:
                return -1 if a[k] < b[k] else 1
            if a[k] == 0:
                return 0
        return 0

    def f_strncasecmp(x0, x1, x2, x3, x4=0, x5=0):
        a, b = rd(x0, x2), rd(x1, x2)
        for k in range(x2):
            ca, cb = a[k], b[k]
            ca = ca + 32 if 65 <= ca <= 90 else ca
            cb = cb + 32 if 65 <= cb <= 90 else cb
            if ca != cb:
                return -1 if ca < cb else 1
            if ca == 0:
                return 0
        return 0

    def f_strnlen(x0, x1, x2, x3, x4=0, x5=0):
        i = rd(x0, x1).find(b'\0')
        return i if i >= 0 else x1

    def f_strdup(x0, x1, x2, x3, x4=0, x5=0):
        s = cstr(x0) + b'\0'
        p = bump(len(s))
        if p:
            wr(p, s)
        return p

    strtok_state = [0]

    def f_strtok(x0, x1, x2, x3, x4=0, x5=0):
        buf = x0 or strtok_state[0]
        if not buf:
            return 0
        d = set(bytes(cstr(x1)))
        s = bytes(cstr(buf))
        i = 0
        while i < len(s) and s[i] in d:
            i += 1
        if i == len(s):
            strtok_state[0] = 0
            return 0
        j = i
        while j < len(s) and s[j] not in d:
            j += 1
        if j < len(s):
            wr(buf + j, b'\0')
            strtok_state[0] = buf + j + 1
        else:
            strtok_state[0] = 0
        return buf + i

    def f_strlcpy(x0, x1, x2, x3, x4=0, x5=0):
        s = cstr(x1)
        if x2:
            wr(x0, s[:x2 - 1] + b'\0')
        return len(s)

    def f_memchr(x0, x1, x2, x3, x4=0, x5=0):
        i = rd(x0, x2).find(bytes([x1 & 0xFF]))
        return x0 + i if i >= 0 else 0

    def f_memmem(x0, x1, x2, x3, x4=0, x5=0):
        i = rd(x0, x1).find(rd(x2, x3))
        return x0 + i if i >= 0 else 0

    def f_tolower(x0, x1, x2, x3, x4=0, x5=0):
        c = x0 & 0xFF
        return c + 32 if 65 <= c <= 90 else c

    def f_strcpy(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0, cstr(x1) + b'\0')
        return x0

    def f_strcat(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0 + len(cstr(x0)), cstr(x1) + b'\0')
        return x0

    def f_strncpy(x0, x1, x2, x3=0, x4=0, x5=0):
        wr(x0, cstr(x1)[:x2].ljust(x2, b'\0'))
        return x0

    # _chk 加固变体：前三个参数与基函数相同，bound/flag 参数直接忽略。
    def f_memcpy_chk(x0, x1, x2, x3, x4=0, x5=0):
        return f_memcpy(x0, x1, x2)

    def f_memset_chk(x0, x1, x2, x3, x4=0, x5=0):
        return f_memset(x0, x1, x2)

    # 进程/系统面：常量描述仿真设备（与 PROPS/getpid/time 同一哲学）。
    def f_getauxval(x0, x1, x2, x3, x4=0, x5=0):
        if x0 == 6:
            return 4096            # AT_PAGESZ
        if x0 == 23:
            return 0               # AT_SECURE：非 setuid —— 诚实
        if x0 == 25:               # AT_RANDOM：16 字节确定性内容（非样本派生）
            p = bump(16)
            wr(p, bytes(range(16)))
            return p
        return 0

    def f_exit(x0, x1, x2, x3, x4=0, x5=0):
        svc_events.append({'libc_exit': x0})
        uc.emu_stop()
        return 0

    def f_stack_chk_fail(x0, x1, x2, x3, x4=0, x5=0):
        # 真设备上这是进程死亡 —— 大声停下，绝不静默落进下一函数（旧的
        # return-0 桩会让执行流摔进 __stack_chk_fail 后面的随机代码）。
        svc_events.append({'stack_chk_fail': 1})
        uc.emu_stop()
        return 0

    def f_sigemptyset(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0, b'\0' * 8)
        return 0

    def f_sigfillset(x0, x1, x2, x3, x4=0, x5=0):
        wr(x0, b'\xff' * 8)
        return 0

    def f_sigaddset(x0, x1, x2, x3, x4=0, x5=0):
        v = struct.unpack('<Q', rd(x0, 8))[0] | (1 << ((x1 - 1) & 63))
        wr(x0, struct.pack('<Q', v))
        return 0

    def f_sigismember(x0, x1, x2, x3, x4=0, x5=0):
        return (struct.unpack('<Q', rd(x0, 8))[0] >> ((x1 - 1) & 63)) & 1

    def f_sigsetjmp(x0, x1, x2, x3, x4=0, x5=0):
        deferred.append({'call': 'sigsetjmp', 'note': 'returns 0 (direct path); longjmp not modeled'})
        return 0

    def f_siglongjmp(x0, x1, x2, x3, x4=0, x5=0):
        deferred.append({'call': 'siglongjmp', 'val': x1})
        return 0

    # pthread/sem：无并发世界 —— 锁与信号量是诚实的无副作用成功；pthread_once
    # 的 init 例程不可在钩子内重入执行，记录待决（与 pthread_create 同一哲学）。
    pthread_keys = {}

    def f_pthread_key_create(x0, x1, x2, x3, x4=0, x5=0):
        k = len(pthread_keys) + 1
        pthread_keys[k] = 0
        wr(x0, struct.pack('<I', k))
        return 0

    def f_pthread_getspecific(x0, x1, x2, x3, x4=0, x5=0):
        return pthread_keys.get(x0, 0)

    def f_pthread_setspecific(x0, x1, x2, x3, x4=0, x5=0):
        pthread_keys[x0] = x1
        return 0

    def f_pthread_once(x0, x1, x2, x3, x4=0, x5=0):
        if struct.unpack('<I', rd(x0, 4))[0] == 0:
            wr(x0, struct.pack('<I', 1))
            once_pending.append(x1)
        return 0

    def f_posix_memalign(x0, x1, x2, x3, x4=0, x5=0):
        p = bump(max(x2, 1))
        if not p:
            return 12  # ENOMEM
        wr(x0, struct.pack('<Q', p))
        return 0

    def f_realloc(x0, x1, x2, x3, x4=0, x5=0):
        p = bump(max(x1, 1))
        if p and x0:
            wr(p, rd(x0, min(x1, 0x100000)))
        return p

    # fd 层 I/O：与 --fs 桥共享一张文件表（fd 即 FILE*，本世界一贯如此）。
    def _fs_real(path):
        real = fs_map.get(path)
        if real is None:
            for k, v in fs_map.items():
                if path.startswith(k):
                    real = v
                    break
        return real

    def f_open(x0, x1, x2, x3, x4=0, x5=0):
        real = _fs_real(cstr(x0).decode(errors='replace'))
        if real is None:
            return -1 & 0xFFFFFFFFFFFFFFFF
        fd = FD[0]
        FD[0] += 1
        files[fd] = open(real, 'rb')
        return fd

    def f_read(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return -1 & 0xFFFFFFFFFFFFFFFF
        blob = f.read(x2)
        wr(x1, blob)
        return len(blob)

    def f_close(x0, x1, x2, x3, x4=0, x5=0):
        f = files.pop(x0, None)
        if f:
            try:
                f.close()
            except Exception:
                pass
        return 0

    def _stat_fill(buf, size):
        wr(buf, b'\0' * 128)
        wr(buf + 16, struct.pack('<I', 0o100644))  # st_mode = S_IFREG|0644
        wr(buf + 20, struct.pack('<I', 1))         # st_nlink
        wr(buf + 40, struct.pack('<q', size))      # st_size (bionic arm64)
        wr(buf + 48, struct.pack('<q', 4096))      # st_blksize

    def f_stat(x0, x1, x2, x3, x4=0, x5=0):
        real = _fs_real(cstr(x0).decode(errors='replace'))
        if real is None:
            return -1 & 0xFFFFFFFFFFFFFFFF
        _stat_fill(x1, os.path.getsize(real))
        return 0

    def f_fstat(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return -1 & 0xFFFFFFFFFFFFFFFF
        pos = f.tell()
        f.seek(0, 2)
        size = f.tell()
        f.seek(pos)
        _stat_fill(x1, size)
        return 0

    def f_access(x0, x1, x2, x3, x4=0, x5=0):
        ok = _fs_real(cstr(x0).decode(errors='replace')) is not None
        return 0 if ok else -1 & 0xFFFFFFFFFFFFFFFF

    def f_readlink(x0, x1, x2, x3, x4=0, x5=0):
        deferred.append({'call': 'readlink', 'path': cstr(x0).decode(errors='replace')})
        return -1 & 0xFFFFFFFFFFFFFFFF

    def f_pipe(x0, x1, x2, x3, x4=0, x5=0):
        import io
        r, w = FD[0], FD[0] + 1
        FD[0] += 2
        files[r] = io.BytesIO(b'')
        files[w] = io.BytesIO()
        wr(x0, struct.pack('<II', r, w))
        return 0

    def f_fgets(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x2)
        if not f:
            return 0
        data = b''
        while len(data) < x1 - 1:
            c = f.read(1)
            if not c:
                break
            data += c
            if c == b'\n':
                break
        if not data:
            return 0
        wr(x0, data + b'\0')
        return x0

    def f_fgetc(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return -1 & 0xFFFFFFFFFFFFFFFF
        b = f.read(1)
        return b[0] if b else -1 & 0xFFFFFFFFFFFFFFFF

    def f_feof(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return 1
        pos = f.tell()
        b = f.read(1)
        f.seek(pos)
        return 0 if b else 1

    def f_fwrite(x0, x1, x2, x3, x4=0, x5=0):
        return x2  # 无汇世界：报告全部 nmemb 已写

    def f_rewind(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if f:
            f.seek(0)
        return 0

    # va_list（AAPCS64: {__stack, __gr_top, __vr_top, __gr_offs, __vr_offs}）—
    # 整数变参按序推进；FP 变参壳代码罕见，降级不取。
    def _va_reader(va):
        def nth(_k):  # 顺序调用即语义（_fmt_render 总是 ai 递增）
            stack, gr_top = struct.unpack('<QQ', rd(va, 16))
            gr_offs = struct.unpack('<i', rd(va + 24, 4))[0]
            if gr_offs < 0:
                v = struct.unpack('<Q', rd(gr_top + gr_offs, 8))[0]
                wr(va + 24, struct.pack('<i', gr_offs + 8))
            else:
                v = struct.unpack('<Q', rd(stack, 8))[0]
                wr(va, struct.pack('<Q', stack + 8))
            return v
        return nth

    def _mk_vprintf(fmt_arg, va_arg, dest_arg=None, size_arg=None):
        def f(x0, x1, x2, x3, x4=0, x5=0):
            args = (x0, x1, x2, x3, x4, x5)
            rendered = _fmt_render(args[fmt_arg], _va_reader(args[va_arg]))
            if dest_arg is None:
                return len(rendered)  # printf/vfprintf：无汇，报告长度
            buf = args[dest_arg]
            if size_arg is not None:
                rendered = rendered[:max(0, args[size_arg] - 1)]
            wr(buf, rendered + b'\0')
            return len(rendered)
        return f

    f_printf = _mk_printf(1)                       # printf(fmt, ...)
    f_fprintf = _mk_printf(2)                      # fprintf(fp, fmt, ...) — fp 忽略
    f_vfprintf = _mk_vprintf(1, 2)                 # vfprintf(fp, fmt, va)
    f_vsnprintf = _mk_vprintf(2, 3, dest_arg=0, size_arg=1)
    f_vsnprintf_chk = _mk_vprintf(4, 5, dest_arg=0, size_arg=1)  # (buf,n,flag,slen,fmt,va)
    f_vsprintf_chk = _mk_vprintf(3, 4, dest_arg=0)               # (buf,flag,slen,fmt,va)

    def f_vasprintf(x0, x1, x2, x3, x4=0, x5=0):
        rendered = _fmt_render(x1, _va_reader(x2))
        p = bump(len(rendered) + 1)
        if not p:
            return -1 & 0xFFFFFFFFFFFFFFFF
        wr(p, rendered + b'\0')
        wr(x0, struct.pack('<Q', p))
        return len(rendered)

    # scanf 引擎：maps 扫描链的 "%08x-%08x %s %s %s %d %s" 一类格式 —
    # 支持宽度、空白折叠、字面量、d/i/u/x/o/p/s/c；按 l 数修正存储宽度。
    def _fmt_scan(fmt, getch, nth):
        pushback = []

        def gc():
            if pushback:
                return pushback.pop()
            return getch()

        def ungc(c):
            pushback.append(c)

        i = 0
        assigned = 0
        while i < len(fmt):
            c = fmt[i]
            if c.isspace():
                while True:
                    ch = gc()
                    if ch is None:
                        break
                    if not chr(ch).isspace():
                        ungc(ch)
                        break
                i += 1
                continue
            if c != '%':
                ch = gc()
                if ch is None or ch != ord(c):
                    if ch is not None:
                        ungc(ch)
                    return assigned
                i += 1
                continue
            i += 1
            suppress = False
            if i < len(fmt) and fmt[i] == '*':
                suppress = True
                i += 1
            width = 0
            while i < len(fmt) and fmt[i].isdigit():
                width = width * 10 + int(fmt[i])
                i += 1
            lmod = 0
            while i < len(fmt) and fmt[i] in 'hljztL':
                lmod += 1 if fmt[i] == 'l' else 0
                i += 1
            if i >= len(fmt):
                break
            spec = fmt[i]
            i += 1
            if spec in 'diuxop':
                ch = gc()
                while ch is not None and chr(ch).isspace():
                    ch = gc()
                tok = ''
                if ch is not None and chr(ch) in '+-':
                    tok += chr(ch)
                    ch = gc()
                lim = width or 64
                while ch is not None and len(tok.lstrip('+-')) < lim and chr(ch).isalnum():
                    tok += chr(ch)
                    ch = gc()
                if ch is not None:
                    ungc(ch)
                if not tok or tok in '+-':
                    return assigned
                base = {'d': 10, 'i': 0, 'u': 10, 'x': 16, 'o': 8, 'p': 16}[spec]
                try:
                    v = int(tok, base)
                except ValueError:
                    return assigned
                if not suppress:
                    ptr = nth(assigned)
                    assigned += 1
                    if lmod >= 2:
                        wr(ptr, struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF))
                    else:
                        wr(ptr, struct.pack('<I', v & 0xFFFFFFFF))
                continue
            if spec in 'sc':
                ch = gc()
                if spec == 's':
                    while ch is not None and chr(ch).isspace():
                        ch = gc()
                buf = bytearray()
                lim = width or (1 if spec == 'c' else 4096)
                while ch is not None and len(buf) < lim and (spec == 'c' or not chr(ch).isspace()):
                    buf.append(ch)
                    ch = gc()
                if ch is not None and spec == 's':
                    ungc(ch)
                if not buf and spec == 's':
                    return assigned
                if not suppress:
                    ptr = nth(assigned)
                    assigned += 1
                    wr(ptr, bytes(buf) + (b'\0' if spec == 's' else b''))
                continue
            if spec == '%':
                ch = gc()
                if ch != ord('%'):
                    if ch is not None:
                        ungc(ch)
                    return assigned
                continue
            return assigned
        return assigned

    def f_sscanf(x0, x1, x2, x3, x4=0, x5=0):
        src = bytes(cstr(x0))
        pos = [0]

        def getch():
            if pos[0] >= len(src):
                return None
            b = src[pos[0]]
            pos[0] += 1
            return b

        return _fmt_scan(cstr(x1).decode(errors='replace'), getch, _varg_reader(2))

    def f_fscanf(x0, x1, x2, x3, x4=0, x5=0):
        f = files.get(x0)
        if not f:
            return -1 & 0xFFFFFFFFFFFFFFFF

        def getch():
            b = f.read(1)
            return b[0] if b else None

        return _fmt_scan(cstr(x1).decode(errors='replace'), getch, _varg_reader(2))

    def f_qsort(x0, x1, x2, x3, x4=0, x5=0):
        # 比较器是访客代码 —— 钩子内不可重入 emu_start；记录待决而非静默
        # "排序完成"（错序比不排更糟）或崩溃。
        deferred.append({'call': 'qsort', 'base': '0x%x' % x0, 'n': x1,
                         'size': x2, 'cmp': '0x%x' % x3})
        return 0

    def f_dl_iterate_phdr(x0, x1, x2, x3, x4=0, x5=0):
        deferred.append({'call': 'dl_iterate_phdr', 'cb': '0x%x' % x0})
        return 0

    def f_mprotect_libc(x0, x1, x2, x3, x4=0, x5=0):
        try:
            lo = x0 & ~(PAGE - 1)
            hi = (x0 + x1 + PAGE - 1) & ~(PAGE - 1)
            uc.mem_protect(lo, hi - lo, x2 & 7 or 1)
        except Exception:
            pass
        return 0

    def f_syscall(x0, x1, x2, x3, x4=0, x5=0):
        svc_events.append({'svc': 'libc_syscall', 'nr': x0})
        return 0

    def f_time(x0, x1, x2, x3, x4=0, x5=0):
        if x0:
            wr(x0, struct.pack('<q', 1234))
        return 1234

    # JNI 资产面：AssetManager 句柄给非空（世界里有管理器），具体资产诚实
    # 报"未找到"（容器字节经 --load/--fs 桥显式注入，不走隐式资产层）。
    def f_aasset_manager(x0, x1, x2, x3, x4=0, x5=0):
        return bump(16)

    table = {
        'malloc': f_malloc, '_Znwm': f_malloc, '_Znam': f_malloc, 'calloc': f_calloc,
        'free': f_free, '_ZdlPv': f_free, '_ZdaPv': f_free,
        'memcpy': f_memcpy, 'memmove': f_memcpy, 'memset': f_memset,
        'memcmp': f_memcmp, 'strlen': f_strlen, '__strlen_chk': f_strlen,
        'strcmp': f_strcmp, 'strcpy': f_strcpy, 'strcat': f_strcat, 'strncpy': f_strncpy,
        'snprintf': f_snprintf, 'sprintf': f_sprintf,
        '__snprintf_chk': f_snprintf_chk, '__sprintf_chk': f_sprintf_chk,
        '__aarch64_sync_cache_range': f_noop, 'pthread_mutex_init': f_noop,
        'pthread_mutex_lock': f_noop, 'pthread_mutex_unlock': f_noop,
        'pthread_detach': f_noop, '__cxa_atexit': f_noop, '__cxa_finalize': f_noop,
        'time': f_time, 'getpid': lambda x0, x1, x2, x3, x4=0, x5=0: 1234,
        'getppid': lambda x0, x1, x2, x3, x4=0, x5=0: 1,
        'gettid': lambda x0, x1, x2, x3, x4=0, x5=0: 1234,
        'getpagesize': lambda x0, x1, x2, x3, x4=0, x5=0: 4096,
        'srand': f_noop, 'rand': lambda x0, x1, x2, x3, x4=0, x5=0: 42,
        'dladdr': lambda x0, x1, x2, x3, x4=0, x5=0: (
            # r29: shells self-locate via dladdr(self_fn, &info) and store
            # dli_fbase as a runtime-table pointer (the polymorphic-ELF
            # pattern: the so's own mapped header doubles as the encrypted
            # table; fbase+0 IS the cipher). Emulator mapping base = 0.
            wr(x1, struct.pack('<QQQQ', 0, 0, 0, x0)), 1)[1],
        'dlerror': f_noop, '__errno': f_errno, 'sysconf': lambda x0, x1, x2, x3, x4=0, x5=0: 4096,
        '__emutls_get_address': f_emutls_get_address, '__cxa_thread_atexit': f_noop,
        'dlopen': f_dlopen, 'dlsym': f_dlsym, 'dlclose': f_noop,
        # r31: names shells resolve by hand through dlopen+dlsym. Signal
        # registration is a success-noop in a world with no signal delivery.
        '__system_property_get': f_prop_get,
        'sigaction': f_noop, 'sigaction64': f_noop,
        'sigprocmask': f_noop, 'sigprocmask64': f_noop,
        'inflate': f_inflate, 'inflateInit_': f_inflateInit_, 'inflateEnd': f_inflateEnd,
        'fopen': f_fopen, 'fread': f_fread, 'fclose': f_fclose,
        'fseek': f_fseek, 'lseek': f_lseek, 'ftell': f_ftell,
        'mmap': f_mmap, 'munmap': f_noop,
        'pthread_create': f_pthread_create,
        # r32: libc surface（见上方 r32 块注释 —— 静默 0 会劫持壳控制流）
        'atoi': f_atoi, 'atol': f_atoi, 'strtol': f_strtol, 'strtoul': f_strtol,
        'strchr': f_strchr, 'strrchr': f_strrchr, 'strstr': f_strstr,
        'strcasestr': f_strcasestr, 'strspn': f_strspn, 'strcspn': f_strcspn,
        'strncmp': f_strncmp, 'strncasecmp': f_strncasecmp, 'strnlen': f_strnlen,
        'strdup': f_strdup, 'strtok': f_strtok, 'strlcpy': f_strlcpy,
        'memchr': f_memchr, 'memmem': f_memmem, 'tolower': f_tolower,
        '__memcpy_chk': f_memcpy_chk, '__memmove_chk': f_memcpy_chk,
        '__memset_chk': f_memset_chk, '__strcat_chk': f_strcat,
        '__strcpy_chk': f_strcpy, '__strncpy_chk': f_strncpy,
        '__strchr_chk': f_strchr,
        'getauxval': f_getauxval, 'prctl': f_noop, 'ptrace': f_noop,
        'kill': f_noop, 'fork': f_noop, 'wait': f_noop, 'waitpid': f_noop,
        'sleep': f_noop, 'exit': f_exit, 'abort': f_exit,
        'android_set_abort_message': f_noop, '__stack_chk_fail': f_stack_chk_fail,
        'signal': f_noop, 'sigemptyset': f_sigemptyset, 'sigemptyset64': f_sigemptyset,
        'sigfillset': f_sigfillset, 'sigfillset64': f_sigfillset,
        'sigaddset': f_sigaddset, 'sigaddset64': f_sigaddset,
        'sigismember': f_sigismember, 'sigismember64': f_sigismember,
        'sigsetjmp': f_sigsetjmp, 'siglongjmp': f_siglongjmp,
        'pthread_attr_init': f_noop, 'pthread_attr_destroy': f_noop,
        'pthread_attr_setdetachstate': f_noop, 'pthread_mutex_destroy': f_noop,
        'pthread_rwlock_rdlock': f_noop, 'pthread_rwlock_wrlock': f_noop,
        'pthread_rwlock_unlock': f_noop,
        'pthread_key_create': f_pthread_key_create,
        'pthread_key_delete': f_noop,
        'pthread_getspecific': f_pthread_getspecific,
        'pthread_setspecific': f_pthread_setspecific,
        'pthread_once': f_pthread_once,
        'sem_init': f_noop, 'sem_destroy': f_noop, 'sem_post': f_noop, 'sem_wait': f_noop,
        'posix_memalign': f_posix_memalign, 'realloc': f_realloc,
        'open': f_open, 'read': f_read, 'close': f_close, 'lseek64': f_lseek,
        'stat': f_stat, 'lstat': f_stat, 'fstat': f_fstat, 'access': f_access,
        'readlink': f_readlink, 'unlink': f_noop, 'rmdir': f_noop, 'remove': f_noop,
        'pipe': f_pipe, 'fdopen': lambda x0, x1, x2, x3, x4=0, x5=0: x0,
        'fileno': lambda x0, x1, x2, x3, x4=0, x5=0: x0,
        'flock': f_noop, 'perror': f_noop, 'fgets': f_fgets, 'fgetc': f_fgetc,
        'fputc': lambda x0, x1, x2, x3, x4=0, x5=0: x0 & 0xFF,
        'fwrite': f_fwrite, 'feof': f_feof, 'fflush': f_noop, 'fsync': f_noop,
        'rewind': f_rewind, 'opendir': f_noop, 'readdir': f_noop, 'closedir': f_noop,
        'printf': f_printf, 'fprintf': f_fprintf, 'vfprintf': f_vfprintf,
        'vsnprintf': f_vsnprintf, 'vasprintf': f_vasprintf,
        '__vsnprintf_chk': f_vsnprintf_chk, '__vsprintf_chk': f_vsprintf_chk,
        'sscanf': f_sscanf, 'fscanf': f_fscanf,
        'qsort': f_qsort, 'dl_iterate_phdr': f_dl_iterate_phdr,
        'mprotect': f_mprotect_libc, 'syscall': f_syscall,
        '__android_log_write': f_noop, 'openlog': f_noop, 'closelog': f_noop,
        'syslog': f_noop,
        'AAssetManager_fromJava': f_aasset_manager, 'AAssetManager_open': f_noop,
        'AAsset_read': f_noop, 'AAsset_getLength': f_noop, 'AAsset_close': f_noop,
    }
    table['_dlsym_rev'] = dlsym_rev        # r31 槽位 -> 名（hook_stub 反查）
    table['_mmap_regions'] = mmap_regions  # main 侧 CLI 输出（非符号名，绑定循环不触碰）
    table['_threads_spawned'] = threads_spawned
    table['_svc_hook'] = hook_svc            # raw-syscall bridge (SVC → UC_HOOK_INTR)
    table['_svc_events'] = svc_events
    table['_deferred'] = deferred            # r32 做不到但已记录的调用（qsort/…）
    table['_once_pending'] = once_pending    # r32 pthread_once 待决 init 例程
    table['_unbound'] = {}                   # r32 未知名调用计数（main 侧绑定循环填）
    return table


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('so')
    ap.add_argument('--fn', help='target function VA (hex)')
    ap.add_argument('--chain', default='',
                    help='fn1,fn2,... — SESSION MODE: run multiple entries sequentially in ONE '
                         'emulated process (shared memory, the real-device lifecycle: '
                         'init_array -> JNI_OnLoad -> natives -> workers). --arg/--java apply '
                         'to the FIRST entry; later entries start with zeroed x0-x7. '
                         'Use when a single --fn cannot reproduce a cross-function state.')
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
    ap.add_argument('--no-init', action='store_true',
                    help='skip running .init_array before the entries (real loaders run it at '
                         'load time; shells stash table allocators there — Battle-1 init[2] '
                         'sets the runtime-table pointer the JNI_OnLoad SM4 decrypt needs)')
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
            # Exception: LIBC_FORCE names lose even to self-defined code —
            # their real bodies need pthread-key machinery the fake thread
            # layer no-ops (see the constant).
            shndx, val = sym_def(symidx)
            if shndx and val and name not in LIBC_FORCE:
                uc.mem_write(r_offset, struct.pack('<Q', val))
                continue
            sa = STUB + 8 * i
            i += 1
            # r32: 表外名字不再塌缩成匿名 return-0 —— 每次调用计数进
            # _unbound，main 侧 JSON 输出（静默 0 曾是控制流劫持的隐身衣：
            # 爱加密 VMP 环境门的 atoi 就是这么丢的）。语义保持诚实失败 0。
            fn = libc.get(name)
            if fn is None:
                unbound = libc.get('_unbound')

                def _mk(nm):
                    def f(x0, x1, x2, x3, x4=0, x5=0):
                        unbound[nm] = unbound.get(nm, 0) + 1
                        return 0
                    return f
                fn = _mk(name)
            stub_addr[sa] = fn
            stub_addr[sa + 1] = name  # type tag for logging
            uc.mem_write(r_offset, struct.pack('<Q', sa))
    for r_offset, rtype, symidx, addend in elf.relocations():
        if rtype == R_RELATIVE:
            # RELA addends are SIGNED int64 — apply two's-complement like a
            # real linker (base=0 + addend mod 2^64). Hardened runtimes carry
            # negative addends in encrypted relocation runs (Battle-3 爱加密
            # libexec.so: 1151/4428 RELATIVE entries) — struct.pack('<Q')
            # crashed setup outright before any emulation happened.
            uc.mem_write(r_offset, struct.pack('<Q', addend & 0xFFFFFFFFFFFFFFFF))
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
                try:
                    uc.mem_map(z & ~(PAGE - 1), 0x1000)
                except Exception:
                    pass  # r18 heap auto-extension covers this address now
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
        if fn is None:
            # r31: f_dlsym's lazily-allocated namespace slots carry no
            # stub_addr entry (that dict maps slot -> callable, not names);
            # the reverse map decodes slot -> name -> semantics.
            fn = libc.get(libc.get('_dlsym_rev', {}).get(addr))
        if callable(fn):
            x = [uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            r = fn(*x)
            if r is not None:
                uc_.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_stub, begin=STUB, end=STUB + STUBSZ)
    # raw-syscall bridge: shells bypass libc with 'mov x8,#N; svc #0' stubs —
    # SVC raises UC_HOOK_INTR; serve openat/read/lseek/mmap/… from the --fs world
    svc_hook = libc.pop('_svc_hook', None)
    if svc_hook:
        uc.hook_add(UC_HOOK_INTR, svc_hook)
    svc_events = libc.pop('_svc_events', [])
    deferred_calls = libc.pop('_deferred', [])
    once_pending = libc.pop('_once_pending', [])
    unbound_imports = libc.pop('_unbound', {})

    watch_events = []

    def hook_watch(uc_, addr, size, user):
        x0 = uc_.reg_read(UC_ARM64_REG_X0)
        regs_all = {
            'x1': uc_.reg_read(UC_ARM64_REG_X1), 'x2': uc_.reg_read(UC_ARM64_REG_X2),
            'x3': uc_.reg_read(UC_ARM64_REG_X3), 'x4': uc_.reg_read(UC_ARM64_REG_X4),
            'x5': uc_.reg_read(UC_ARM64_REG_X5), 'x6': uc_.reg_read(UC_ARM64_REG_X6),
            'x7': uc_.reg_read(UC_ARM64_REG_X7),
        }
        # r27: extended-context registers — deep-chain forensics (reader bases,
        # stack frames) live in x8-x18 (callee-saved convention shells rely on)
        try:
            from unicorn.arm64_const import (UC_ARM64_REG_X8, UC_ARM64_REG_X9,
                                             UC_ARM64_REG_X10, UC_ARM64_REG_X11,
                                             UC_ARM64_REG_X12, UC_ARM64_REG_X13,
                                             UC_ARM64_REG_X14, UC_ARM64_REG_X15,
                                             UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18)
            for nm, c in (('x8', UC_ARM64_REG_X8), ('x9', UC_ARM64_REG_X9),
                          ('x10', UC_ARM64_REG_X10), ('x11', UC_ARM64_REG_X11),
                          ('x12', UC_ARM64_REG_X12), ('x13', UC_ARM64_REG_X13),
                          ('x14', UC_ARM64_REG_X14), ('x15', UC_ARM64_REG_X15),
                          ('x16', UC_ARM64_REG_X16), ('x17', UC_ARM64_REG_X17),
                          ('x18', UC_ARM64_REG_X18)):
                regs_all[nm] = uc_.reg_read(c)
        except ImportError:
            pass
        try:
            # r28: drop the stale upper bound (heap base 0x500000000000 > the old
            # 0x800000000000 cap — heap-pointed strings were silently skipped)
            buf = bytes(uc_.mem_read(x0, 32)).hex() if x0 > 0x1000 else ''
        except Exception:
            buf = ''
        watch_events.append(json.dumps({
            'watch': '0x%x' % addr, 'x0': '0x%x' % x0,
            'x1': '0x%x' % regs_all['x1'], 'x2': '0x%x' % regs_all['x2'],
            'x3': '0x%x' % regs_all['x3'], 'x4': '0x%x' % regs_all['x4'],
            'x5': '0x%x' % regs_all['x5'], 'x6': '0x%x' % regs_all['x6'],
            'x7': '0x%x' % regs_all['x7'], 'buf': buf,
            **{k: '0x%x' % v for k, v in regs_all.items() if k.startswith('x1') and len(k) <= 3},
            'lr': '0x%x' % uc_.reg_read(UC_ARM64_REG_LR),
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

    # r28 session mode: shells live a MULTI-ENTRY lifecycle in one process
    # (init_array -> JNI_OnLoad -> natives -> workers) with shared memory —
    # a single --fn cannot reproduce cross-function state. --chain runs the
    # entries sequentially in this ONE unicorn instance. Per-entry args ride
    # along as 'fn;reg=VAL;reg=VAL' tokens (later entries start zeroed unless
    # given args); the FIRST entry also receives the global --arg setup.
    entries = []  # [(fn_va, {reg: val_str}), ...]
    if args.fn:
        entries.append((int(args.fn, 0), {}))
    for tok in filter(None, (t.strip() for t in args.chain.split(','))):
        parts = tok.split(';')
        entry_args = {}
        for kv in parts[1:]:
            if '=' in kv:
                k, v = kv.split('=', 1)
                entry_args[k.strip()] = v
        entries.append((int(parts[0], 0), entry_args))
    if not entries:
        print('{"error":"E_ARGS","detail":"need --fn or --chain"}')
        sys.exit(2)
    regmap = {'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2,
              'x3': UC_ARM64_REG_X3, 'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
              'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7}

    def setup_entry(idx):
        for r in regmap.values():
            uc.reg_write(r, 0)
        if idx == 0:
            for spec in args.arg:
                reg, val = spec.split('=')
                uc.reg_write(regmap[reg.lower()], int(val, 0))
        for reg, val in entries[idx][1].items():
            uc.reg_write(regmap[reg.lower()], int(val, 0))
        uc.reg_write(UC_ARM64_REG_SP, STACK + STACKSZ // 2)
        uc.reg_write(UC_ARM64_REG_LR, SENTINEL)

    # r29: run .init_array like a real loader — shells stash table allocators
    # there (Battle-1: init[2] tail-calls the runtime-table setter; without it
    # the JNI_OnLoad SM4 decrypt degrades silently to a NULL destination).
    # The RELATIVE relocations above already materialized the fn pointers.
    def raise_if_cpu_exc(since):
        """hook_svc stopped emulation on a non-SVC CPU exception: emu_stop
        makes emu_start return NORMALLY, so without this check an encrypted/
        bogus entry would masquerade as a clean run returning x0=0."""
        for e in svc_events[since:]:
            if 'exception' in e:
                raise RuntimeError(
                    'sync CPU exception intno=%s at pc=%s (not an SVC — '
                    'undefined insn or still-encrypted code)' % (e['exception'], e['pc']))

    init_ran = []
    if not args.no_init:
        try:
            dtag = elf.dynamic_tags()
            ia, iasz = dtag.get(DT_INIT_ARRAY, 0), dtag.get(DT_INIT_ARRAYSZ, 0)
            dt_init = dtag.get(DT_INIT, 0)
        except Exception:
            ia, iasz, dt_init = 0, 0, 0
        # Battle-3 爱加密: hardened shells put the bootstrap decryptor in
        # DT_INIT — every real loader runs it BEFORE .init_array. Running
        # .init_array first executes still-encrypted code (the old intno=1
        # wall on all 55 entries). Faithful order: DT_INIT -> INIT_ARRAY.
        if dt_init:
            try:
                uc.reg_write(UC_ARM64_REG_SP, STACK + STACKSZ // 2)
                uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
                n0 = len(svc_events)
                uc.emu_start(dt_init, SENTINEL, timeout=args.timeout * 1000 * 1000)
                raise_if_cpu_exc(n0)
                init_ran.append('0x%x(dt_init)' % dt_init)
            except Exception:
                init_ran.append('0x%x(dt_init)!' % dt_init)
        for k in range(iasz // 8 if ia else 0):
            try:
                fn = struct.unpack('<Q', bytes(uc.mem_read(ia + k * 8, 8)))[0]
                if not fn:
                    continue
                uc.reg_write(UC_ARM64_REG_SP, STACK + STACKSZ // 2)
                uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
                n0 = len(svc_events)
                uc.emu_start(fn, SENTINEL, timeout=args.timeout * 1000 * 1000)
                raise_if_cpu_exc(n0)
                init_ran.append('0x%x' % fn)
            except Exception:
                # per-init best-effort: one crashing init must not starve the rest
                init_ran.append('0x%x!' % fn if fn else '0!')

    def dump_fixed_regions():
        # --dump-mem：跑完（无论成败）dump 固定区——物化诊断（数据段运行时解密/派生 key 落点）
        # r29: per-spec best-effort — one bad address must not kill the run's output
        for spec in args.dump_mem:
            try:
                va_s, ln_s, path = spec.split(':')
                blob = bytes(uc.mem_read(int(va_s, 0), int(ln_s, 0)))
                open(path, 'wb').write(blob)
            except Exception:
                pass

    returns = []
    try:
        for idx, (fn_va, _entry_args) in enumerate(entries):
            setup_entry(idx)
            n0 = len(svc_events)
            uc.emu_start(fn_va, SENTINEL, timeout=args.timeout * 1000 * 1000)
            raise_if_cpu_exc(n0)
            returns.append('0x%x' % uc.reg_read(UC_ARM64_REG_X0))
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
              f'"entry":"0x{entries[idx][0]:x}",'
              f'"init_array_ran":{json.dumps(init_ran)},'
              f'"regs":{json.dumps(regs)},'
              f'"svc_events":{json.dumps(svc_events)},'
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
    if init_ran:
        out['init_array_ran'] = init_ran
    if len(returns) > 1:
        out['chain_returns'] = returns
    mmaps = libc.pop('_mmap_regions', [])
    if mmaps:
        out['mmap_regions'] = [{'addr': '0x%x' % m['addr'], 'len': m['len'], 'source': m['source']} for m in mmaps]
    threads = libc.pop('_threads_spawned', [])
    if threads:
        out['threads_spawned'] = [{'start': '0x%x' % t['start'], 'arg': '0x%x' % t['arg']} for t in threads]
    if svc_events:
        out['svc_events'] = svc_events
    if unbound_imports:
        # r32: 表外 libc 名的调用计数 —— 每次出现都意味着控制流吃过一个
        # 静默 0；出现在这里 = 语义缺口清单，不是噪音。
        out['unbound_imports'] = unbound_imports
    if deferred_calls:
        out['deferred_calls'] = deferred_calls
    if once_pending:
        out['once_pending'] = ['0x%x' % f for f in once_pending]
    if args.java:
        out['registered_natives'] = {f'{k[0]}{k[1]}': f'0x{v:x}' for k, v in regs.items()}
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
