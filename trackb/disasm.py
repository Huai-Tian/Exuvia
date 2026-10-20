#!/usr/bin/env python3
"""Exuvia Track B: disassembly-stream generator (user-side tool, capstone required).

L2 evidence capability (README_AGENT §3.2 first step — disassembly streams into
evidence). Multi-architecture: ELF64 (aarch64/x86_64) and ELF32 (arm/x86) —
Battle-1 found half the shell's libraries are ELF32 (armeabi-v7a/x86), so
read-side coverage must be architecture-complete before Battle 2.

Usage:
  disasm.py shell.so --fn 0x2c5b88 --len 196            # one function by VA
  disasm.py shell.so --symbol JNI_OnLoad                 # resolve via PT_DYNAMIC (runtime view)
  disasm.py shell.so --all-defined                       # every defined dynsym body
  disasm.py shell.so --range 0x7984:0x100                # raw range

Thumb note (arm): a symbol with st_value bit0 set is Thumb — disassembled in
CS_MODE_THUMB with the bit cleared.

Output: text stream `0xVA  mnemonic  operands` on stdout (redirect to file for
evidence attachment, e.g. evidence/<debt_id>/JNI_OnLoad.asm).

Exit codes: 0 ok; 2 capstone missing (unavailable semantics); 3 ELF error.
"""

import argparse
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN
    from capstone import CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_32
except ImportError:
    print('{"error":"unavailable","detail":"capstone not installed (user-side dependency, README_AGENT §3.1)"}')
    sys.exit(2)

EM_386, EM_ARM, EM_X86_64, EM_AARCH64 = 3, 40, 62, 183


class Elf:
    """ELF32/ELF64 reader: PT_LOAD mapping + runtime-view (PT_DYNAMIC) dynsym."""

    def __init__(self, data):
        self.d = data
        if not data.startswith(b'\x7fELF'):
            raise ValueError('not an ELF')
        self.cls = data[4]          # 1 = ELF32, 2 = ELF64
        self.machine = struct.unpack_from('<H', data, 0x12)[0]
        if self.cls == 2:
            phoff, = struct.unpack_from('<Q', data, 0x20)
            phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
        else:
            phoff, = struct.unpack_from('<I', data, 0x1c)
            phentsize, phnum = struct.unpack_from('<HH', data, 0x2a)
        self.loads, self.pt_dynamic = [], None
        for i in range(phnum):
            b = phoff + i * phentsize
            if self.cls == 2:
                p_type, = struct.unpack_from('<I', data, b)
                if p_type == 1:
                    self.loads.append((struct.unpack_from('<Q', data, b + 8)[0],
                                        struct.unpack_from('<Q', data, b + 16)[0],
                                        struct.unpack_from('<Q', data, b + 32)[0]))
                elif p_type == 2:
                    self.pt_dynamic = (struct.unpack_from('<Q', data, b + 8)[0],
                                       struct.unpack_from('<Q', data, b + 32)[0])
            else:
                p_type, = struct.unpack_from('<I', data, b)
                if p_type == 1:
                    self.loads.append((struct.unpack_from('<I', data, b + 4)[0],
                                       struct.unpack_from('<I', data, b + 8)[0],
                                       struct.unpack_from('<I', data, b + 16)[0]))
                elif p_type == 2:
                    self.pt_dynamic = (struct.unpack_from('<I', data, b + 4)[0],
                                       struct.unpack_from('<I', data, b + 20)[0])

    def va2off(self, va):
        for off, vaddr, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def tags(self):
        out = {}
        if not self.pt_dynamic:
            return out
        off, sz = self.pt_dynamic
        ent = 16 if self.cls == 2 else 8
        for i in range(sz // ent):
            if self.cls == 2:
                t, v = struct.unpack_from('<QQ', self.d, off + i * ent)
            else:
                t, v = struct.unpack_from('<II', self.d, off + i * ent)
            if t == 0:
                break
            out.setdefault(t, v)
        return out

    def symbols(self):
        """Defined dynsym entries (name, st_value, st_size) — runtime view."""
        tags = self.tags()
        if 6 not in tags or 5 not in tags:
            return []
        symtab, strtab = self.va2off(tags[6]), self.va2off(tags[5])
        n = None
        if 4 in tags:  # DT_HASH nchain
            n = struct.unpack_from('<I', self.d, self.va2off(tags[4]) + 4)[0]
        if not n:
            return []
        syment = 24 if self.cls == 2 else 16
        out = []
        for i in range(n):
            b = symtab + i * syment
            if self.cls == 2:
                if struct.unpack_from('<H', self.d, b + 6)[0] == 0:
                    continue
                val, size = struct.unpack_from('<QQ', self.d, b + 8)
                name_off = struct.unpack_from('<I', self.d, b)[0]
            else:
                if struct.unpack_from('<H', self.d, b + 14)[0] == 0:
                    continue
                name_off, val, size = struct.unpack_from('<III', self.d, b)
            start = strtab + name_off
            end = self.d.index(b'\0', start)
            out.append((self.d[start:end].decode(errors='replace'), val, size))
        return out


def make_disassembler(elf):
    if elf.machine == EM_AARCH64:
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    if elf.machine == EM_X86_64:
        import capstone
        return capstone.Cs(CS_ARCH_X86, capstone.CS_MODE_64)
    if elf.machine == EM_ARM:
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)  # Thumb handled per-symbol
    if elf.machine == EM_386:
        return Cs(CS_ARCH_X86, CS_MODE_32)
    raise ValueError(f'unsupported machine {elf.machine}')


def disasm_range(data, elf, va, length, md, thumb=False):
    off = elf.va2off(va)
    if off is None:
        print(f'{{"error":"E_READ","detail":"VA 0x{va:x} not mapped"}}', file=sys.stderr)
        return 1
    engine = md
    if thumb:
        from capstone import Cs as _Cs, CS_ARCH_ARM as _A, CS_MODE_THUMB as _T
        engine = _Cs(_A, _T)
        va &= ~1
        off = elf.va2off(va)
    for insn in engine.disasm(data[off:off + length], va):
        print(f'0x{insn.address:08x}  {insn.mnemonic:10s} {insn.op_str}')
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('so')
    ap.add_argument('--fn', help='function VA (hex)')
    ap.add_argument('--len', type=lambda x: int(x, 0), default=0x100, help='byte length (with --fn/--symbol)')
    ap.add_argument('--symbol', help='defined dynsym name (runtime view resolution)')
    ap.add_argument('--all-defined', action='store_true', help='disassemble every defined dynsym body (st_size bounded)')
    ap.add_argument('--range', dest='span', help='start:length hex (e.g. 0x7984:0x100)')
    args = ap.parse_args()

    data = open(args.so, 'rb').read()
    try:
        elf = Elf(data)
        md = make_disassembler(elf)
    except ValueError as e:
        print(f'{{"error":"E_PARSE","detail":"{e}"}}')
        sys.exit(3)

    rc = 0
    if args.span:
        va, ln = args.span.split(':')
        rc = disasm_range(data, elf, int(va, 0), int(ln, 0), md)
    elif args.symbol:
        for name, va, size in elf.symbols():
            if name == args.symbol:
                ln = size if size else args.len
                thumb = (elf.machine == EM_ARM) and (va & 1)
                print(f'# {name} @ 0x{va:x} ({ln} bytes{", thumb" if thumb else ""})')
                rc = disasm_range(data, elf, va, ln, md, thumb=thumb)
                break
        else:
            print('{"error":"E_NOT_FOUND","detail":"symbol not in defined dynsym (runtime view)"}')
            rc = 1
    elif args.all_defined:
        for name, va, size in elf.symbols():
            if size:
                thumb = (elf.machine == EM_ARM) and (va & 1)
                print(f'# {name} @ 0x{va:x} ({size} bytes{", thumb" if thumb else ""})')
                disasm_range(data, elf, va, size, md, thumb=thumb)
                print()
    elif args.fn:
        rc = disasm_range(data, elf, int(args.fn, 0), args.len, md)
    else:
        ap.print_help()
    sys.exit(rc)


if __name__ == '__main__':
    main()
