#!/usr/bin/env python3
"""Exuvia Track B: disassembly-stream generator (user-side tool, capstone required).

L2 evidence capability (README_AGENT §3.2 first step — disassembly streams into
evidence; decompiler-grade pseudocode is a later, unavailable-class capability).
Battle-1 finding that earned this (evidence milestones x2): analysts chasing
expectation values and decrypt routines need the instruction stream as a
first-class workpackage artifact, not ad-hoc console dumps.

Usage:
  disasm.py shell.so --fn 0x2c5b88 --len 196            # one function by VA
  disasm.py shell.so --symbol JNI_OnLoad                 # resolve via PT_DYNAMIC (runtime view)
  disasm.py shell.so --all-defined                       # every defined dynsym body
  disasm.py shell.so --range 0x7984:0x100                # raw range

Output: text stream `0xVA  mnemonic  operands` on stdout (redirect to file for
evidence attachment, e.g. evidence/<debt_id>/JNI_OnLoad.asm).

Exit codes: 0 ok; 2 capstone/unicorn missing (unavailable semantics); 3 ELF error.
"""

import argparse
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    print('{"error":"unavailable","detail":"capstone not installed (user-side dependency, README_AGENT §3.1)"}')
    sys.exit(2)


class Elf:
    def __init__(self, data):
        self.d = data
        if not data.startswith(b'\x7fELF') or data[4] != 2:
            raise ValueError('not ELF64')
        u16 = lambda o: struct.unpack_from('<H', data, o)[0]
        u32 = lambda o: struct.unpack_from('<I', data, o)[0]
        u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
        phoff, phentsize, phnum = u64(0x20), u16(0x36), u16(0x38)
        self.loads, self.pt_dynamic = [], None
        for i in range(phnum):
            b = phoff + i * phentsize
            if u32(b) == 1:
                self.loads.append((u64(b + 8), u64(b + 16), u64(b + 32)))
            elif u32(b) == 2:
                self.pt_dynamic = (u64(b + 8), u64(b + 32))

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
        for i in range(sz // 16):
            t, v = struct.unpack_from('<QQ', self.d, off + i * 16)
            if t == 0:
                break
            out.setdefault(t, v)
        return out

    def symbols(self):
        """Defined dynsym entries via the runtime view (PT_DYNAMIC first)."""
        tags = self.tags()
        if 6 not in tags or 5 not in tags:
            return []
        symtab, strtab = self.va2off(tags[6]), self.va2off(tags[5])
        n = None
        if 4 in tags:
            n = struct.unpack_from('<I', self.d, self.va2off(tags[4]) + 4)[0]
        elif 0x6FFFFEF5 in tags:
            gh = self.va2off(tags[0x6FFFFEF5])
            nbuckets, symoffset = struct.unpack_from('<II', self.d, gh)
            bloom = struct.unpack_from('<I', self.d, gh + 8)[0]
            buckets = gh + 16 + bloom * 8
            mx = max((struct.unpack_from('<I', self.d, buckets + i * 4)[0]
                      for i in range(nbuckets)), default=0)
            if mx:
                chain = buckets + nbuckets * 4
                i = mx
                while not (struct.unpack_from('<I', self.d, chain + (i - symoffset) * 4)[0] & 1):
                    i += 1
                n = i + 1
        if not n:
            return []
        out = []
        for i in range(n):
            b = symtab + i * 24
            if struct.unpack_from('<H', self.d, b + 6)[0] == 0:
                continue
            name_off = struct.unpack_from('<I', self.d, b)[0]
            start = strtab + name_off
            end = self.d.index(b'\0', start)
            out.append((self.d[start:end].decode(errors='replace'),
                        struct.unpack_from('<Q', self.d, b + 8)[0],
                        struct.unpack_from('<Q', self.d, b + 16)[0]))
        return out


def disasm_range(data, elf, va, length, md):
    off = elf.va2off(va)
    if off is None:
        print(f'{{"error":"E_READ","detail":"VA 0x{va:x} not mapped"}}', file=sys.stderr)
        return 1
    for insn in md.disasm(data[off:off + length], va):
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
    except ValueError as e:
        print(f'{{"error":"E_PARSE","detail":"{e}"}}')
        sys.exit(3)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    rc = 0
    if args.span:
        va, ln = args.span.split(':')
        rc = disasm_range(data, elf, int(va, 0), int(ln, 0), md)
    elif args.symbol:
        for name, va, size in elf.symbols():
            if name == args.symbol:
                ln = size if size else args.len
                print(f'# {name} @ 0x{va:x} ({ln} bytes)')
                rc = disasm_range(data, elf, va, ln, md)
                break
        else:
            print(f'{"error":"E_NOT_FOUND","detail":"symbol not in defined dynsym (runtime view)"}')
            rc = 1
    elif args.all_defined:
        for name, va, size in elf.symbols():
            if size:
                print(f'# {name} @ 0x{va:x} ({size} bytes)')
                disasm_range(data, elf, va, size, md)
                print()
    elif args.fn:
        rc = disasm_range(data, elf, int(args.fn, 0), args.len, md)
    else:
        ap.print_help()
    sys.exit(rc)


if __name__ == '__main__':
    main()
