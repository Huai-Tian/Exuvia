#!/usr/bin/env python3
"""Exuvia Track B: embedded-ELF recovery (user-side, sample-agnostic).

Packers embed second-stage native payloads inside encrypted containers. After
the analyst (or LLM) peels a crypto layer (crypto_recon) and inflates, the
product is often a raw blob that IS an ELF .so — frequently with the magic
stripped and section headers zeroed. This tool recovers the structure
mechanically so the LLM can reason about symbols and code:

  scan <file> [--step N]
        Find embedded ELF64 headers — both magic-present (7f 45 4c 46) and
        magic-stripped (field-semantic validation: class/data/version bytes,
        e_type/e_machine sanity, phoff/phnum bounds). Reports offset + field
        summary for each candidate.
  layout <file> [--window 4096] [--machine arm64] [--samples 8]
        Entropy segmentation with code-validity sampling: native code sits at
        H≈5.0-6.5, encrypted/compressed data at H≈7.5+. For each cold region
        capstone disassembles --samples windows and reports the valid-instruction
        ratio — distinguishing real code (high ratio) from tables/metadata.
  symbols <file> --phdr-at N [--phdr-count 6] [--strtab-at N]
        Recover the dynamic symbol table by either route:
          (a) phdr route: parse Elf64_Phdr at --phdr-at, find PT_DYNAMIC,
              walk Elf64_Dyn for DT_SYMTAB/DT_STRTAB, map vaddr->file-offset
              via PT_LOAD segments;
          (b) strtab route (--strtab-at): locate the string table directly,
              then backtrack contiguous valid Elf64_Sym entries by st_name
              cross-reference validation (works when phdrs/DYNAMIC are absent
              or still encrypted — battle-tested on stripped shells).

Every offset is a CLI argument — no sample knowledge is embedded
(zero-sample policy). Exit 0 ok; 2 dependency missing (capstone for layout).
"""

import argparse
import math
import struct
import sys

MACHINES = {0x03: 'x86', 0x28: 'arm', 0x32: 'ia64', 0x3E: 'x86_64', 0xB7: 'aarch64',
            0xF3: 'riscv', 0x5032: 'aarch64_be'}


def _entropy(block):
    if not block:
        return 0.0
    cnt = [0] * 256
    for b in block:
        cnt[b] += 1
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in cnt if c)


# ---------------------------------------------------------------- scan

def _try_std_header(data, off):
    """Validate a magic-present ELF64 header at off; return field dict or None."""
    if off + 64 > len(data) or data[off:off + 4] != b'\x7fELF':
        return None
    ei_class, ei_data = data[off + 4], data[off + 5]
    if ei_class != 2 or ei_data != 1:  # ELFCLASS64, ELFDATA2LSB only
        return None
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, off + 16)
    return _validate_common(data, e_type, e_machine, e_version, e_entry, e_phoff,
                            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)


def _try_stripped_header(data, off):
    """Validate a magic-stripped ELF64 header at off (all fields shifted -4).

    Layout: class(1) data(1) ver(1) osabi(1) pad(8) e_type(2) e_machine(2)
    e_version(4) e_entry(8) e_phoff(8) e_shoff(8) e_flags(4) e_ehsize(2)
    e_phentsize(2) e_phnum(2) e_shentsize(2) e_shnum(2) e_shstrndx(2) = 60B.
    """
    if off + 60 > len(data):
        return None
    ei_class, ei_data, ei_ver = data[off], data[off + 1], data[off + 2]
    if ei_class != 2 or ei_data != 1 or ei_ver != 1:
        return None
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, off + 12)
    return _validate_common(data, e_type, e_machine, e_version, e_entry, e_phoff,
                            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)


def _validate_common(data, e_type, e_machine, e_version, e_entry, e_phoff,
                     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx):
    """Semantic sanity: returns field dict when the values hang together."""
    if e_type not in (1, 2, 3):          # REL, EXEC, DYN
        return None
    if e_machine not in MACHINES:
        return None
    if e_version != 1:
        return None
    if e_phentsize not in (32, 56):      # ELF32/ELF64 phdr — we only map 56
        return None
    if not (0 < e_phnum <= 128):
        return None
    if e_phoff + e_phnum * e_phentsize > len(data) * 16:  # phdr may be in another layer
        if e_phoff >= len(data):
            return None
    if e_shnum > 4096 or (e_shstrndx not in (0, 0xffff) and e_shstrndx >= max(e_shnum, 1)):
        return None
    if e_entry > len(data) * 64:         # entry beyond any plausible mapping
        return None
    return {'e_type': e_type, 'e_machine': e_machine, 'machine': MACHINES[e_machine],
            'e_entry': e_entry, 'e_phoff': e_phoff, 'e_phentsize': e_phentsize,
            'e_phnum': e_phnum, 'e_shnum': e_shnum, 'e_shstrndx': e_shstrndx}


def cmd_scan(path, step):
    data = open(path, 'rb').read()
    hits = []
    # magic-present candidates: direct byte search
    i = data.find(b'\x7fELF')
    while i >= 0:
        f = _try_std_header(data, i)
        if f:
            hits.append((i, 'magic', f))
        i = data.find(b'\x7fELF', i + 1)
    # magic-stripped candidates: grid walk (stride 1 is too slow on MB blobs;
    # headers are at least 4-byte aligned in every packing scheme observed)
    for off in range(0, len(data) - 59, step):
        f = _try_stripped_header(data, off)
        if f:
            # deduplicate: a stripped header at off == std header at off+4 with magic
            if (off + 4, 'magic') not in [(h[0], h[1]) for h in hits]:
                hits.append((off, 'stripped', f))
    if not hits:
        print('no embedded ELF64 header candidates found')
        return 0
    for off, kind, f in hits:
        print('0x%08x  %-9s  type=%d machine=%s entry=0x%x phoff=0x%x phnum=%d shnum=%d'
              % (off, kind, f['e_type'], f['machine'], f['e_entry'], f['e_phoff'],
                 f['e_phnum'], f['e_shnum']))
    return 0


# ---------------------------------------------------------------- layout

def cmd_layout(path, window, machine, samples):
    data = open(path, 'rb').read()
    if machine == 'arm64':
        arch, mode = 10, 0  # capstone CS_ARCH_ARM64 / CS_MODE_LITTLE_ENDIAN
        try:
            import capstone
        except ImportError:
            print('capstone required for --samples code validation (pip install capstone)', file=sys.stderr)
            return 2
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    else:
        print('unsupported machine for code sampling: %s' % machine, file=sys.stderr)
        return 2
    # entropy profile with transition detection
    transitions = []  # (offset, hot?) hot = H >= 7.0
    prev_hot = None
    i = 0
    regions = []
    while i < len(data):
        h = _entropy(data[i:i + window])
        hot = h >= 7.0
        if hot != prev_hot:
            if regions:
                regions[-1][2] = i
            regions.append([i, hot, len(data)])
            prev_hot = hot
        i += window
    print('entropy regions (hot = H>=7.0, window %d):' % window)
    cold_regions = []
    for start, hot, end in regions:
        print('  0x%08x-0x%08x  %s' % (start, end, 'HOT/encrypted' if hot else 'cold'))
        if not hot:
            cold_regions.append((start, end))
    # code-validity sampling inside cold regions
    print('\ncode-validity sampling (cold regions, %d windows each):' % samples)
    for start, end in cold_regions:
        span = end - start
        if span < 64:
            continue
        step = max(64, span // samples)
        valid_total = insn_total = 0
        for off in range(start, min(end - 16, start + span), step):
            chunk = data[off:off + 64]
            insns = list(md.disasm(chunk, off))
            if not insns:
                continue
            valid = sum(1 for ins in insns if ins.mnemonic not in ('udf', 'svc'))
            valid_total += valid
            insn_total += len(insns)
        ratio = (valid_total / insn_total) if insn_total else 0.0
        verdict = 'CODE' if ratio >= 0.8 else ('mixed' if ratio >= 0.4 else 'data/tables')
        print('  0x%08x-0x%08x  valid-ratio=%.2f  -> %s' % (start, end, ratio, verdict))
    return 0


# ---------------------------------------------------------------- symbols

PHDR_TYPES = {1: 'PT_LOAD', 2: 'PT_DYNAMIC', 6: 'PT_PHDR', 7: 'PT_INTERP',
              0x6474e550: 'PT_GNU_EH_FRAME', 0x6474e551: 'PT_GNU_STACK',
              0x6474e552: 'PT_GNU_RELRO'}
DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT = 6, 5, 10, 11


def _parse_phdrs(data, off, count):
    phdrs = []
    for i in range(count):
        p_off = off + i * 56
        if p_off + 56 > len(data):
            break
        p_type, p_flags = struct.unpack_from('<II', data, p_off)
        (p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from('<QQQQQQ', data, p_off + 8)
        phdrs.append({'type': p_type, 'flags': p_flags, 'offset': p_offset,
                      'vaddr': p_vaddr, 'filesz': p_filesz, 'memsz': p_memsz})
    return phdrs


def _vaddr2off(phdrs, vaddr):
    for p in phdrs:
        if p['type'] == 1 and p['vaddr'] <= vaddr < p['vaddr'] + p['filesz']:
            return p['offset'] + (vaddr - p['vaddr'])
    return None


def _route_phdr(data, phdr_at, phdr_count):
    phdrs = _parse_phdrs(data, phdr_at, phdr_count)
    print('program headers @0x%x:' % phdr_at)
    for p in phdrs:
        print('  %-16s flags=%d off=0x%x vaddr=0x%x filesz=0x%x' % (
            PHDR_TYPES.get(p['type'], hex(p['type'])), p['flags'], p['offset'],
            p['vaddr'], p['filesz']))
    dyn = next((p for p in phdrs if p['type'] == 2), None)
    if not dyn:
        print('no PT_DYNAMIC — falling back to strtab route required')
        return None, None
    tags = {}
    off = dyn['offset']
    for i in range(dyn['filesz'] // 16):
        tag, val = struct.unpack_from('<QQ', data, off + i * 16)
        if tag == 0:
            break
        tags[tag] = val
    if DT_SYMTAB not in tags or DT_STRTAB not in tags:
        print('dynamic table lacks DT_SYMTAB/DT_STRTAB')
        return None, None
    sym_off = _vaddr2off(phdrs, tags[DT_SYMTAB])
    str_off = _vaddr2off(phdrs, tags[DT_STRTAB])
    str_sz = tags.get(DT_STRSZ, 0x10000)
    if sym_off is None or str_off is None:
        print('vaddr mapping failed (segments do not cover symtab/strtab)')
        return None, None
    # nsym from the gap between symtab and strtab (ELF layout convention)
    nsym = max(1, (str_off - sym_off) // 24)
    return (sym_off, nsym, str_off, str_sz), phdrs


def _sym_valid(data, b, strtab_end):
    """One Elf64_Sym entry semantic check (name inside strtab, sane info/value)."""
    if b + 24 > len(data):
        return False
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, b)
    if st_name >= strtab_end:
        return False
    if (st_info >> 4) > 2 or (st_info & 0xF) > 3:
        return False
    if st_value > len(data) * 64:
        return False
    return True


def _route_strtab(data, strtab_at, slack=0x200):
    """Backtrack contiguous valid Elf64_Sym entries ending near strtab_at.

    The dynsym may be separated from the strtab by padding or foreign metadata
    of arbitrary length, so try every byte end-point within
    [strtab_at-slack, strtab_at] and keep the longest fully-valid run."""
    strtab_end = min(0x10000, len(data) - strtab_at)
    best = None
    for end in range(strtab_at, max(0, strtab_at - slack), -1):
        n = 0
        b = end - 24
        while b >= 0 and _sym_valid(data, b, strtab_end):
            n += 1
            b -= 24
        if n >= 2 and (best is None or n > best[1]):
            best = (end - n * 24, n)
    if not best:
        return None
    return (best[0], best[1], strtab_at, strtab_end), None


def cmd_symbols(path, phdr_at, phdr_count, strtab_at):
    data = open(path, 'rb').read()
    phdrs = None
    found = None
    if phdr_at is not None:
        found, phdrs = _route_phdr(data, phdr_at, phdr_count)
    if found is None and strtab_at is not None:
        print('using strtab backtracking route @0x%x' % strtab_at)
        found, phdrs = _route_strtab(data, strtab_at)
    if not found:
        print('no symbol table recovered — give --phdr-at or --strtab-at', file=sys.stderr)
        return 2
    sym_off, nsym, str_off, str_sz = found
    strtab = data[str_off:str_off + str_sz]
    print('\ndynamic symbols: %d @file 0x%x (strtab @0x%x, 0x%x bytes)' % (nsym, sym_off, str_off, str_sz))
    for j in range(nsym):
        b = sym_off + j * 24
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, b)
        end = strtab.find(b'\x00', st_name) if st_name < len(strtab) else -1
        nm = strtab[st_name:end].decode('utf-8', 'replace') if end and end > 0 else ('' if st_name == 0 else '?')
        bind = ('LOCAL', 'GLOBAL', 'WEAK')[min(st_info >> 4, 2)]
        typ = ('NOTYPE', 'OBJECT', 'FUNC', 'SECTION')[min(st_info & 0xF, 3)]
        shn = {0: 'UND', 0xfff1: 'ABS'}.get(st_shndx, str(st_shndx))
        if nm or st_value:
            print('  [%3d] %-6s %-8s shndx=%-4s val=0x%08x sz=%-7d %s' % (
                j, bind, typ, shn, st_value, st_size, nm))
    return 0


def main():
    ap = argparse.ArgumentParser(description='embedded-ELF structure recovery (sample-agnostic)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('scan', help='find embedded ELF64 headers (magic or stripped)')
    s.add_argument('file')
    s.add_argument('--step', type=int, default=1, help='stride for stripped-header scan (1=exhaustive, 4=faster)')
    s = sub.add_parser('layout', help='entropy regions + code-validity sampling')
    s.add_argument('file')
    s.add_argument('--window', type=int, default=4096)
    s.add_argument('--machine', default='arm64')
    s.add_argument('--samples', type=int, default=8)
    s = sub.add_parser('symbols', help='recover dynamic symbol table')
    s.add_argument('file')
    s.add_argument('--phdr-at', type=lambda x: int(x, 0), help='file offset of Elf64_Phdr table')
    s.add_argument('--phdr-count', type=int, default=8)
    s.add_argument('--strtab-at', type=lambda x: int(x, 0), help='file offset of .dynstr (backtrack route)')
    a = ap.parse_args()
    if a.cmd == 'scan':
        return cmd_scan(a.file, a.step)
    if a.cmd == 'layout':
        return cmd_layout(a.file, a.window, a.machine, a.samples)
    if a.cmd == 'symbols':
        if a.phdr_at is None and a.strtab_at is None:
            print('need --phdr-at or --strtab-at', file=sys.stderr)
            return 2
        return cmd_symbols(a.file, a.phdr_at, a.phdr_count, a.strtab_at)
    return 2


if __name__ == '__main__':
    sys.exit(main())
