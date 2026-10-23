#!/usr/bin/env python3
"""upxunpack.py — pure-Python UPX-packed ELF unpacker (Track B).

Shell vendors love shipping their loader .so UPX-compressed (sometimes with
patched magic, but the PackHeader / NRV stream stays stock — observed in the
family-3 battle on the shell's own libexec.so). upx -d is not always
available and refuses patched headers; this tool reimplements the decode
deterministically, semantics-for-semantics from the UCL reference
(n2b_d.c / n2d_d.c / n2e_d.c + getbit.h):

  upxunpack.py packed.so [-o out.so] [--ph-off 0xOFFSET]

  - finds the PackHeader via the UPX! magic (l_info.l_magic), reads p_info
    and the b_info chain {sz_unc, sz_cpr, method, ftid}
  - NRV2B / NRV2D / NRV2E, each in LE32 / 8-bit / LE16 bit-buffer variants
    (UPX methods 2..10); LZMA (14) is reported honestly, not implemented
  - reverses the arm64 call filter 0x52 (B/BL rel26: low26 = (w - i) &
    0x3ffffff, keyed on bits[30:26] == 0b00101 — exactly the predicate the
    stock arm64 stub applies); other filters are warned about, not guessed
  - output = concatenated decompressed blocks (the original file prefix);
    when the blocks total less than p_info.p_filesize the tail was not
    carried by the compressed stream (runtime-rebuilt regions — e.g. the
    packer's own RW/GOT) and is zero-padded, and the report says so.

Self-check anchor: selftest.py test_upxunpack (synthetic NRV2E stream with
literal + repeat-match + end marker, PackHeader parse, filter round-trip).
Zero-sample: no family- or sample-specific constants.
"""
import argparse
import json
import struct
import sys

M = {2: ('nrv2b', 32), 3: ('nrv2b', 8), 4: ('nrv2b', 16),
     5: ('nrv2d', 32), 6: ('nrv2d', 8), 7: ('nrv2d', 16),
     8: ('nrv2e', 32), 9: ('nrv2e', 8), 10: ('nrv2e', 16)}
M_LZMA = 14


class _Bits:
    """Bit-buffer variants from UCL getbit.h, sharing the byte cursor."""

    def __init__(self, src, width):
        self.src = src
        self.ilen = 0
        self.bb = 0
        self.bc = 0
        self.width = width

    def get(self):
        if self.width == 32:
            # bc > 0 ? (bb>>--bc)&1 : (bc=31, bb=le32, ilen+=4, (bb>>31)&1)
            if self.bc > 0:
                self.bc -= 1
                return (self.bb >> self.bc) & 1
            self.bc = 31
            self.bb = struct.unpack_from('<I', self.src, self.ilen)[0]
            self.ilen += 4
            return (self.bb >> 31) & 1
        if self.width == 16:
            # bb*=2, bb&0xffff ? (bb>>16)&1 : reload le16*2+1
            self.bb = (self.bb * 2) & 0xffffffff
            if self.bb & 0xffff:
                return (self.bb >> 16) & 1
            self.ilen += 2
            self.bb = (self.src[self.ilen - 2] |
                       (self.src[self.ilen - 1] << 8)) * 2 + 1
            return (self.bb >> 16) & 1
        # width 8: bb*=2, bb&0xff ? (bb>>8)&1 : reload byte*2+1
        self.bb = (self.bb * 2) & 0xffffffff
        if self.bb & 0xff:
            return (self.bb >> 8) & 1
        self.bb = self.src[self.ilen] * 2 + 1
        self.ilen += 1
        return (self.bb >> 8) & 1


def nrv_decompress(src, algo, width):
    """UCL n2b/n2d/n2e decompressors (non-overlap path). Returns
    (output, consumed_input_bytes). Raises on corrupt streams."""
    out = bytearray()
    bits = _Bits(src, width)
    last_m_off = 1
    while True:
        while bits.get():
            out.append(src[bits.ilen])
            bits.ilen += 1
        m_off = 1
        if algo == 'nrv2b':
            while True:
                m_off = m_off * 2 + bits.get()
                if bits.get():
                    break
        else:  # 2d / 2e share the m_off loop
            while True:
                m_off = m_off * 2 + bits.get()
                if bits.get():
                    break
                m_off = (m_off - 1) * 2 + bits.get()
        if m_off > 0xffffff + 3:
            raise ValueError('m_off lookbehind overrun')
        if m_off == 2:
            m_off = last_m_off
            m_len = None
            if algo != 'nrv2b':
                m_len = bits.get()
        else:
            m_off = (m_off - 3) * 256 + src[bits.ilen]
            bits.ilen += 1
            if m_off == 0xffffffff:
                break
            if algo == 'nrv2b':
                last_m_off = m_off + 1
                m_off += 1
                m_len = None
            else:
                m_len = (m_off ^ 0xffffffff) & 1
                m_off >>= 1
                m_off += 1
                last_m_off = m_off
        if algo == 'nrv2b':
            m_len = bits.get()
            m_len = m_len * 2 + bits.get()
            if m_len == 0:
                m_len += 1
                while True:
                    m_len = m_len * 2 + bits.get()
                    if bits.get():
                        break
                m_len += 2
            m_len += (m_off > 0xd00)
        elif algo == 'nrv2d':
            m_len = m_len * 2 + bits.get()
            if m_len == 0:
                m_len += 1
                while True:
                    m_len = m_len * 2 + bits.get()
                    if bits.get():
                        break
                m_len += 2
            m_len += (m_off > 0x500)
        else:  # nrv2e
            if m_len:
                m_len = 1 + bits.get()
            elif bits.get():
                m_len = 3 + bits.get()
            else:
                m_len += 1
                while True:
                    m_len = m_len * 2 + bits.get()
                    if bits.get():
                        break
                m_len += 3
            m_len += (m_off > 0x500)
        if m_off > len(out):
            raise ValueError('match before start (m_off=%d olen=%d)'
                             % (m_off, len(out)))
        for _ in range(m_len + 1):
            out.append(out[-m_off])
    return bytes(out), bits.ilen


def unfilter_arm64_calls(buf):
    """Reverse UPX arm64 filter 0x52: for each 4-byte word i with
    bits[30:26] == 0b00101 (B/BL), low26 := (word - i) & 0x3ffffff —
    the exact inverse the stock stub applies after decompression."""
    buf = bytearray(buf)
    n = len(buf) // 4
    fixed = 0
    for i in range(n):
        w = struct.unpack_from('<I', buf, i * 4)[0]
        if (w >> 26) & 0x1f == 5:
            struct.pack_into('<I', buf, i * 4,
                             (w & 0xfc000000) | ((w - i) & 0x3ffffff))
            fixed += 1
    return bytes(buf), fixed


def find_pack_header(d, ph_off=None):
    if ph_off is not None:
        ph = ph_off
        if d[ph + 4:ph + 8] != b'UPX!':
            raise ValueError('no UPX! magic at --ph-off +4')
        return ph
    pos = 0
    while True:
        i = d.find(b'UPX!', pos)
        if i < 0:
            raise ValueError('UPX! magic not found (patched header? '
                             'supply --ph-off)')
        if i >= 4 and i + 24 <= len(d):
            return i - 4
        pos = i + 1


def unpack(data, ph_off=None):
    """-> (unpacked_bytes, report dict). Output is the concatenation of all
    decompressed blocks, i.e. the original file prefix of p_filesize bytes;
    any uncovered tail is zero-padded and flagged in the report."""
    ph = find_pack_header(data, ph_off)
    l_checksum, l_magic = struct.unpack_from('<I4s', data, ph)
    # 4 bytes of version/format/method/level sit between l_info and p_info
    p_progid, p_filesize, p_blocksize = struct.unpack_from('<III', data, ph + 12)
    # b_info chain follows p_info
    p = ph + 24
    blocks = []
    while True:
        sz_unc, sz_cpr = struct.unpack_from('<II', data, p)
        if sz_unc == 0:
            break
        method, ftid = data[p + 8], data[p + 9]
        blocks.append({'off': p, 'sz_unc': sz_unc, 'sz_cpr': sz_cpr,
                       'method': method, 'ftid': ftid})
        p += 12 + sz_cpr
    out = bytearray()
    for b in blocks:
        algo = M.get(b['method'])
        if algo is None:
            raise ValueError('unsupported method %d (LZMA=14 not '
                             'implemented)' % b['method'])
        src = data[b['off'] + 12: b['off'] + 12 + b['sz_cpr']]
        dec, used = nrv_decompress(src, *algo)
        if len(dec) != b['sz_unc'] or used != b['sz_cpr']:
            raise ValueError('block @%#x size mismatch: unc %#x/%#x, used '
                             '%#x/%#x' % (b['off'], len(dec), b['sz_unc'],
                                          used, b['sz_cpr']))
        if b['ftid'] == 0x52:
            dec, fixed = unfilter_arm64_calls(dec)
            b['unfiltered'] = fixed
        elif b['ftid'] != 0:
            b['unfiltered'] = 'SKIPPED: filter %#x not implemented' % b['ftid']
        out += dec
    tail = max(0, p_filesize - len(out))
    report = {'tool': 'upxunpack', 'pack_header': ph,
              'p_filesize': p_filesize, 'blocks': blocks,
              'decompressed': len(out), 'tail_zero_padded': tail}
    out += b'\0' * tail
    return bytes(out), report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('packed', help='UPX-packed ELF (or raw UPX stream file)')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--ph-off', default=None,
                    help='PackHeader offset (decimal or 0x..) when the '
                         'UPX! magic was patched')
    ap.add_argument('--json', action='store_true', help='machine-readable report')
    args = ap.parse_args()
    data = open(args.packed, 'rb').read()
    ph_off = int(args.ph_off, 0) if args.ph_off else None
    out, rep = unpack(data, ph_off)
    path = args.out or args.packed + '.unpacked'
    with open(path, 'wb') as f:
        f.write(out)
    if args.json:
        print(json.dumps(rep))
    else:
        print('[upxunpack] %d blocks, %#x -> %#x bytes (%s) -> %s'
              % (len(rep['blocks']), len(data), len(out),
                 'tail padded %#x' % rep['tail_zero_padded']
                 if rep['tail_zero_padded'] else 'complete', path))
        for b in rep['blocks']:
            print('  block @%#x unc=%#x cpr=%#x method=%s ftid=%#x %s'
                  % (b['off'], b['sz_unc'], b['sz_cpr'],
                     M.get(b['method'], ('?',))[0], b['ftid'],
                     ('unfiltered %d' % b['unfiltered'])
                     if isinstance(b.get('unfiltered'), int)
                     else (b.get('unfiltered') or '')))


if __name__ == '__main__':
    main()
