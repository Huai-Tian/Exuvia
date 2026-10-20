#!/usr/bin/env python3
"""Exuvia Track B: ciphertext reconnaissance (user-side, sample-agnostic).

Mechanical aids for the analyst (or outsourced LLM) working an encrypted-payload
debt entry: locate the container, fingerprint the cipher, and run known-plaintext
keystream scans when a candidate key exists. Every value is a CLI argument — no
sample knowledge is embedded (zero-sample policy).

Subcommands:
  entropy <file> [--block N]          block-entropy profile (container location)
  ecb <file> [--block 16]             repeated-block census (ECB fingerprint)
  aes-scan <so>                       scan code segments for ARMv8 AES instructions
  rc4-scan <file> --key <hex> [--stride N] [--seed-i N] [--seed-j N]
         [--range lo:hi] [--magic <hex>] [--skip N]
         exhaustive known-plaintext scan: bytes decrypting to a length header in
         range AND the given magic right after (dual filter — near-zero noise)
  dxor <str> [--key 0x10] [--hex] [--strings <file>]
         Dalvik string-obfuscation decoder: per-character XOR applied to a
         string literal (recovered verbatim from dex bytecode via any dex
         reader). Battle-1 finding: shell Java layers are plaintext and carry
         the call-site structure — this decoder is the key that opened them.
  hash-scan <so> [--find-callers]
         instruction-level hash-constant scan: shells load MD5/SHA1/SHA256
         IVs via movz/movk immediates (never contiguous bytes), so byte scans
         miss them. Decodes every aligned word, reports movz/movk carrying
         known IV fragments. Battle-1: located the shell's private MD5 engine
         this way (four IVs in four adjacent movz, file 0xf5ee8).

Exit codes: 0 ok; 2 dependency missing (capstone needed for aes-scan only).
"""

import argparse
import math
import struct
import sys


def cmd_entropy(path, block):
    data = open(path, 'rb').read()
    B = block * 1024
    i = 0
    while i < len(data):
        blk = data[i:i + B]
        cnt = [0] * 256
        for b in blk:
            cnt[b] += 1
        n = len(blk)
        h = -sum((c / n) * math.log2(c / n) for c in cnt if c)
        print(f'0x{i:08x}-{min(i + B, len(data)):08x}  H={h:.3f} ' + '#' * int(h * 4))
        i += B


def cmd_ecb(path, block):
    data = open(path, 'rb').read()
    blocks = [bytes(data[i:i + block]) for i in range(0, len(data) - block, block)]
    uniq = len(set(blocks))
    dup = len(blocks) - uniq
    print(f'{len(blocks)} blocks of {block}B, unique {uniq}, repeated {dup} -> '
          + ('ECB fingerprint (repeats present)' if dup else 'stream/CTR/CBC profile (all unique)'))


def cmd_aes_scan(path):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print('{"error":"unavailable","detail":"capstone not installed (user-side dependency)"}')
        sys.exit(2)
    data = open(path, 'rb').read()
    u16 = lambda o: struct.unpack_from('<H', data, o)[0]
    u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
    u32 = lambda o: struct.unpack_from('<I', data, o)[0]
    phoff, phentsize, phnum = u64(0x20), u16(0x36), u16(0x38)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    hits = []
    for i in range(phnum):
        b = phoff + i * phentsize
        if u32(b) == 1 and (u32(b + off_flags(b)) if False else True):
            off, vaddr, filesz = u64(b + 8), u64(b + 16), u64(b + 32)
            try:
                for insn in md.disasm(data[off:off + filesz], vaddr):
                    if insn.mnemonic in ('aese', 'aesd', 'aesmc', 'aesimc'):
                        hits.append(f'0x{insn.address:x} {insn.mnemonic}')
            except Exception:
                pass
    print(f'AES instructions: {len(hits)} ' + (str(hits[:8]) if hits else '(none — no hardware AES)'))


def off_flags(b):
    return b


def rc4_keystream(key, n, stride, seed_i, seed_j, j_add=0):
    S = list(range(256))
    j = 0
    ki = 0
    for i in range(256):
        j = (j + key[ki] + S[i]) & 0xFF
        ki = (ki + 1) % len(key)
        S[i], S[j] = S[j], S[i]
    i, j = seed_i, seed_j
    ks = bytearray()
    for _ in range(n):
        i = (i + stride) & 0xFF
        j = (S[i] + j + j_add) & 0xFF
        S[i], S[j] = S[j], S[i]
        ks.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(ks)


def cmd_rc4_scan(path, keyhex, stride, seed_i, seed_j, lo_hi, magic, skip, j_add=0):
    data = open(path, 'rb').read()[skip:]
    key = bytes.fromhex(keyhex)
    lo, hi = lo_hi
    ks = rc4_keystream(key, 8, stride, seed_i, seed_j, j_add)
    magic_b = bytes.fromhex(magic)
    found = []
    for off in range(len(data) - 8):
        d4 = struct.unpack('<I', bytes(a ^ b for a, b in zip(data[off:off + 4], ks[:4])))[0]
        if lo <= d4 <= hi:
            m2 = bytes(a ^ b for a, b in zip(data[off + 4:off + 4 + len(magic_b)], ks[4:4 + len(magic_b)]))
            if m2 == magic_b:
                found.append((off + skip, d4))
    print(f'dual-filter hits: {len(found)}')
    for off, d4 in found[:10]:
        print(f'  file-offset 0x{off:x} declared-length {d4}')


def mat_parity_key(buf, m, keylen_max):
    """14B-header material lattice -> (eff_keylen, key) or None.

    Battle-1 cryptor-family key-material semantics (r16/r17 distilled):
      keylen = s16 @mat+6, flags = u16 @mat+8, payload = mat+0xe
      eff_keylen = flags==0 ? keylen : keylen-1
      shift = s16 @payload+0xe; off = (shift > 8) ? 0 : u32 @payload+0x20 (0x18 when 0)
      keysrc = payload + off*16 + 0x28
      key[i] = sum_k even-bit-parity(keysrc[i*8+k]) << (7-k)
    (parity(b) = b ^ b>>2 ^ b>>4 ^ b>>6 & 1 — one bit per payload byte)
    """
    if m + 0x30 > len(buf):
        return None
    keylen = struct.unpack_from('<h', buf, m + 6)[0]
    if keylen <= 0 or keylen > keylen_max:
        return None
    flags = struct.unpack_from('<H', buf, m + 8)[0]
    eff = keylen if flags == 0 else keylen - 1
    if eff <= 0 or eff > keylen_max:
        return None
    if m + 0x20 > len(buf):
        return None
    shift = struct.unpack_from('<h', buf, m + 0x1c)[0]
    if shift > 8:
        off = 0
    else:
        if m + 0x32 > len(buf):
            return None
        off = struct.unpack_from('<I', buf, m + 0x2e)[0]
        if off == 0:
            off = 0x18
    keysrc = m + 0xe + off * 16 + 0x28
    if keysrc + eff * 8 > len(buf):
        return None
    key = bytearray(eff)
    for i in range(eff):
        b = 0
        for k in range(8):
            c = buf[keysrc + i * 8 + k]
            b |= ((c ^ (c >> 2) ^ (c >> 4) ^ (c >> 6)) & 1) << (7 - k)
        key[i] = b
    return eff, bytes(key)


def cmd_rc4mat(matsrc, carrier_path, ct_off, stride, seed_i, seed_j, j_add,
               lo_hi, magic, keylen_max, limit):
    """Material-space scan: every offset of <matsrc> is tried as a 14B-header
    key material; each derives a parity-key and runs the variant RC4 against
    the carrier's [4B declared length][magic] head. A hit hands you the
    material offset + derived key — the ciphertext coordinates were already
    known; this hunts the KEY-MATERIAL space (hunt philosophy extension)."""
    mat = open(matsrc, 'rb').read()
    ct = open(carrier_path, 'rb').read()
    head = ct[ct_off:ct_off + 6]
    if len(head) < 6:
        print('{"error":"E_ARGS","detail":"carrier too short at ct-off"}')
        return
    lo, hi = lo_hi
    auto = magic == 'auto'
    magic_b = None if auto else bytes.fromhex(magic)
    hits = 0
    for m in range(0, max(len(mat) - 0x36, 0)):
        dk = mat_parity_key(mat, m, keylen_max)
        if dk is None:
            continue
        eff, key = dk
        ks = rc4_keystream(key, 6, stride, seed_i, seed_j, j_add)
        d4 = struct.unpack('<I', bytes(a ^ b for a, b in zip(head[:4], ks[:4])))[0]
        if not (lo <= d4 <= hi):
            continue
        m2 = bytes(a ^ b for a, b in zip(head[4:6], ks[4:6]))
        ok = auto and (m2[0] & 0x0f) == 8 and ((m2[0] << 8) | m2[1]) % 31 == 0 and not (m2[1] & 0x20)
        if not ok and not auto:
            ok = m2 == magic_b
        if ok:
            hits += 1
            if hits <= limit:
                print('mat 0x%x keylen %d key %s -> declared-len 0x%x magic %s'
                      % (m, eff, key.hex(), d4, m2.hex()))
    print('{"rc4mat_done":"0x%x","carrier":"%s@0x%x","hits":%d}'
          % (len(mat), carrier_path, ct_off, hits))



HASH_IVS = {
    0x2301: 'MD5/SHA1 IV[0] low (0x67452301)', 0xab89: 'IV[1] low (0xefcdab89)',
    0xdcfe: 'IV[2] low (0x98badcfe)', 0x5476: 'IV[3] low (0x10325476)',
    0x6745: 'IV[0] high', 0xefcd: 'IV[1] high', 0x98ba: 'IV[2] high', 0x1032: 'IV[3] high',
    0x9e66: 'SHA256 IV[0] low (0x6a09e667)', 0x7ae8: 'SHA256 IV[1] low (0xbb67ae85)',
    0x2f98: 'SHA256 K[0] low (0x428a2f98)', 0x2799: 'SHA1 K1 (0x5a827999)',
    0xc3d2: 'SHA1 E low (0xc3d2e1f0)', 0xe1f0: 'SHA1 E high',
}


def cmd_hash_scan(path):
    """Instruction-level movz/movk hash-IV scan — A64 ONLY.

    Battle-1 blind spot, documented honestly: MOVZ/MOVK are AArch64 instructions;
    32-bit libraries load their constants via ldr-literal pools (PIC-relative,
    runtime-GOT-composed — raw IV bytes were absent too). 32-bit IV detection
    needs ldr-literal target tracking (unimplemented recon gap, x1)."""
    import struct as st
    data = open(path, 'rb').read()
    hits = []
    for off in range(0, len(data) - 4, 4):
        w = st.unpack_from('<I', data, off)[0]
        op = w & 0xFFE00000
        imm16 = (w >> 5) & 0xFFFF
        if op in (0x52800000, 0x72A80000, 0xD2800000, 0xF2A80000) and imm16 in HASH_IVS:
            kind = {0x52800000: 'movz.w', 0x72A80000: 'movk.w lsl16',
                    0xD2800000: 'movz.x', 0xF2A80000: 'movk.x lsl16'}[op]
            hits.append((off, kind, imm16))
    print(f'hash-constant movz/movk hits: {len(hits)}')
    for off, kind, imm in hits[:40]:
        print(f'  0x{off:06x}  {kind:14s} #0x{imm:04x}  {HASH_IVS[imm]}')
    # 相邻聚集 → 引擎定位
    if hits:
        print(f'engine zone: file 0x{hits[0][0]:x} .. 0x{hits[-1][0]:x}')


def cmd_dxor(s, key, as_hex, strings_file):
    def dec(t):
        if as_hex:
            raw = bytes.fromhex(t)
            return bytes(b ^ key for b in raw).decode(errors='replace')
        return ''.join(chr(ord(c) ^ key) for c in t)
    if strings_file:
        for line in open(strings_file, encoding='utf-8', errors='replace'):
            t = line.rstrip('\n')
            if t:
                print(f'{t} -> {dec(t)}')
    else:
        print(dec(s))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('entropy')
    p.add_argument('file')
    p.add_argument('--block', type=int, default=64)

    p = sub.add_parser('ecb')
    p.add_argument('file')
    p.add_argument('--block', type=int, default=16)

    p = sub.add_parser('aes-scan')
    p.add_argument('so')

    p = sub.add_parser('hash-scan')
    p.add_argument('so')

    p = sub.add_parser('dxor')
    p.add_argument('str', nargs='?')
    p.add_argument('--key', type=lambda x: int(x, 0), default=0x10, help='per-char XOR key')
    p.add_argument('--hex', action='store_true', help='input is a hex string (bytes)')
    p.add_argument('--strings', help='file with one literal per line')

    p = sub.add_parser('rc4-scan')
    p.add_argument('file')
    p.add_argument('--key', required=True, help='hex key')
    p.add_argument('--stride', type=int, default=1, help='PRGA i stride per byte (variant family)')
    p.add_argument('--j-add', type=int, default=0, help='PRGA j increment offset (variant family; standard RC4 = 0)')
    p.add_argument('--seed-i', type=int, default=0)
    p.add_argument('--seed-j', type=int, default=0)
    p.add_argument('--range', default='1000:100000000', help='accepted declared-length range lo:hi')
    p.add_argument('--magic', default='789c', help='expected magic right after the length header (hex)')
    p.add_argument('--skip', type=int, default=0)

    p = sub.add_parser('rc4mat',
                       help='material-space scan: every offset of matsrc as a 14B-header key material '
                            '(parity-key derivation, cryptor family) -> variant RC4 -> [4B len][magic] judge')
    p.add_argument('matsrc', help='material source file (where the material may live)')
    p.add_argument('--carrier', required=True, help='ciphertext file')
    p.add_argument('--ct-off', default='0', help='ciphertext start offset in carrier (hex/dec)')
    p.add_argument('--stride', type=int, default=1, help='PRGA i stride per byte (variant family)')
    p.add_argument('--j-add', type=int, default=0, help='PRGA j increment offset (variant family)')
    p.add_argument('--seed-i', type=int, default=0)
    p.add_argument('--seed-j', type=int, default=0)
    p.add_argument('--range', default='1000:100000000', help='accepted declared-length range lo:hi')
    p.add_argument('--magic', default='auto', help="'auto' = RFC1950 CMF/FLG lattice, or exact hex (e.g. 789c)")
    p.add_argument('--keylen-max', type=int, default=64, help='material keylen lattice upper bound')
    p.add_argument('--limit', type=int, default=10)

    args = ap.parse_args()
    if args.cmd == 'entropy':
        cmd_entropy(args.file, args.block)
    elif args.cmd == 'ecb':
        cmd_ecb(args.file, args.block)
    elif args.cmd == 'aes-scan':
        cmd_aes_scan(args.so)
    elif args.cmd == 'hash-scan':
        cmd_hash_scan(args.so)
    elif args.cmd == 'dxor':
        cmd_dxor(args.str, args.key, args.hex, args.strings)
    elif args.cmd == 'rc4-scan':
        lo, hi = map(int, args.range.split(':'))
        cmd_rc4_scan(args.file, args.key, args.stride, args.seed_i, args.seed_j, (lo, hi), args.magic, args.skip, args.j_add)
    elif args.cmd == 'rc4mat':
        lo, hi = map(int, args.range.split(':'))
        cmd_rc4mat(args.matsrc, args.carrier, int(args.ct_off, 0), args.stride,
                   args.seed_i, args.seed_j, args.j_add, (lo, hi),
                   args.magic, args.keylen_max, args.limit)


if __name__ == '__main__':
    main()
