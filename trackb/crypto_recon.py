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

    args = ap.parse_args()
    if args.cmd == 'entropy':
        cmd_entropy(args.file, args.block)
    elif args.cmd == 'ecb':
        cmd_ecb(args.file, args.block)
    elif args.cmd == 'aes-scan':
        cmd_aes_scan(args.so)
    elif args.cmd == 'rc4-scan':
        lo, hi = map(int, args.range.split(':'))
        cmd_rc4_scan(args.file, args.key, args.stride, args.seed_i, args.seed_j, (lo, hi), args.magic, args.skip, args.j_add)


if __name__ == '__main__':
    main()
