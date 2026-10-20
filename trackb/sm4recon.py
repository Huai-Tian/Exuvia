#!/usr/bin/env python3
"""sm4recon.py — SM4 recon/decrypt tool (Battle-1 r12 productized tool).

Battle-1's SECOND engine (below the variant-RC4 layer) is SM4 (GB/T 32907-2016)
in CFB mode with a zero IV:
  keystream block 1 = E(0);  block n = E(ciphertext block n-1)
  plaintext = ciphertext XOR keystream        (CFB is symmetric)
Round keys (RK, 32 x u32 = 128 bytes) are shell-derived — 0x2c677c expands a
key-material (r11 fact: s2 = MD5(signature)) XOR a static template; the
vanilla textbook schedule is also provided (--rkexp) for standard-SM4 shells.

Verification anchors: S-box head d6 90 e9 fe cc e1 3d b7; GB/T 32907 Appendix-A
vector key=0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246.

Subcommands:
  dec/enc <file> --rk <rk.bin> [--offset N] [--len N] [--out FILE]
      CFB decrypt (== encrypt) a carrier segment.
  scan <file> --rk <rk.bin> [--form material|zlib|dex|all] [--limit N]
      full-offset scan of the constant block-1 keystream; 'material' is the
      14-byte-header key-material lattice (keylen/flag/shift — the
      __arm_c_1 feeding format, r10 fact), 'zlib'/'dex' are payload forms.
  rkexp --key <HEX>       textbook key expansion -> 32 RK u32s (stdout)
"""
import argparse
import struct
import sys

# GB/T 32907-2016 standard S-box (256 bytes; extracted and byte-verified
# against the Battle-1 corpus shell's 0x2caf00 table — identical to standard).
SBOX = bytes([
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
])
assert SBOX[:8] == bytes.fromhex('d690e9fecce13db7'), 'S-box corrupted'

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
# CK_i 字节 = 7*(4i+j)（GB/T 32907-2016；CK_0 = 0x00070e15）
CK = [sum((((7 * (4 * i + j)) & 0xff) << (24 - 8 * j)) for j in range(4)) for i in range(32)]


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _tau(a):
    return ((SBOX[(a >> 24) & 0xff] << 24) | (SBOX[(a >> 16) & 0xff] << 16)
            | (SBOX[(a >> 8) & 0xff] << 8) | SBOX[a & 0xff])


def _L(b):       # round-function linear layer (rotl 2/10/18/24)
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _Lp(b):      # key-expansion linear layer (rotl 13/23)
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def rk_standard(key16):
    """Textbook key expansion: 16-byte key -> 32 RK u32s."""
    MK = struct.unpack('>4I', key16)
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        t = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]
        K.append(K[i] ^ _Lp(_tau(t)))
        rk.append(K[-1])
    return rk


def sm4_block(rk, block):
    """SM4 encrypt one 16-byte block (decrypt = caller reverses rk)."""
    X = list(struct.unpack('>4I', block))
    for i in range(32):
        t = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]
        X.append(X[i] ^ _L(_tau(t)))
    return struct.pack('>4I', X[35], X[34], X[33], X[32])


def cfb_keystream(rk, data, off, n):
    """CFB keystream over data[off:off+n] — block1 = E(0), then E(prev cipher)."""
    ks = sm4_block(rk, b'\0' * 16)
    out = ks
    pos = 16
    while pos < n:
        ct = data[off + pos - 16: off + pos]
        ks = sm4_block(rk, ct)
        out += ks
        pos += 16
    return out[:n]


def cfb_crypt(data, off, n, rk):
    """CFB decrypt: feedback walks the INPUT (ciphertext) — matches the shell engine."""
    ks = cfb_keystream(rk, data, off, n)
    return bytes(data[off + i] ^ ks[i] for i in range(n))


def cfb_encrypt(rk, plain):
    """CFB encrypt: feedback walks the OUTPUT (ciphertext). Decrypt with cfb_crypt."""
    out = b''
    prev = b'\0' * 16
    for i in range(0, len(plain), 16):
        ks = sm4_block(rk, prev)
        block = plain[i:i + 16]
        cb = bytes(a ^ b for a, b in zip(block, ks))
        out += cb
        prev = cb
    return out


# ---- forms ----
def is_zlib(a, b):
    return (a & 0x0f) == 8 and ((a << 8) | b) % 31 == 0 and (b & 0x20) == 0


def is_keymaterial(p):
    """14-byte-header key-material lattice (Battle-1 r10 fact, 0x7184 semantics)."""
    if len(p) < 16:
        return False
    keylen = struct.unpack_from('<h', p, 6)[0]
    flag = struct.unpack_from('<H', p, 8)[0]
    shift = p[0xe]
    return keylen in (16, 24, 32, 48, 64) and flag <= 0x100 and shift <= 31


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_dec = sub.add_parser('dec', help='CFB decrypt (same as enc — CFB is symmetric)')
    p_enc = sub.add_parser('enc', help='alias of dec')
    for p in (p_dec, p_enc):
        p.add_argument('file')
        p.add_argument('--rk', required=True, help='128-byte round-key file')
        p.add_argument('--offset', default='0')
        p.add_argument('--len', default='0x100')
        p.add_argument('--out', default=None)

    p_scan = sub.add_parser('scan', help='full-offset scan (block-1 keystream is constant)')
    p_scan.add_argument('file')
    p_scan.add_argument('--rk', required=True)
    p_scan.add_argument('--form', default='all', choices=['material', 'zlib', 'dex', 'all'])
    p_scan.add_argument('--limit', type=int, default=20)

    p_rk = sub.add_parser('rkexp', help='textbook key expansion (16-byte key)')
    p_rk.add_argument('--key', required=True)

    args = ap.parse_args()
    if args.cmd == 'rkexp':
        key = bytes.fromhex(args.key)
        assert len(key) == 16
        rk = rk_standard(key)
        print(struct.pack('<32I', *rk).hex())
        return

    rk_bytes = open(args.rk, 'rb').read()
    assert len(rk_bytes) == 128, 'rk file must be exactly 128 bytes (32 x u32 LE)'
    rk = struct.unpack('<32I', rk_bytes)

    if args.cmd in ('dec', 'enc'):
        data = open(args.file, 'rb').read()
        off = int(args.offset, 0)
        n = min(int(args.len, 0), len(data) - off)
        out = cfb_crypt(data, off, n, rk)
        if args.out:
            open(args.out, 'wb').write(out)
            print('{"wrote":"%s","offset":"0x%x","len":"0x%x"}' % (args.out, off, n))
        else:
            print(out.hex())

    elif args.cmd == 'scan':
        data = open(args.file, 'rb').read()
        ks1 = sm4_block(rk, b'\0' * 16)
        forms = args.form
        hits = 0
        for o in range(len(data) - 16):
            p = bytes(data[o + k] ^ ks1[k] for k in range(16))
            form = None
            if forms in ('material', 'all') and is_keymaterial(p):
                form = 'material'
            elif forms in ('dex', 'all') and p[:4] == b'dex\n':
                form = 'dex'
            elif forms in ('zlib', 'all') and is_zlib(p[0], p[1]):
                form = 'zlib@0'
            elif forms in ('zlib', 'all') and is_zlib(p[4], p[5]):
                ln = struct.unpack_from('<I', p, 0)[0]
                if 0x70 < ln < 100 * 1024 * 1024:
                    form = 'len+zlib'
            if form:
                hits += 1
                if hits <= args.limit:
                    print('0x%x %s %s' % (o, form, p.hex()))
        print('{"scan_done":"0x%x","form":"%s","hits":%d}' % (len(data), forms, hits))


if __name__ == '__main__':
    main()
