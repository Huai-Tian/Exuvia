#!/usr/bin/env python3
"""Exuvia Track B: DEX tail-container reconstructor (profile-driven).

A common shell layout keeps a tiny stub classes.dex in the APK and appends the
real payload after it: [stub dex][encrypted header block][dex#1 body][sub-
containers...][trailer]. The runtime .so reassembles the real dex images in
memory at load time. When the crypto is static (key/IV recoverable from the
.so rodata — typical for this layout), the whole reconstruction can be done
STATICALLY, with no dump and no emulation.

This module is family-agnostic: the layout is described by a profile (CLI
args or JSON). Verification is format-driven and needs no profile to trust:
every recovered dex must pass its own header sha1+adler32 self-check — a
byte-perfect oracle that cannot false-positive.

Profile "aes128cbc-tail-v1" (the layout this module ships as the reference):
  classes.dex = [stub dex 0..L) + [enc_len AES-128-CBC block] + [dex#1 body]
              + [sub-container]* + [trailer; last 4B big-endian = L]
  decrypted block: [name_len B app-class-name + NUL][3B file_size BE]
                   [dex#1 header at +0x1c ...]
  dex#1 = block[0x1c:enc_len] + tail[enc_len : enc_len + (fsize-(enc_len-0x1c))]
  sub-container: [4B BE len][payload]; payload's first xor_prefix bytes are
  XORed with xor_key, the rest is plaintext.

Usage:
  python3 dexcontainer.py packed_classes.dex out_dir \
      --key bajk3b4j3bvuoa3h --iv mers46ha35ga23hn
  python3 dexcontainer.py packed_classes.dex out_dir --profile layout.json
  python3 dexcontainer.py packed_classes.dex out_dir --key-so shell.so:0x566dd \
      --iv-so shell.so:0x57a91

Exit codes: 0 = at least one dex recovered AND self-verified; 3 = bad input;
4 = no dex passed self-verification (wrong profile/key — not silent garbage).
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


def read_key_spec(spec):
    """'ascii-or-hex-string' or 'file:offset' (16 raw bytes at file offset)."""
    if ':' in spec and os.path.exists(spec.split(':')[0]):
        path, off = spec.split(':', 1)
        with open(path, 'rb') as f:
            f.seek(int(off, 16) if off.startswith('0x') else int(off))
            return f.read(16)
    try:
        b = bytes.fromhex(spec)
        if len(b) == 16:
            return b
    except ValueError:
        pass
    b = spec.encode()
    if len(b) != 16:
        raise ValueError('key/iv must resolve to 16 bytes: %r' % spec)
    return b


def dex_self_check(buf):
    """A real dex verifies its own header: sha1(bytes[0x20:]) and adler32
    (bytes[0x0c:]). Byte-perfect oracle — anything else is not this dex."""
    if len(buf) < 0x70 or not buf.startswith(b'dex\n'):
        return False
    fsize = struct.unpack('<I', buf[0x20:0x24])[0]
    if fsize != len(buf):
        return False
    if hashlib.sha1(buf[0x20:]).digest() != buf[0x0c:0x20]:
        return False
    return (zlib.adler32(buf[0x0c:]) & 0xffffffff) == struct.unpack('<I', buf[8:12])[0]


def rebuild(packed, key, iv, enc_len=0x210, hdr_off=0x1c, xor_prefix=0x70, xor_key=0x66):
    """The aes128cbc-tail-v1 layout. Returns (app_class_name, [dex bytes...]).

    Layout of the decrypted header block:
      [uleb-ish len byte][app class name][NUL][3B big-endian file size]
      [dex#1 header at hdr_off ...]
    dex#1 = block[hdr_off:hdrlen] + tail[enc_len : enc_len + (fsize-(hdrlen-hdr_off))]
    where hdrlen = enc_len - pkcs7_pad. dex#1's own header file_size field is
    the length source — the profile never hardcodes sizes.
    Sub-containers follow dex#1: [4B BE len][payload], payload's first
    xor_prefix bytes XORed with xor_key, rest plaintext.
    """
    if AES is None:
        raise RuntimeError('pycryptodome required (pip install pycryptodome)')
    L = struct.unpack('>I', packed[-4:])[0]
    tail = packed[L:]
    pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(tail[:enc_len])
    pad = pt[-1]
    hdrlen = enc_len - pad if 0 < pad <= 16 else enc_len
    namelen = pt[0]
    app_name = pt[1:1 + namelen].split(b'\0')[0].decode('utf-8', 'replace')
    fsize = struct.unpack('<I', pt[hdr_off + 32:hdr_off + 36])[0]  # dex header file_size
    if not (0x100 < fsize < 0x10000000):
        raise ValueError('implausible dex#1 size %s — wrong key/iv/profile?' % hex(fsize))
    dex1 = pt[hdr_off:hdrlen] + tail[enc_len:enc_len + (fsize - (hdrlen - hdr_off))]
    if len(dex1) != fsize:
        raise ValueError('dex#1 truncated: got %d want %d' % (len(dex1), fsize))
    out = [dex1]
    buf = pt[:hdrlen] + tail[enc_len:-4]
    pos = hdr_off + fsize
    while pos + 4 <= len(buf):
        ln = int.from_bytes(buf[pos:pos + 4], 'big')
        if ln <= 0 or pos + 4 + ln > len(buf):
            break
        payload = buf[pos + 4:pos + 4 + ln]
        if xor_prefix:
            sub = bytes(b ^ xor_key for b in payload[:xor_prefix]) + payload[xor_prefix:]
        else:
            sub = payload
        if sub.startswith(b'dex\n'):
            out.append(sub)
        pos += 4 + ln
    return app_name, out


def main():
    ap = argparse.ArgumentParser(description='Rebuild dex images from a shell tail container')
    ap.add_argument('packed_dex', help='classes.dex as shipped in the packed APK')
    ap.add_argument('out_dir')
    ap.add_argument('--profile', help='JSON profile: {key, iv, enc_len, hdr_off, xor_prefix, xor_key}')
    ap.add_argument('--key', help='16B key as ascii/hex, or file:offset into the shell .so')
    ap.add_argument('--iv', help='16B IV as ascii/hex, or file:offset')
    ap.add_argument('--enc-len', type=lambda s: int(s, 0), default=0x210)
    ap.add_argument('--hdr-off', type=lambda s: int(s, 0), default=0x1c)
    ap.add_argument('--xor-prefix', type=lambda s: int(s, 0), default=0x70)
    ap.add_argument('--xor-key', type=lambda s: int(s, 0), default=0x66)
    args = ap.parse_args()

    prof = {}
    if args.profile:
        prof = json.load(open(args.profile))
    key = read_key_spec(args.key or prof['key'])
    iv = read_key_spec(args.iv or prof['iv'])
    enc_len = prof.get('enc_len', args.enc_len)
    hdr_off = prof.get('hdr_off', args.hdr_off)
    xor_prefix = prof.get('xor_prefix', args.xor_prefix)
    xor_key = prof.get('xor_key', args.xor_key)

    packed = open(args.packed_dex, 'rb').read()
    app_name, dexes = rebuild(packed, key, iv, enc_len=enc_len, hdr_off=hdr_off,
                              xor_prefix=xor_prefix, xor_key=xor_key)
    os.makedirs(args.out_dir, exist_ok=True)
    verified = 0
    for i, d in enumerate(dexes, 1):
        ok = dex_self_check(d)
        tag = 'VERIFIED' if ok else 'FAILED-SELF-CHECK'
        if ok:
            verified += 1
        path = os.path.join(args.out_dir, f'classes{i}_rebuilt.dex')
        with open(path, 'wb') as f:
            f.write(d)
        print(f'[{tag}] {path} ({len(d)} bytes)')
    print(f'original application class: {app_name}')
    print(json.dumps({'app': app_name, 'dexes': len(dexes), 'verified': verified}))
    if verified == 0:
        sys.exit(4)


if __name__ == '__main__':
    main()
