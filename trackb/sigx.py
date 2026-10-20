#!/usr/bin/env python3
"""sigx.py — APK signing-chain certificate extractor (Battle-1 r11 productized tool).

Extracts signer certificates from an APK's signing blocks and/or v1 META-INF,
writing one DER file per certificate plus a machine-readable manifest. The
output feeds directly into `so_emulator.py --sig-file` (runtime key derivation
chains that read the signing chain — Battle-1 r10 proved the expectation baked
into the shell equals the hardening-time original signature; this tool turns
"extract the original signature" into a one-liner).

Mechanical facts only: walks APK Signing Block pairs (u64 len + u32 id + value),
then the nested length-prefixed v2/v3 signer structures:
  [u32 signers_len][signer: [u32 sd_len][signed_data][u32 sigs_len][sigs][u32 pk_len][pk]]
  signed_data: [u32 digests_len][digests][u32 certs_len][certs][u32 attrs_len][attrs]
v1 fallback: any META-INF/*.RSA|DSA|EC entry is treated as a PKCS#7 container
and returned whole (Android's PackageInfo.signatures carries the certificate,
not the signature file — v2/v3 paths extract the true cert; the v1 path is an
honest approximation documented in the manifest).

Zero-sample discipline: selftest builds a synthetic APK with a synthetic
signing block (see selftest.py).

Usage:
  sigx.py <apk> [--out DIR] [--json]
"""
import struct
import sys
import zipfile


def _u32(b, p):
    return struct.unpack_from('<I', b, p)[0]


def _find_cd_off(data):
    i = data.rfind(b'PK\x05\x06')
    if i < 0:
        raise ValueError('no EOCD (not a zip/apk)')
    return struct.unpack_from('<I', data, i + 16)[0]


def _signing_block(data):
    """Return (block_bytes, offset_map) or (None, {}). Pairs: [u64 len][u32 id][value]."""
    cd = _find_cd_off(data)
    if cd < 24:
        return None, {}
    size = struct.unpack_from('<Q', data, cd - 24)[0]
    if size == 0 or cd - size - 8 < 0:
        return None, {}
    sb = data[cd - size - 8:cd]
    if sb[-16:] != b'APK Sig Block 42':
        return None, {}
    blocks = {}
    p = 8
    while p + 12 <= len(sb) - 24:
        ln = struct.unpack_from('<Q', sb, p)[0]
        bid = _u32(sb, p + 8)
        blocks[bid] = sb[p + 12:p + 8 + ln]
        p += 8 + ln
    return sb, blocks


def _certs_from_v2v3(val):
    """v2 (0x7109871a) and v3 (0xf05368c0) share the signer-nest shape."""
    out = []
    signers_len = _u32(val, 0)
    signers = val[4:4 + signers_len]
    if not signers:
        return out
    slen = _u32(signers, 0)
    signer = signers[4:4 + slen]
    sd_len = _u32(signer, 0)
    sd = signer[4:4 + sd_len]
    dp = 0
    dl = _u32(sd, dp); dp += 4 + dl        # digests
    cl = _u32(sd, dp); dp += 4
    certs = sd[dp:dp + cl]
    cp = 0
    while cp < len(certs):
        clen = _u32(certs, cp); cp += 4
        out.append(certs[cp:cp + clen]); cp += clen
    return out


def _certs_from_v1(apk_path):
    out = []
    with zipfile.ZipFile(apk_path) as z:
        for n in z.namelist():
            top = n.upper().rsplit('/', 1)[-1]
            if top.endswith(('.RSA', '.DSA', '.EC')) and n.upper().startswith('META-INF/'):
                out.append((n, z.read(n)))
    return out


def extract(apk_path):
    """Returns list of {'source': str, 'der': bytes}. v2/v3 first (true certs), v1 fallback."""
    data = open(apk_path, 'rb').read()
    result = []
    sb, blocks = _signing_block(data)
    if sb is not None:
        for bid, val in blocks.items():
            name = {0x7109871A: 'v2', 0xF05368C0: 'v3'}.get(bid)
            if name:
                for der in _certs_from_v2v3(val):
                    result.append({'source': name, 'der': der})
    if not result:
        for n, blob in _certs_from_v1(apk_path):
            result.append({'source': 'v1:%s (PKCS#7 whole-file approximation)' % n, 'der': blob})
    return result


def main():
    import argparse
    import hashlib
    import json
    import os
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('apk')
    ap.add_argument('--out', default='sigs', help='output directory (default sigs/)')
    args = ap.parse_args()

    certs = extract(args.apk)
    if not certs:
        print('{"error":"no-signing","detail":"no v2/v3 block, no v1 META-INF signature"}')
        sys.exit(1)
    os.makedirs(args.out, exist_ok=True)
    manifest = []
    for i, c in enumerate(certs):
        name = os.path.join(args.out, 'cert_%d.der' % (i + 1))
        with open(name, 'wb') as f:
            f.write(c['der'])
        manifest.append({
            'file': name,
            'source': c['source'],
            'size': len(c['der']),
            'sha256': hashlib.sha256(c['der']).hexdigest(),
        })
    print(json.dumps({'schema': 'exuvia.sigx', 'certs': manifest}, indent=2))
    print('feed example: so_emulator.py ... --sig-file %s' % manifest[0]['file'])


if __name__ == '__main__':
    main()
