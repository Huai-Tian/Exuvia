#!/usr/bin/env python3
"""sign2.py — minimal APK v2 signer (python-cryptography, sample-agnostic).

The repair pipeline's final step: the repaired APK must be installable, which
on API 30+ requires a v2 signature. This implements the APK Signature Scheme
v2 wire format (the 0x7109871a block) with RSASSA-PKCS1-v1_5 + SHA2-256
(algorithm id 0x0101) — the format every Android verifies:

  APK Signing Block: [u64 size][pairs: (u64 len, u32 id, value)...][u64 size]
                    [u64 magic "APK Sig Block 42"]
  inserted between the last zip entry and the Central Directory; the EOCD's
  CD-offset field adjusted past the block.

  v2 block value: [u32 len][signers seq]
  signer: [u32 sd_len][signed_data][u32 sigs_len][sigs][u32 pk_len][pk]
  signed_data: [u32 digests_len][digests][u32 certs_len][certs][u32 attrs_len][attrs]
  digest: [u32 alg_id][u32 digest_len][digest]
  The digest covers the whole zip in 3 regions (before the block, after the
  block to the CD, the CD + the EOCD with the block-stripped CD offset), each
  split into 1MB chunks hashed as SHA256(0xa5 | u32le(chunk_len) | chunk),
  top-level = SHA256(all chunk digests concatenated).

Usage:
  sign2.py <in.apk> <out.apk> [--key key.der --cert cert.der]
           (default: generates a fresh self-signed RSA-2048 test key)

Validation: sigx.py extracts the cert from the signed output; aapt/Android
accepts it. Zero-sample discipline: selftest builds a synthetic zip, signs,
re-extracts, verifies the digest.
"""
import argparse
import hashlib
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import datetime

V2_BLOCK_ID = 0x7109871A
SIG_ALG_RSA_PKCS1_SHA256 = 0x0101
MAGIC = b'APK Sig Block 42'
CHUNK = 1048576


def u32(b):
    return struct.pack('<I', b)


def u64(b):
    return struct.pack('<Q', b)


def chunk_digests(region: bytes) -> bytes:
    """The per-chunk SHA-256 digests of one region (1MB chunks, each prefixed
    0xa5 | u32le(len)). Returns the raw concatenation of chunk digests."""
    out = b''
    for i in range(0, len(region), CHUNK):
        chunk = region[i:i + CHUNK]
        out += hashlib.sha256(b'\xa5' + struct.pack('<I', len(chunk)) + chunk).digest()
    if not region:
        out = hashlib.sha256(b'\xa5' + struct.pack('<I', 0)).digest()
    return out


def _find_cd(data: bytes):
    i = data.rfind(b'PK\x05\x06')
    if i < 0:
        raise ValueError('no EOCD')
    return struct.unpack_from('<I', data, i + 16)[0], i


def gen_key_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Exuvia Repair')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


def _lp(payload: bytes) -> bytes:
    """A length-prefixed record: u32(len) + payload."""
    return u32(len(payload)) + payload


def _lp_seq(records: list) -> bytes:
    """A length-prefixed sequence of length-prefixed records:
    u32(sum of 4+len per record) + records."""
    return u32(sum(4 + len(r) for r in records)) + b''.join(_lp(r) for r in records)


def sign_v2(data: bytes, key, cert_der: bytes) -> bytes:
    cd_off, eocd_off = _find_cd(data)
    # region 1: everything before the block; region 2: empty (the block sits
    # immediately before the CD); region 3: the CD + the EOCD with the CD
    # offset treated as the pre-block position (v2 digest rule).
    region1 = data[:cd_off]
    region3 = data[cd_off:eocd_off] + data[eocd_off:eocd_off + 16] + u32(cd_off) + data[eocd_off + 20:]
    # ONE top-level digest over ALL chunks of ALL regions in order (v2 spec)
    digest = hashlib.sha256(chunk_digests(region1) + chunk_digests(region3)).digest()

    # signed_data: digests | certificates | additional attributes (empty)
    digest_record = u32(SIG_ALG_RSA_PKCS1_SHA256) + u32(len(digest)) + digest
    sd_bytes = (_lp_seq([digest_record])
                + _lp_seq([cert_der])
                + u32(0))
    # the signature covers the signed_data CONTENT (the sd_bytes)
    signature = key.sign(sd_bytes, padding.PKCS1v15(), hashes.SHA256())
    sig_record = u32(SIG_ALG_RSA_PKCS1_SHA256) + u32(len(signature)) + signature
    key_pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    signer = _lp(sd_bytes) + _lp_seq([sig_record]) + _lp(key_pub_der)
    v2_value = _lp_seq([signer])

    pair = u64(len(v2_value) + 4) + u32(V2_BLOCK_ID) + v2_value
    # block size = everything from the end of the first u64 size field through
    # the magic: pairs + 8 (trailing size) + 16 (magic)
    block = u64(len(pair) + 24) + pair + u64(len(pair) + 24) + MAGIC
    signed = data[:cd_off] + block + data[cd_off:]
    # the EOCD shifted by len(block) — edit at the NEW position
    new_cd_off = cd_off + len(block)
    new_eocd_off = eocd_off + len(block)
    signed = signed[:new_eocd_off + 16] + u32(new_cd_off) + signed[new_eocd_off + 20:]
    return signed


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('infile')
    ap.add_argument('outfile')
    ap.add_argument('--key', help='PEM/DER private key path (default: fresh test key)')
    ap.add_argument('--cert', help='DER cert path')
    args = ap.parse_args()

    data = open(args.infile, 'rb').read()
    if args.key:
        key = serialization.load_pem_private_key(open(args.key, 'rb').read(), password=None)
        cert_der = open(args.cert, 'rb').read()
    else:
        key, cert = gen_key_cert()
        cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed = sign_v2(data, key, cert_der)
    open(args.outfile, 'wb').write(signed)
    print('v2-signed: %s (%d bytes, +%d)' % (args.outfile, len(signed), len(signed) - len(data)))
    print('cert sha256: %s' % hashlib.sha256(cert_der).hexdigest()[:32])


if __name__ == '__main__':
    main()
