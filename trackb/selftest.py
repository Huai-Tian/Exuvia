#!/usr/bin/env python3
"""Track B user-side tools self-test (synthetic fixtures only — zero-sample policy).

Runs the product tools end-to-end on self-built inputs:
  1. so_emulator: synthetic arm64 ELF64 with PT_LOAD + a `movz x0,#0x1234; ret`
     function — CLI invocation must capture the return value.
  2. crypto_recon rc4_keystream: RFC 6230 test vector (key="Key", data="Plaintext"
     -> BBF316E8D940AF0AD3) with standard stride-1/seed-0 parameters.
  3. crypto_recon entropy/ecb: smoke on deterministic PRNG blobs.

Exit code: 0 = all green. Requires unicorn (user-side dependency).
"""

import json
import struct
import subprocess
import sys
import tempfile
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build_minimal_arm64_elf() -> bytes:
    """Synthetic ELF64 little-endian aarch64: header + PHDR + one code page.

    Layout: 64B header | 56B PT_LOAD (off=0x1000, vaddr=0x1000) | pad | code.
    Code: movz x0, #0x1234 ; ret
    """
    eh = bytearray(64)
    eh[0:4] = b'\x7fELF'
    eh[4] = 2   # ELF64
    eh[5] = 1   # LE
    eh[6] = 1   # EV_CURRENT
    eh[16:18] = struct.pack('<H', 3)     # ET_DYN
    eh[18:20] = struct.pack('<H', 183)   # EM_AARCH64
    struct.pack_into('<Q', eh, 0x20, 64)   # e_phoff
    struct.pack_into('<H', eh, 0x36, 64)   # e_ehsize
    struct.pack_into('<H', eh, 0x38, 56)   # e_phentsize
    struct.pack_into('<H', eh, 0x3A, 1)    # e_phnum
    ph = bytearray(56)
    struct.pack_into('<I', ph, 0, 1)       # PT_LOAD
    struct.pack_into('<Q', ph, 8, 0x1000)  # p_offset
    struct.pack_into('<Q', ph, 16, 0x1000) # p_vaddr (identity)
    code_size = 0x100
    struct.pack_into('<Q', ph, 32, code_size)  # p_filesz
    struct.pack_into('<Q', ph, 40, code_size)  # p_memsz
    # movz x0, #0x1234 ; ret
    code = struct.pack('<I', 0xD2824600 | 0)  # movz x0, #0x1234 (imm16<<5)
    code = struct.pack('<I', (0x1234 << 5) | 0xD2800000) + struct.pack('<I', 0xD65F03C0)
    out = bytes(eh) + bytes(ph)
    out += b'\0' * (0x1000 - len(out))
    out += code + b'\0' * (code_size - len(code))
    return out


def test_so_emulator():
    try:
        import unicorn  # noqa: F401
    except ImportError:
        print('SKIP so_emulator (unicorn not installed — unavailable semantics)')
        return
    with tempfile.TemporaryDirectory() as td:
        so = os.path.join(td, 'synthetic.so')
        open(so, 'wb').write(build_minimal_arm64_elf())
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, 'so_emulator.py'), so, '--fn', '0x1000'],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'so_emulator exit {r.returncode}: {r.stderr}'
        out = json.loads(r.stdout)
        got = int(out['return'], 16)
        assert got == 0x1234, f'expected return 0x1234, got 0x{got:x}'
        print(f'so_emulator OK: synthetic fn returned 0x{got:x}')


def test_rc4_vector():
    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location('crypto_recon', os.path.join(HERE, 'crypto_recon.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # RFC 6230 test vector: key "Key", plaintext "Plaintext" -> BBF316E8D940AF0AD3
    ks = mod.rc4_keystream(b'Key', 9, stride=1, seed_i=0, seed_j=0)
    ct = bytes(a ^ b for a, b in zip(b'Plaintext', ks))
    expected = bytes.fromhex('BBF316E8D940AF0AD3')
    assert ct == expected, f'RC4 vector mismatch: {ct.hex()} != {expected.hex()}'
    print('crypto_recon rc4_keystream OK: RFC 6230 vector matches')


def test_recon_smoke():
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, 'blob.bin')
        # xorshift64* deterministic bytes — high entropy, all-unique blocks
        s = 0x12345678
        blob = bytearray()
        for _ in range(64 * 1024):
            s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
            s ^= s >> 7
            s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
            blob.append((s * 0x2545F4914F6CDD1D >> 56) & 0xFF)
        open(f, 'wb').write(bytes(blob))
        r = subprocess.run([sys.executable, os.path.join(HERE, 'crypto_recon.py'), 'ecb', f],
                           capture_output=True, text=True, timeout=60)
        assert 'all unique' in r.stdout, r.stdout
        print('crypto_recon ecb OK: PRNG blob fingerprinted as stream-cipher profile')


def build_minimal_arm32_elf() -> bytes:
    """Synthetic ELF32 little-endian ARM: header + PT_LOAD(phdr32) + code page.

    Code (ARM mode): mov r0, #0x12 ; bx lr — asserts on 'mov' + 'bx'.
    """
    import struct as _s
    eh = bytearray(52)
    eh[0:4] = b'\x7fELF'
    eh[4] = 1  # ELF32
    eh[5] = 1  # LE
    eh[6] = 1  # EV_CURRENT
    _s.pack_into('<H', eh, 16, 3)    # ET_DYN
    _s.pack_into('<H', eh, 18, 40)   # EM_ARM
    _s.pack_into('<I', eh, 0x1C, 52)  # e_phoff
    _s.pack_into('<H', eh, 0x2A, 32)  # e_phentsize (Elf32_Phdr)
    _s.pack_into('<H', eh, 0x2C, 1)   # e_phnum
    ph = bytearray(32)
    _s.pack_into('<I', ph, 0, 1)      # PT_LOAD
    _s.pack_into('<I', ph, 4, 0x1000)  # p_offset
    _s.pack_into('<I', ph, 8, 0x1000)  # p_vaddr
    _s.pack_into('<I', ph, 16, 0x100)  # p_filesz
    _s.pack_into('<I', ph, 20, 0x100)  # p_memsz
    code = _s.pack('<I', 0xE3A00012) + _s.pack('<I', 0xE12FFF1E)  # mov r0,#0x12 ; bx lr
    out = bytes(eh) + bytes(ph)
    out += b'\0' * (0x1000 - len(out))
    out += code + b'\0' * (0x100 - len(code))
    return out


def test_disasm():
    try:
        import capstone  # noqa: F401
    except ImportError:
        print('SKIP disasm (capstone not installed — unavailable semantics)')
        return
    with tempfile.TemporaryDirectory() as td:
        so = os.path.join(td, 'synthetic.so')
        open(so, 'wb').write(build_minimal_arm64_elf())
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, 'disasm.py'), so, '--fn', '0x1000', '--len', '0x10'],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'disasm exit {r.returncode}: {r.stderr}'
        assert 'mov' in r.stdout and 'ret' in r.stdout, r.stdout  # capstone renders movz as mov alias
        print('disasm OK: synthetic fn stream contains mov + ret')
        # ELF32 ARM path (Battle-1: half the shell libs are 32-bit — read side must cover them)
        so32 = os.path.join(td, 'synthetic32.so')
        open(so32, 'wb').write(build_minimal_arm32_elf())
        r2 = subprocess.run(
            [sys.executable, os.path.join(HERE, 'disasm.py'), so32, '--fn', '0x1000', '--len', '0x10'],
            capture_output=True, text=True, timeout=60)
        assert r2.returncode == 0, f'disasm32 exit {r2.returncode}: {r2.stderr}'
        assert 'mov' in r2.stdout and 'bx' in r2.stdout, r2.stdout
        print('disasm OK: ELF32 ARM stream contains mov + bx lr')


def build_synthetic_signed_apk(cert_der: bytes) -> bytes:
    """Synthetic APK: minimal zip with a synthetic v2 APK Signing Block before the CD.
    Layout mirrors the real block: [u64 size][pairs: [u64 len][u32 id][value]...][u64 size][16B magic],
    with size = len(pairs) + 24 (covers the trailing size field + magic)."""
    def u32(v): return struct.pack('<I', v)
    def u64(v): return struct.pack('<Q', v)
    # v2 value 三层长度前缀（corpus 原包逐字段实证 1320 = 4+1316 = 4+[4+1312]）：
    #   val = [signers_len][ [signer_len][ [sd_len][ [digests_len][] [certs_len][certs] ] ] ]
    #   —— 每个 _len 字段 = 其后内容净长（不含自身 4B）
    cert_entry = u32(len(cert_der)) + cert_der
    certs = u32(len(cert_entry)) + cert_entry
    sd = u32(0) + certs
    signer = u32(len(sd)) + sd
    signer_entry = u32(len(signer)) + signer
    val = u32(len(signer_entry)) + signer_entry
    pair = u64(4 + len(val)) + u32(0x7109871A) + val  # ln = id(4B) + value
    size = len(pair) + 24
    block = u64(size) + pair + u64(size) + b'APK Sig Block 42'
    import zipfile, io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
    zbytes = buf.getvalue()
    cd_off = zbytes.rfind(b'PK\x01\x02')
    assert cd_off > 0
    out = zbytes[:cd_off] + block + zbytes[cd_off:]
    # EOCD 的 CD offset 字段必须前移 len(block)（真实签名 APK 由工具链维护此字段）
    eocd = out.rfind(b'PK\x05\x06')
    assert eocd > 0
    return out[:eocd + 16] + struct.pack('<I', cd_off + len(block)) + out[eocd + 20:]


def test_sigx():
    """sigx.py: synthetic APK + synthetic signing block -> DER round-trip (r11 tool)."""
    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location('sigx', os.path.join(HERE, 'sigx.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # synthetic cert DER: minimal X.509-ish SEQUENCE head + deterministic payload
    cert = bytes.fromhex('3082010a') + bytes((i * 7 + 3) & 0xFF for i in range(256))
    apk_bytes = build_synthetic_signed_apk(cert)
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, 'synthetic.apk')
        open(apk, 'wb').write(apk_bytes)
        out = os.path.join(td, 'sigs')
        r = subprocess.run([sys.executable, os.path.join(HERE, 'sigx.py'), apk, '--out', out],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'sigx exit {r.returncode}: {r.stderr}'
        got = open(os.path.join(out, 'cert_1.der'), 'rb').read()
        assert got == cert, f'DER round-trip mismatch: {len(got)}B vs {len(cert)}B'
        print('sigx OK: synthetic signing block -> DER round-trip')


if __name__ == '__main__':
    test_so_emulator()
    test_rc4_vector()
    test_recon_smoke()
    test_disasm()
    test_sigx()
    print('trackb selftest: ALL GREEN')
