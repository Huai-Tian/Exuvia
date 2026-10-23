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
    # raw-syscall bridge (r27): synthetic fn does openat(path)+read(fd,buf,16)
    # through 'mov x8,#N; svc #0' stubs — the --fs world must serve the file and
    # the fd table must carry fd/lseek state across BOTH svc calls.
    with tempfile.TemporaryDirectory() as td:
        realfile = os.path.join(td, 'svc.bin')
        content = b'SYSCALL_BRIDGE_OK'
        open(realfile, 'wb').write(content)
        so = os.path.join(td, 'syscall.so')
        eh = bytearray(64)
        eh[0:4] = b'\x7fELF'
        eh[4] = 2
        eh[5] = 1
        eh[6] = 1
        eh[16:18] = struct.pack('<H', 3)
        eh[18:20] = struct.pack('<H', 183)
        struct.pack_into('<Q', eh, 0x20, 64)
        struct.pack_into('<H', eh, 0x36, 64)
        struct.pack_into('<H', eh, 0x38, 56)
        struct.pack_into('<H', eh, 0x3A, 1)
        ph = bytearray(56)
        struct.pack_into('<I', ph, 0, 1)
        struct.pack_into('<Q', ph, 8, 0x1000)
        struct.pack_into('<Q', ph, 16, 0x1000)
        struct.pack_into('<Q', ph, 32, 0x1000)
        struct.pack_into('<Q', ph, 40, 0x1000)
        code = b''.join(struct.pack('<I', w) for w in (
            0x92800C60,  # movn x0, #0x63     -> AT_FDCWD (-100)
            0xD2822001,  # movz x1, #0x1100   -> pathname vaddr
            0xD2800002,  # movz x2, #0        -> O_RDONLY
            0xD2800003,  # movz x3, #0        -> mode
            0xD2800708,  # movz x8, #56       -> NR openat
            0xD4000001,  # svc #0             -> x0 = fd
            0xD2824001,  # movz x1, #0x1200   -> buf vaddr
            0xD2800222,  # movz x2, #17       -> count
            0xD28007E8,  # movz x8, #63       -> NR read
            0xD4000001,  # svc #0             -> x0 = nread
            0xD65F03C0,  # ret
        ))
        img = bytes(eh) + bytes(ph)
        img += b'\0' * (0x1000 - len(img))
        img += code + b'\0' * (0x100 - len(code))
        img += b'\0' * (0x1100 - len(img))
        img += b'/data/local/tmp/svc_test.bin\0'
        img += b'\0' * (0x1200 - len(img))
        img += b'\0' * (0x1000 - (len(img) - 0x1000))
        open(so, 'wb').write(img)
        dumpf = os.path.join(td, 'buf.bin')
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, 'so_emulator.py'), so, '--fn', '0x1000',
             '--fs', '/data/local/tmp/svc_test.bin:' + realfile,
             '--dump-mem', '0x1200:17:' + dumpf],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'so_emulator svc exit {r.returncode}: {r.stderr}\n{r.stdout}'
        out = json.loads(r.stdout)
        assert int(out['return'], 16) == 17, f'expected read()=17, got {out["return"]}'
        assert open(dumpf, 'rb').read() == content, 'read() buffer mismatch'
        ev = {e.get('svc'): e for e in out.get('svc_events', [])}
        assert 'openat' in ev and ev['openat'].get('fd', 0) >= 0x100, out.get('svc_events')
        print('so_emulator svc OK: raw openat/read syscalls served from the --fs world')
    # --chain session mode (r28): fn1 stores a magic into the image; fn2 loads
    # it back — the second entry MUST observe the first entry's write (shared
    # memory across entries in one emulated process).
    with tempfile.TemporaryDirectory() as td:
        so = os.path.join(td, 'chain.so')
        eh = bytearray(64)
        eh[0:4] = b'\x7fELF'
        eh[4] = 2
        eh[5] = 1
        eh[6] = 1
        eh[16:18] = struct.pack('<H', 3)
        eh[18:20] = struct.pack('<H', 183)
        struct.pack_into('<Q', eh, 0x20, 64)
        struct.pack_into('<H', eh, 0x36, 64)
        struct.pack_into('<H', eh, 0x38, 56)
        struct.pack_into('<H', eh, 0x3A, 1)
        ph = bytearray(56)
        struct.pack_into('<I', ph, 0, 1)
        struct.pack_into('<Q', ph, 8, 0x1000)
        struct.pack_into('<Q', ph, 16, 0x1000)
        struct.pack_into('<Q', ph, 32, 0x1000)
        struct.pack_into('<Q', ph, 40, 0x1000)
        fn1 = b''.join(struct.pack('<I', w) for w in (
            0xD2822000,   # movz x0, #0x1100   (cell address)
            0xD297DDE1,   # movz x1, #0xBEEF   (0xBEEF<<5|1 — carry counted!)
            0xF9000001,   # str x1, [x0]
            0xD65F03C0,   # ret
        ))
        fn2 = b''.join(struct.pack('<I', w) for w in (
            0xD2822000,  # movz x0, #0x1100
            0xF9400000,  # ldr x0, [x0]
            0xD65F03C0,  # ret
        ))
        img = bytes(eh) + bytes(ph)
        img += b'\0' * (0x1000 - len(img))
        img += fn1 + b'\0' * (0x10 - len(fn1)) + fn2
        img += b'\0' * (0x1000 - (len(img) - 0x1000))
        open(so, 'wb').write(img)
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, 'so_emulator.py'), so,
             '--chain', '0x1000,0x1010'],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'chain exit {r.returncode}: {r.stderr}\n{r.stdout}'
        out = json.loads(r.stdout)
        assert out['chain_returns'] == ['0x1100', '0xbeef'], out['chain_returns']
        print('so_emulator chain OK: fn1 write observed by fn2 (session-shared memory)')


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


def test_sm4recon():
    """sm4recon.py: GB/T 32907 Appendix-A vector + CFB round-trip + scan hit (r12 tool)."""
    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location('sm4recon', os.path.join(HERE, 'sm4recon.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    rk = mod.rk_standard(key)
    out = mod.sm4_block(rk, key)
    expected = bytes.fromhex('681edf34d206965e86b3e94f536e4246')
    assert out == expected, f'SM4 vector mismatch: {out.hex()}'
    print('sm4recon OK: GB/T 32907 Appendix-A vector matches')
    # CFB round-trip：encrypt（feedback 走输出）→ decrypt（feedback 走输入）== 明文
    plain = bytes((i * 31 + 7) & 0xFF for i in range(64))
    cipher = mod.cfb_encrypt(rk, plain)
    assert mod.cfb_crypt(cipher, 0, 64, rk) == plain, 'CFB round-trip failed'
    print('sm4recon OK: CFB round-trip')
    # r15: nonzero IV — the IV is a call-site fact, not a constant. Round-trip
    # with an explicit IV, then scan with the matching block-1 constant E(IV).
    iv = bytes(range(16))
    cipher_iv = mod.cfb_encrypt(rk, plain, iv)
    assert mod.cfb_crypt(cipher_iv, 0, 64, rk, iv) == plain, 'CFB nonzero-IV round-trip failed'
    print('sm4recon OK: CFB round-trip with nonzero IV')
    # scan：把合成材料头藏进随机海洋 → form=material 必须命中
    import struct as _s
    mat = bytearray(16)
    _s.pack_into('<h', mat, 6, 32)     # keylen = 32
    _s.pack_into('<H', mat, 8, 1)      # flag
    mat[0xe] = 8                       # shift
    carrier = bytearray()
    s = 0x1234
    for _ in range(2048):
        s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 7
        s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
        carrier.append((s * 0x2545F4914F6CDD1D >> 56) & 0xFF)
    off = 777
    carrier[off:off+16] = bytes(a ^ b for a, b in zip(mat, mod.sm4_block(rk, b'\0'*16)))
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, 'carrier.bin')
        open(f, 'wb').write(bytes(carrier))
        rkf = os.path.join(td, 'rk.bin')
        open(rkf, 'wb').write(struct.pack('<32I', *rk))
        r = subprocess.run([sys.executable, os.path.join(HERE, 'sm4recon.py'), 'scan', f,
                            '--rk', rkf, '--form', 'material', '--limit', '50'],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'sm4recon scan exit {r.returncode}: {r.stderr}'
        # r17: corrected s16-keylen lattice is weaker (honest semantics) -> more FPs;
        # the planted offset must still be among the printed hits.
        assert 'material' in r.stdout and '0x309' in r.stdout, r.stdout  # 777 = 0x309
        print('sm4recon OK: material-form scan hits the planted offset')
        # scan --iv：block-1 常量 = E(IV)（r15：IV 是调用现场事实，扫描器必须参数化）
        carrier_iv = bytearray(carrier)
        carrier_iv[off:off+16] = bytes(a ^ b for a, b in zip(mat, mod.sm4_block(rk, iv)))
        f_iv = os.path.join(td, 'carrier_iv.bin')
        open(f_iv, 'wb').write(bytes(carrier_iv))
        r = subprocess.run([sys.executable, os.path.join(HERE, 'sm4recon.py'), 'scan', f_iv,
                            '--rk', rkf, '--iv', iv.hex(), '--form', 'material', '--limit', '50'],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f'sm4recon scan --iv exit {r.returncode}: {r.stderr}'
        assert 'material' in r.stdout and '0x309' in r.stdout, r.stdout
        print('sm4recon OK: --iv scan hits the planted offset with E(IV) block-1')


def test_elfrecon():
    """elfrecon: synthetic stripped-magic ELF scan + dynsym backtracking recovery.

    Fixture A: a 60-byte magic-stripped aarch64 ET_DYN header planted at a PRNG
    ocean offset — `scan` must report exactly that offset and the fields we set.
    Fixture B: an Elf64_Sym table (3 defined FUNC + 1 UND import) before a
    .dynstr (with foreign metadata between) — `symbols --strtab-at` must recover
    all 4 names/vals through the slack backtracking route.
    """
    import struct
    # ---- fixture A: stripped-magic ELF header
    hdr = bytearray(60)
    hdr[0] = 2          # EI_CLASS = 64-bit
    hdr[1] = 1          # EI_DATA = LE
    hdr[2] = 1          # EI_VERSION
    struct.pack_into('<HH', hdr, 12, 3, 0xB7)       # e_type=ET_DYN, e_machine=aarch64
    struct.pack_into('<I', hdr, 16, 1)              # e_version
    struct.pack_into('<QQ', hdr, 20, 0x31fe0, 0x40)  # e_entry, e_phoff
    struct.pack_into('<HHHHHH', hdr, 48, 0x40, 56, 4, 64, 8, 7)  # ehsize..shstrndx
    ocean = bytearray()
    s = 0xbeef
    for _ in range(8192):
        s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 7
        s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
        ocean.append((s * 0x2545F4914F6CDD1D >> 56) & 0xFF)
    plant = 1234
    blob = bytes(ocean[:plant]) + bytes(hdr) + bytes(ocean[plant:]) + bytes(hdr)  # one at tail too
    with tempfile.TemporaryDirectory() as td:
        fa = os.path.join(td, 'ocean.bin')
        open(fa, 'wb').write(blob)
        r = subprocess.run([sys.executable, os.path.join(HERE, 'elfrecon.py'), 'scan', fa],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f'scan exit {r.returncode}: {r.stderr}'
        assert '0x%08x' % plant in r.stdout and 'stripped' in r.stdout and 'aarch64' in r.stdout, r.stdout
        assert '0x%08x' % (len(blob) - 60) in r.stdout, r.stdout  # tail hit too
        print('elfrecon scan OK: stripped-magic ELF found at planted + tail offsets')
    # ---- fixture B: dynsym backtrack through slack
    strtab = b'\x00'
    names = []
    for nm in (b'JNI_OnLoad', b'parse_entry', b'read_bits', b'lseek'):
        names.append(len(strtab))
        strtab += nm + b'\x00'
    symtab = bytearray()
    for st_name, val in zip(names, (0x40, 0x80, 0xc0, 0)):
        symtab += struct.pack('<IBBHQQ', st_name, (1 << 4) | 2, 0, 0 if val == 0 else 7, val, 64)
    pad = b'\xcc' * 16  # foreign metadata between symtab end and strtab
    fb = bytes(symtab) + pad + strtab
    with tempfile.TemporaryDirectory() as td:
        fbb = os.path.join(td, 'symblob.bin')
        open(fbb, 'wb').write(fb)
        strtab_at = len(symtab) + len(pad)
        r = subprocess.run([sys.executable, os.path.join(HERE, 'elfrecon.py'), 'symbols', fbb,
                            '--strtab-at', str(strtab_at)], capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f'symbols exit {r.returncode}: {r.stderr}'
        for nm in ('JNI_OnLoad', 'parse_entry', 'read_bits', 'lseek'):
            assert nm in r.stdout, r.stdout
        assert 'val=0x000000c0' in r.stdout and 'val=0x00000040' in r.stdout, r.stdout
        print('elfrecon symbols OK: 4-entry dynsym recovered through 16B slack (backtrack route)')


def _build_synthetic_axml():
    """A minimal AXML: string pool + one <application> with a stub android:name.
    Layout: file hdr | string pool | start elem (2 attrs) | end elem."""
    import struct as _s

    def _u16(v):
        return _s.pack('<H', v)

    def _u32(v):
        return _s.pack('<I', v)

    strings = ['application', 'name', 'com.stub.StubApp', 'allowBackup']
    # string pool chunk: hdr(8) + count/styleCount/flags/stringsStart/stylesStart (20)
    offsets = []
    data = b''
    for sstr in strings:
        enc = _u16(len(sstr)) + sstr.encode('utf-16-le') + b'\x00\x00'
        offsets.append(len(data))
        data += enc
    strings_start = 28 + 4 * len(strings)
    pool = (_u16(0x0001) + _u16(28) + _u32(0)  # csize patched below
            + _u32(len(strings)) + _u32(0) + _u32(0) + _u32(strings_start) + _u32(0)
            + b''.join(_u32(o) for o in offsets) + data)
    pool = bytearray(pool)
    _s.pack_into('<I', pool, 4, len(pool))
    pool = bytes(pool)
    # start element: headerSize=16, attrStart=20, attrSize=20, 2 attrs
    # attrs: name="com.stub.StubApp" (idx 1/2), allowBackup (idx 3 raw=-1 data=0)
    a1 = _u32(0xFFFFFFFF) + _u32(1) + _u32(2) + _u16(8) + bytes([0, 0x03]) + _u32(2)
    a2 = _u32(0xFFFFFFFF) + _u32(3) + _u32(0xFFFFFFFF) + _u16(8) + bytes([0, 0x12]) + _u32(0)
    attrs = a1 + a2
    body = (_u32(1) + _u32(0xFFFFFFFF)   # line, comment
            + _u32(0xFFFFFFFF) + _u32(0)  # ns=-1, name=0 ('application')
            + _u16(20) + _u16(20) + _u16(2) + _u16(0) + _u16(0) + _u16(0)  # attrExt
            + attrs)
    se = _u16(0x0102) + _u16(16) + _u32(0) + body  # size patched below
    se = bytearray(se)
    _s.pack_into('<I', se, 4, len(se))
    se = bytes(se)
    ee = _u16(0x0103) + _u16(16) + _u32(24) + _u32(1) + _u32(0xFFFFFFFF) + _u32(0xFFFFFFFF)
    total = 8 + len(pool) + len(se) + len(ee)
    hdr = _u16(0x0003) + _u16(8) + _u32(total)
    return hdr + pool + se + ee


def _build_synthetic_axml_dual():
    """A minimal AXML: string pool + one <application> carrying BOTH launch
    attributes (android:name + android:appComponentFactory) whose classes live
    in a generic non-com namespace, plus an allowBackup sibling.
    Layout: file hdr | string pool | start elem (3 attrs) | end elem."""
    import struct as _s

    def _u16(v):
        return _s.pack('<H', v)

    def _u32(v):
        return _s.pack('<I', v)

    strings = ['application', 'name', 'x.y.z.Wrapper', 'allowBackup',
               'appComponentFactory', 'x.y.z.Factory']
    offsets = []
    data = b''
    for sstr in strings:
        enc = _u16(len(sstr)) + sstr.encode('utf-16-le') + b'\x00\x00'
        offsets.append(len(data))
        data += enc
    strings_start = 28 + 4 * len(strings)
    pool = (_u16(0x0001) + _u16(28) + _u32(0)  # csize patched below
            + _u32(len(strings)) + _u32(0) + _u32(0) + _u32(strings_start) + _u32(0)
            + b''.join(_u32(o) for o in offsets) + data)
    pool = bytearray(pool)
    _s.pack_into('<I', pool, 4, len(pool))
    pool = bytes(pool)
    # attrs: name="x.y.z.Wrapper" (idx 1/2), allowBackup (idx 3 raw=-1 data=0),
    # appComponentFactory="x.y.z.Factory" (idx 4/5)
    a1 = _u32(0xFFFFFFFF) + _u32(1) + _u32(2) + _u16(8) + bytes([0, 0x03]) + _u32(2)
    a2 = _u32(0xFFFFFFFF) + _u32(3) + _u32(0xFFFFFFFF) + _u16(8) + bytes([0, 0x12]) + _u32(0)
    a3 = _u32(0xFFFFFFFF) + _u32(4) + _u32(5) + _u16(8) + bytes([0, 0x03]) + _u32(5)
    attrs = a1 + a2 + a3
    body = (_u32(1) + _u32(0xFFFFFFFF)   # line, comment
            + _u32(0xFFFFFFFF) + _u32(0)  # ns=-1, name=0 ('application')
            + _u16(20) + _u16(20) + _u16(3) + _u16(0) + _u16(0) + _u16(0)  # attrExt
            + attrs)
    se = _u16(0x0102) + _u16(16) + _u32(0) + body  # size patched below
    se = bytearray(se)
    _s.pack_into('<I', se, 4, len(se))
    se = bytes(se)
    ee = _u16(0x0103) + _u16(16) + _u32(24) + _u32(1) + _u32(0xFFFFFFFF) + _u32(0xFFFFFFFF)
    total = 8 + len(pool) + len(se) + len(ee)
    hdr = _u16(0x0003) + _u16(8) + _u32(total)
    return hdr + pool + se + ee


def test_repair_pipeline():
    """The repair pipeline (r30): AXML surgery + the v2 sign round-trip +
    the dexclean classification on a synthetic DEX — all synthetic, zero-sample."""
    sys.path.insert(0, HERE)
    import repair
    import sign2
    import dexclean
    import io
    import zipfile as zf

    # --- A. the manifest surgery on a synthetic AXML
    axml = _build_synthetic_axml()
    surgery = repair.find_manifest_surgery(axml, None)
    assert surgery, 'surgery point not found in the synthetic AXML'
    assert len(surgery) == 1 and surgery[0][5] == 'com.stub.StubApp', surgery
    fixed = repair.apply_surgery(axml, surgery)
    from axmltool import Axml
    ax2 = Axml(fixed)
    app = [n for n in ax2.tree if n['name'] == 'application'][0]
    assert all(a['name'] != 'name' for a in app['attrs']), 'stub attr still present'
    assert any(a['name'] == 'allowBackup' for a in app['attrs']), 'sibling attr lost'
    print('repair pipeline OK: synthetic manifest surgery (stub attr removed, siblings kept)')

    # --- A2. prefix-agnostic wrapper detection + appComponentFactory + multi-removal.
    # A wrapper need not live in a com.* namespace, and packers also hijack
    # android:appComponentFactory (API 28+) — BOTH launch attributes must go
    # when their classes are absent from the shipped dex set.
    axml2 = _build_synthetic_axml_dual()
    surgery2 = repair.find_manifest_surgery(axml2, {'com.example.Real'})
    assert len(surgery2) == 2, surgery2
    assert {(h[4], h[5]) for h in surgery2} == {
        ('name', 'x.y.z.Wrapper'), ('appComponentFactory', 'x.y.z.Factory')}, surgery2
    fixed2 = repair.apply_surgery(axml2, surgery2)
    ax3 = Axml(fixed2)
    app2 = [n for n in ax3.tree if n['name'] == 'application'][0]
    assert all(a['name'] not in ('name', 'appComponentFactory')
               for a in app2['attrs']), 'wrapper attrs still present'
    assert any(a['name'] == 'allowBackup' for a in app2['attrs']), 'sibling attr lost'
    # negative control: classes that ARE shipped must never be touched
    surgery3 = repair.find_manifest_surgery(axml2, {'x.y.z.Wrapper', 'x.y.z.Factory'})
    assert surgery3 == [], surgery3
    print('repair pipeline OK: dual launch-attr surgery '
          '(name+appComponentFactory removed, shipped classes kept)')

    # --- B. the v2 sign round-trip on a synthetic zip
    buf = io.BytesIO()
    with zf.ZipFile(buf, 'w') as z:
        z.writestr('a.txt', 'hello')
    blob = buf.getvalue()
    key, cert = sign2.gen_key_cert()
    cert_der = cert.public_bytes(sign2.serialization.Encoding.DER)
    signed = sign2.sign_v2(blob, key, cert_der)
    # re-verify with an INDEPENDENT implementation (never trust the module's
    # own math — the r31 lesson: an ID/padding mismatch and a missing top-level
    # 0x5a prefix both survived self-verification because the verifier shared
    # the signer's assumptions). The verifier below is written from the SPEC:
    # chunk = SHA256(0xa5|u32le(len)|chunk); top = SHA256(0x5a|u32le(count)|...);
    # padding is selected BY ALGORITHM ID (0x0103 -> PKCS1v15, 0x0101 -> PSS).
    import struct as st
    import hashlib
    cd_off, eocd_off = sign2._find_cd(signed)
    magic_off = cd_off - 16
    assert signed[magic_off:cd_off] == sign2.MAGIC
    size = st.unpack_from('<Q', signed, magic_off - 8)[0]
    block_start = cd_off - size - 8
    region1 = signed[:block_start]
    region_cd = signed[cd_off:eocd_off]
    region_eocd = (signed[eocd_off:eocd_off + 16]
                   + st.pack('<I', block_start) + signed[eocd_off + 20:])
    def spec_chunks(b):
        cs = [b[i:i + 1048576] for i in range(0, len(b), 1048576)] or [b'']
        return [hashlib.sha256(b'\xa5' + st.pack('<I', len(c)) + c).digest() for c in cs]
    # THREE sections chunked independently (spec) — never merge CD with EOCD
    all_dg = spec_chunks(region1) + spec_chunks(region_cd) + spec_chunks(region_eocd)
    computed = hashlib.sha256(b'\x5a' + st.pack('<I', len(all_dg))
                              + b''.join(all_dg)).digest()
    # locate the claimed digest + verify
    pairs = {}
    p = block_start + 8
    while p < magic_off - 8:
        plen = st.unpack_from('<Q', signed, p)[0]
        pid = st.unpack_from('<I', signed, p + 8)[0]
        pairs[pid] = signed[p + 12:p + 8 + plen]
        p += 8 + plen
    v2 = pairs[sign2.V2_BLOCK_ID]
    def read_lp(b, pos):
        n = st.unpack_from('<I', b, pos)[0]
        return b[pos + 4:pos + 4 + n], pos + 4 + n
    signers_seq, _ = read_lp(v2, 0)
    signer, _ = read_lp(signers_seq, 0)
    sd, pos = read_lp(signer, 0)
    sigs_seq, pos = read_lp(signer, pos)
    pk, pos = read_lp(signer, pos)
    dg_seq, _ = read_lp(sd, 0)
    dg_rec, _ = read_lp(dg_seq, 0)
    alg_id = st.unpack_from('<I', dg_rec, 0)[0]
    assert alg_id == 0x0103, 'algorithm id must declare PKCS1v15 (got 0x%04x)' % alg_id
    claimed = dg_rec[8:40]
    assert claimed == computed, 'v2 digest mismatch'
    sig_rec, _ = read_lp(sigs_seq, 0)
    sig_alg_id = st.unpack_from('<I', sig_rec, 0)[0]
    assert sig_alg_id == alg_id, 'digest vs signature algorithm ids differ'
    sig = sig_rec[8:8 + st.unpack_from('<I', sig_rec, 4)[0]]
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as pad
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    # padding selected BY the declared ID — the way a real verifier does it
    sig_pad = {0x0103: pad.PKCS1v15, 0x0102: pad.PSS, 0x0101: pad.PSS}[sig_alg_id]()
    load_der_public_key(pk).verify(sig, sd, sig_pad, hashes.SHA256())
    # the zip still readable + the EOCD CD offset points past the block
    zz = zf.ZipFile(io.BytesIO(signed))
    assert zz.read('a.txt') == b'hello'
    assert st.unpack_from('<I', signed, eocd_off + 16)[0] == cd_off
    print('repair pipeline OK: v2 sign round-trip (digest+RSA verified, zip intact)')

    # --- C. the dexclean classification on a minimal synthetic DEX
    d_shell = _mk_dex('Lcom/stub/StubApp;')
    dx = dexclean.Dex(d_shell)
    keep, shell, foreign = dx.classify('', [])
    assert len(shell) == 1 and shell[0][1] == 'com.stub.StubApp', (keep, shell, foreign)
    d_app = _mk_dex('Lcom/example/MyApp;')
    dx2 = dexclean.Dex(d_app)
    k2, s2_, f2 = dx2.classify('com.example', [])
    assert len(k2) == 1 and len(s2_) == 0 and len(f2) == 0, (k2, s2_, f2)
    print('repair pipeline OK: dexclean classification (shell caught, app kept)')


def test_rc4mat():
    """rc4mat (r17 tool): material-space scan — synthetic 14B-header material ->
    parity-key derivation round-trip + planted scan hit via the CLI."""
    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location('crypto_recon', os.path.join(HERE, 'crypto_recon.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # synthetic material whose even-bit-parity keysrc yields the planted key
    key = bytes.fromhex('a5c39f1b7d2e')  # 6 bytes
    keysrc = bytearray()
    for kb in key:
        for k in range(8):
            keysrc.append(0x01 if (kb >> (7 - k)) & 1 else 0x00)
    mat = bytearray(0xe)
    struct.pack_into('<h', mat, 6, len(key))   # keylen
    struct.pack_into('<H', mat, 8, 0)          # flags = 0
    mat += bytearray(0x1e - 0xe)
    struct.pack_into('<h', mat, 0x1c, 24)     # shift > 8 -> off = 0 path
    mat += bytearray(0x36 - 0x1e)
    mat += keysrc                              # keysrc = payload + 0x28
    eff, got = mod.mat_parity_key(bytes(mat), 0, 64)
    assert got == key and eff == len(key), f'parity-key round-trip failed: {got and got.hex()}'
    print('crypto_recon rc4mat OK: synthetic material -> parity-key round-trip')
    # planted scan: carrier head = [4B declared length][zlib magic] XOR keystream(derived key)
    ks = mod.rc4_keystream(key, 6, 2, 3, 5, 1)   # battle variant params on the CLI
    head = bytearray(struct.pack('<I', 4096) + b'\x78\x9c')
    carrier = bytes(a ^ b for a, b in zip(head, ks))
    # hide the material in a PRNG ocean at a known offset
    ocean = bytearray()
    s = 0xfeed
    for _ in range(4096):
        s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 7
        s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
        ocean.append((s * 0x2545F4914F6CDD1D >> 56) & 0xFF)
    off = 777
    matsrc = bytes(ocean[:off]) + bytes(mat) + bytes(ocean[off:])
    with tempfile.TemporaryDirectory() as td:
        mf = os.path.join(td, 'matsrc.bin')
        cf = os.path.join(td, 'carrier.bin')
        open(mf, 'wb').write(matsrc)
        open(cf, 'wb').write(carrier)
        r = subprocess.run([sys.executable, os.path.join(HERE, 'crypto_recon.py'), 'rc4mat', mf,
                            '--carrier', cf, '--ct-off', '0',
                            '--stride', '2', '--seed-i', '3', '--seed-j', '5', '--j-add', '1'],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f'rc4mat exit {r.returncode}: {r.stderr}'
        assert 'mat 0x309' in r.stdout and '"hits":1' in r.stdout, r.stdout  # 777 = 0x309
        print('crypto_recon rc4mat OK: planted material found by the material-space scan')


def _mk_dex(class_desc):
    """Synthetic minimal DEX (1 type, 1 class): header + tables + map_list,
    with sums computed. Shared by the repair/dexdoctor anchors."""
    import struct as st2
    import hashlib as hl
    import zlib
    strings = [class_desc, '']
    hdr = bytearray(0x70)
    hdr[0:8] = b'dex\n035\x00'
    n_str = 2
    n_type = 1
    n_cls = 1
    str_ids_off = 0x70
    type_ids_off = str_ids_off + n_str * 4
    class_defs_off = type_ids_off + n_type * 4
    data_off = class_defs_off + n_cls * 32
    s0_off = data_off
    s1_off = s0_off + 1 + len(strings[0]) + 1
    str_blob = (bytes([len(strings[0])]) + strings[0].encode() + b'\x00' + b'\x00')
    cd = st2.pack('<IIIIIIII', 0, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0, 0)
    map_off = data_off + len(str_blob)
    entries = [(0x0000, 1, 0), (0x0001, n_str, str_ids_off), (0x0002, n_type, type_ids_off),
               (0x0006, n_cls, class_defs_off), (0x1000, 1, map_off)]
    map_list = st2.pack('<I', 5) + b''.join(st2.pack('<HHII', t, 0, c, o) for t, c, o in entries)
    out = bytearray(hdr)
    out += st2.pack('<I', s0_off)
    out += st2.pack('<I', s1_off)
    out += st2.pack('<I', 0)
    out += cd
    out += str_blob
    out += map_list
    st2.pack_into('<IIII', out, 56, n_str, str_ids_off, n_type, type_ids_off)
    st2.pack_into('<II', out, 96, n_cls, class_defs_off)
    st2.pack_into('<I', out, 52, map_off)
    st2.pack_into('<I', out, 32, len(out))
    st2.pack_into('<I', out, 36, 0x70)
    st2.pack_into('<I', out, 40, 0x12345678)  # endian tag
    out[12:32] = hl.sha1(bytes(out[32:])).digest()
    st2.pack_into('<I', out, 8, zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)
    return bytes(out)


def test_fidelity():
    """fidelity (r31): self-comparison verdict + injected-divergence detection."""
    import tempfile, os
    import fidelity
    healthy = _mk_dex('Lcom/example/MyApp;')
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, 'a.dex')
        q = os.path.join(td, 'b.dex')
        open(p, 'wb').write(healthy)
        open(q, 'wb').write(healthy)
        rep = fidelity.report(p, q)
        assert rep['verdict'] == 'IDENTICAL-CLASSSET'
        assert rep['bytes']['identical'] and rep['classes']['dump_only'] == []
        assert rep['members'].get('reliable'), 'synthetic 035 walk must be reliable'
        # divergence: a different app entirely
        other = _mk_dex('Lcom/other/Thing;')
        open(q, 'wb').write(other)
        rep2 = fidelity.report(p, q)
        assert rep2['verdict'] == 'DIVERGENT'
    print('fidelity OK: self-compare IDENTICAL-CLASSSET, foreign dex DIVERGENT')


def test_dexdoctor():
    """dexdoctor (r31): triage + first-aid for wounded dumps. Each planted
    pathology must heal back to the EXACT original bytes (the golden test)."""
    import struct as st
    import dexdoctor
    healthy = _mk_dex('Lcom/example/MyApp;')
    t0 = dexdoctor.Triage(healthy).diagnose()
    assert not t0.issues, 'healthy synthetic triaged as wounded: %s' % t0.issues

    # wound A: shell-zeroed sums + trashed file_size
    wa = bytearray(healthy)
    wa[12:32] = b'\x00' * 20
    st.pack_into('<I', wa, 8, 0)
    st.pack_into('<I', wa, 32, 0)
    # wound B: map_off wiped (the anti-static-parse sabotage) + sums zeroed
    wb = bytearray(healthy)
    st.pack_into('<I', wb, 52, 0)
    wb[12:32] = b'\x00' * 20
    # wound C: page-aligned dump with trailing zero padding
    pad = (4096 - len(healthy) % 4096) or 4096
    wc = bytearray(healthy) + b'\x00' * pad
    # wound D: whole-memory dump carrying the shell's runtime workspace
    # (high-entropy crypto material) past the map_list
    wd = bytearray(healthy) + bytes(range(256)) * 100
    # wound E: repack toolchain bug — one map section split into two entries
    # (ART rejects the whole DEX with "Duplicate map section")
    we = bytearray(healthy)
    mo = st.unpack_from('<I', we, 52)[0]
    items = [list(st.unpack_from('<HHII', we, mo + 4 + k * 12)) for k in range(st.unpack_from('<I', we, mo)[0])]
    split = []
    for it in items:
        if it[0] == 0x0001 and it[2] == 2:  # string_ids (fixed-size): split in half
            split.append([0x0001, 0, 1, it[3]])
            split.append([0x0001, 0, 1, it[3] + 4])
        else:
            split.append(list(it))
    split.sort(key=lambda x: x[3])
    new_map = st.pack('<I', len(split)) + b''.join(st.pack('<HHII', t, u, c, o) for t, u, c, o in split)
    del we[mo:]
    we += new_map
    st.pack_into('<I', we, 32, len(we))  # file_size grows by the extra entry
    for name, wound in (('A sums+file_size', wa), ('B map_off', wb), ('C padding', wc),
                       ('D shell workspace', wd), ('E duplicate map section', we)):
        t = dexdoctor.Triage(bytes(wound)).diagnose()
        assert t.issues, 'wound %s not detected' % name
        healed = t.fix()
        assert healed == healthy, 'wound %s healed imperfectly (bytes differ)' % name
        post = dexdoctor.Triage(healed).diagnose()
        assert not post.issues, 'wound %s leaves residual: %s' % (name, post.issues)
    print('dexdoctor OK: 5 planted pathologies detected + healed to exact original bytes')


if __name__ == '__main__':
    test_so_emulator()
    test_rc4_vector()
    test_recon_smoke()
    test_disasm()
    test_sigx()
    test_sm4recon()
    test_elfrecon()
    test_repair_pipeline()
    test_dexdoctor()
    test_fidelity()
    test_rc4mat()
    print('trackb selftest: ALL GREEN')
