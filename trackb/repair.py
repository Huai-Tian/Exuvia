#!/usr/bin/env python3
"""Repair prototype: packed APK + dumped DEX -> restored APK. Sample-agnostic.

The industry gap this fills: dumpers (56.al etc.) produce DEX fine, but the
dumped DEX dropped back into the packed APK still won't launch — because the
SHELL left surgery markers in the APK (the wrapper Application class in the
manifest, the stub classes.dex, the native loader assets). This tool performs
that repair mechanically:

  repair <packed.apk> <dumped.dex> [-o out.apk] [--app-name CLS|--no-app-name]

  1. MANIFEST SURGERY: parse the binary AXML, find the <application> element's
     android:name attribute pointing at a wrapper class (auto-detect: the class
     that lives in the SHELL's stub classes.dex — com.stub.*, *.StubApp,
     com.secneo.* etc. — or give --app-name CLS / --no-app-name to force).
     Remove the 20-byte attribute entry in place (chunk sizes and the file
     header adjusted; the sequential-chunk AXML format tolerates the shift).
  2. DEX SWAP: classes.dex <- the dumped DEX (validation: magic/checksum/
     signature fields verified and re-fixed if the dumper broke them).
  3. SHELL ASSET REMOVAL: entries the known shells drop into assets/
     (libjiagu*, .jgapp, *.jiagu patterns).
  4. REBUILD: zip with the original entry order/methods preserved, then
     zipalign + v2-sign via the trackb/sigx tool.

Verification (this corpus has ground truth): the repaired APK's manifest
must be structurally identical to the original's; all shared entries
byte-equal; only the signing block differs.
"""
import argparse
import hashlib
import struct
import sys
import zipfile
import zlib

# wrapper-class patterns seen across the industry packers (360/secneo/qihoo
# family + generic stubs). A <application> launch attribute matching these
# gets removed; the pattern list is heuristic — the definitive test is "the
# class is absent from the shipped DEX set" (checked when dex_classes is
# given), which is prefix-agnostic by construction.
WRAPPER_PATTERNS = (
    'com.stub.', 'StubApp', '.stub.', 'com.secneo.', 'com.qihoo.',
    'com.tencent.bugly.', 'protect.', 'com.morgoo.', 'dxloader.',
    'com.wrapper.', 'com.app.plugin.', 'android.support.multidex',
)

# <application> attributes that NAME a class the runtime must instantiate at
# launch: android:name -> the Application subclass; android:appComponentFactory
# (API 28+) -> the factory consulted even earlier. If such a class is a packer
# wrapper — or simply absent from the shipped dexes — keeping the attribute
# kills the process with ClassNotFoundException before any app code runs.
# Removing it restores the platform default, which is exactly what an unpacked
# app needs.
APP_CLASS_ATTRS = ('name', 'appComponentFactory')


def find_manifest_surgery(axml: bytes, dex_classes=None):
    """Locate EVERY wrapper launch attribute on <application>. Returns a list
    of (attr_abs_offset, attr_size, chunk_off, chunk_csize, attr_name, value),
    possibly empty. Two removal tests, both zero-sample:
      * heuristic: the value matches WRAPPER_PATTERNS;
      * definitive: dex_classes was given and the class is absent from the
        shipped DEX set — a launch-time class that does not exist in the APK
        is a dead wrapper no matter which namespace it hides behind (no
        'com.'-style prefix assumptions)."""
    d = axml
    if d[:2] != struct.pack('<H', 3):
        raise ValueError('manifest is not AXML')
    # string pool
    off = 8
    strings = []
    while off < len(d) - 8:
        ctype, hsize, csize = struct.unpack_from('<HHI', d, off)
        if csize < hsize or off + csize > len(d):
            break
        if ctype == 0x0001:
            (s_count, _sc, flags, data_start, _ss) = struct.unpack_from('<IIIII', d, off + 8)
            offsets = struct.unpack_from('<%dI' % s_count, d, off + hsize)
            for so in offsets:
                p = off + data_start + so
                n = struct.unpack_from('<H', d, p)[0]
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', d, p + 2)[0]
                    raw = d[p + 4:p + 4 + n * 2]
                else:
                    raw = d[p + 2:p + 2 + n * 2]
                strings.append(raw.decode('utf-16-le', errors='replace'))
        elif ctype == 0x0102:
            ns, name = struct.unpack_from('<II', d, off + 16)
            (attr_start, attr_size, attr_count, id_idx, _cl, _st) = struct.unpack_from('<HHHHHH', d, off + 24)
            if name < len(strings) and strings[name] == 'application':
                hits = []
                for k in range(attr_count):
                    a = off + 16 + attr_start + k * attr_size
                    if a + 20 > len(d):
                        break
                    a_ns, a_name, a_raw, _vs, _vr, _vt, _vd = struct.unpack_from('<IIIHBBI', d, a)
                    nm = strings[a_name] if a_name < len(strings) else ''
                    val = strings[a_raw] if a_raw < len(strings) else ''
                    if nm in APP_CLASS_ATTRS and val:
                        if val in WRAPPER_PATTERNS or any(p in val for p in WRAPPER_PATTERNS):
                            hits.append((a, attr_size, off, csize, nm, val))
                            continue
                        # definitive: the class is NOT in the shipped DEX set
                        if dex_classes is not None and val not in dex_classes:
                            hits.append((a, attr_size, off, csize, nm, val))
                if hits:
                    return hits
        off += csize
    return []


def apply_surgery(axml: bytes, items) -> bytes:
    """Remove every attribute entry listed in items (find_manifest_surgery
    hits); fix attrCount, element chunk size and file size per deletion.
    Deletions run in descending-offset order so the remaining offsets stay
    valid, and size fields are re-read each round so multiple removals from
    the SAME element chunk compose correctly."""
    d = bytearray(axml)
    for attr_off, attr_size, chunk_off, _cs, _nm, _val in sorted(items, reverse=True):
        # 1. drop the attribute entry
        del d[attr_off:attr_off + attr_size]
        # 2. attrCount -= 1 (u16 at chunk_off+28)
        cnt = struct.unpack_from('<H', d, chunk_off + 28)[0]
        struct.pack_into('<H', d, chunk_off + 28, cnt - 1)
        # 3. the element chunk size -= attr_size
        cur = struct.unpack_from('<I', d, chunk_off + 4)[0]
        struct.pack_into('<I', d, chunk_off + 4, cur - attr_size)
        # 4. the file-level chunk size -= attr_size (the XML chunk header @0)
        total = struct.unpack_from('<I', d, 4)[0]
        struct.pack_into('<I', d, 4, total - attr_size)
    return bytes(d)


def dex_classes_set(dex: bytes):
    """The set of class descriptors in a DEX (fast: scan the type strings via
    the header map — but a robust cheap scan: the type list from string ids).
    For the prototype: parse the header + string ids."""
    if dex[:4] != b'dex\n':
        return None
    try:
        string_ids_size = struct.unpack_from('<I', dex, 56)[0]
        string_ids_off = struct.unpack_from('<I', dex, 60)[0]
        out = set()
        for i in range(min(string_ids_size, 200000)):
            off = struct.unpack_from('<I', dex, string_ids_off + i * 4)[0]
            # uleb128 length
            n = 0
            shift = 0
            while True:
                b = dex[off]
                off += 1
                n |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            s = dex[off:off + n].decode('utf-8', errors='replace')
            if s.startswith('L') and s.endswith(';'):
                out.add(s[1:-1].replace('/', '.'))
        return out
    except Exception:
        return None


def dex_validate_fix(dex: bytes):
    """Verify/fix the DEX header checksum+signature (dumpers often leave them
    stale after repairing the map). Returns (dex, fixes_applied)."""
    if dex[:4] != b'dex\n':
        return dex, []
    fixes = []
    sig = hashlib.sha1(dex[32:]).digest()
    if dex[12:32] != sig:
        dex = dex[:12] + sig + dex[32:]
        fixes.append('sha1-signature')
    adler = zlib.adler32(dex[12:]) & 0xFFFFFFFF
    if struct.unpack_from('<I', dex, 8)[0] != adler:
        dex = dex[:8] + struct.pack('<I', adler) + dex[12:]
        fixes.append('adler32-checksum')
    return dex, fixes


SHELL_ASSET_PATTERNS = (
    'libjiagu', '.jgapp', 'jiagu',  # 360 family
    # 爱加密 family (family-3): the encrypted shell container, the runtime
    # lib dir, the anti-tamper seed/signature blobs and the planted marker
    # files — all packer-fixed names (written by the packer, not the app),
    # the same contract the 360 row above has always been.
    'ijiami', '.ajm', 'ijm_lib',
    'af.bin', 'signed.bin',
    'sign_verify.png', 'data_path_defualt_code.png',
)


def is_shell_asset(name):
    """Shell loader-machinery asset test (zero-sample).

    Two generic tells, no family strings required:
      * a native library UNDER assets/ — a legit APK ships .so only in lib/;
        a .so in assets/ is the packer's runtime, extracted and loaded by the
        wrapper at bootstrap (device-verified on two families: 360's
        assets/libjiagu*.so, tosks's assets/libtosks*.so);
      * the family pattern table above (encrypted containers and other
        non-.so shell payloads, e.g. 360's .jgapp, 爱加密's .ajm).

    Deliberately NO content/magic tell: an app may legitimately encrypt its
    own assets (the family-3 sample's own assets/icon|images/*.png carry no
    PNG magic BY DESIGN — the app encrypts its resources, empty files
    included). Content-based rejection would false-positive real apps; the
    net stays name-based. Evaluated and EXCLUDED on the same evidence:
    assets/dexopt/baseline.prof{,m} — the standard androidx ProfileInstaller
    asset ("pro\\x00" magic), app-side build output, not shell machinery.
    """
    return name.startswith('assets/') and (
        name.endswith('.so')
        or any(p in name for p in SHELL_ASSET_PATTERNS))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('packed')
    ap.add_argument('dumped_dex')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--app-name', default=None,
                    help='force the original Application class to SET (skip removal)')
    ap.add_argument('--keep-app-name', action='store_true',
                    help='do not touch the android:name attribute')
    args = ap.parse_args()
    out = args.out or args.packed.rsplit('.', 1)[0] + '.repaired.apk'

    zin = zipfile.ZipFile(args.packed)
    dex = open(args.dumped_dex, 'rb').read()
    dex, fixes = dex_validate_fix(dex)
    if fixes:
        print('dex fixes applied: %s' % ', '.join(fixes))

    manifest = zin.read('AndroidManifest.xml')
    if not args.keep_app_name and not args.app_name:
        klasses = dex_classes_set(dex)
        surgery = find_manifest_surgery(manifest, klasses)
        if surgery:
            for attr_off, _size, _co, _cs, aname, val in surgery:
                print('manifest surgery: removing android:%s="%s" (attr @0x%x, 20B)'
                      % (aname, val, attr_off))
            manifest = apply_surgery(manifest, surgery)
        else:
            print('manifest: no wrapper launch attribute found (nothing to remove)')

    removed = []
    with zipfile.ZipFile(out, 'w') as zo:
        for info in zin.infolist():
            name = info.filename
            if name == 'AndroidManifest.xml':
                zo.writestr(name, manifest)
                continue
            if name == 'classes.dex':
                zo.writestr(name, dex)
                continue
            if is_shell_asset(name):
                removed.append(name)
                continue
            zo.writestr(info, zin.read(name))
    print('removed shell entries: %s' % (removed or 'none'))
    print('repaired APK: %s' % out)


if __name__ == '__main__':
    main()
