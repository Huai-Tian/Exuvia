#!/usr/bin/env python3
"""dexclean.py — dumped-DEX cleaner (repair pipeline's first stage). Sample-agnostic.

Runtime dumpers (FART/frida-dexdump/56.al-style services) catch in-memory DEX
that often carries IMPURITIES: classes from other apps loaded in the same
process, framework fragments, or the shell's own stub classes. Dropping such a
DEX back into the APK produces an app that either fails verification or
misbehaves. This tool:

  1. PARSES the DEX fully (header / string_ids / type_ids / class_defs).
  2. CLASSIFIES every class: KEEP (the app's own package + the manifest's
     components + the well-known library namespaces) / SHELL (the wrapper
     stubs — must go) / FOREIGN (other-app or system classes — junk).
  3. CROSS-REFERENCES the packed APK's manifest: every declared component
     (activity/service/provider/receiver) must be present in the KEEP set —
     a missing component = a red flag reported loudly.
  4. CLEANS (default): drops the SHELL + FOREIGN class_def entries from the
     class_defs array (the DEX stays structurally valid — dead data left in
     the data section is harmless), fixes the map_list entry + header
     checksum + sha1 signature. --report prints without touching.

Usage:
  dexclean.py <dumped.dex> [--apk packed.apk] [--report] [-o out.dex]
"""
import argparse
import hashlib
import struct
import sys
import zlib

# well-known third-party/library namespaces an app legitimately bundles
LIB_PREFIXES = (
    'androidx.', 'com.google.android.material.', 'kotlin.', 'kotlinx.',
    'org.intellij.lang.', 'org.jetbrains.annotations.', 'javax.annotation.',
    'org.slf4j.', 'com.google.protobuf.', 'okhttp3.', 'okio.', 'retrofit2.',
    'io.reactivex.', 'org.reactivestreams.', 'com.squareup.', 'org.json.',
    'android.support.', 'com.android.', 'dalvik.', 'libcore.', 'java.', 'javax.',
)
# shell wrapper stubs seen across the industry (the repair must remove them)
SHELL_PREFIXES = (
    'com.stub.', 'com.secneo.', 'com.qihoo.', 'com.morgoo.', 'dxloader.',
    'protect.', 'com.wrapper.', 'com.app.plugin.', 'com.epoint.', 'cn.security.',
)


def uleb128(d, p):
    r = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            return r, p


class Dex:
    def __init__(self, data: bytes):
        self.d = bytearray(data)
        if self.d[:4] != b'dex\n':
            raise ValueError('not a DEX')
        self.parse_header()

    def parse_header(self):
        d = self.d
        (self.file_size, self.header_size, self.endian, self.link_size, self.link_off,
         self.map_off) = struct.unpack_from('<IIIIII', d, 32)
        (self.string_ids_size, self.string_ids_off, self.type_ids_size,
         self.type_ids_off) = struct.unpack_from('<IIII', d, 56)
        (self.proto_ids_size, self.proto_ids_off, self.field_ids_size,
         self.field_ids_off) = struct.unpack_from('<IIII', d, 72)
        (self.method_ids_size, self.method_ids_off, self.class_defs_size,
         self.class_defs_off, self.data_size, self.data_off) = struct.unpack_from('<IIIIII', d, 88)
        self._tlw = self._detect_type_list_width()

    def _detect_type_list_width(self):
        """type_list entries are u32 per the classic 035 spec, but the 039
        (min-api 29) toolchain emits compact u16 lists. Detect STRUCTURALLY
        (never by version table): boundary-walk the map-declared 0x1001
        region — the correct width tiles it exactly, the wrong one dies
        early or overruns. Fallback 4 (the classic spec)."""
        mo = self.map_off
        if not mo or mo + 4 > len(self.d):
            return 4
        n = struct.unpack_from('<I', self.d, mo)[0]
        items = [struct.unpack_from('<HHII', self.d, mo + 4 + k * 12) for k in range(n)]
        items.sort(key=lambda x: x[3])
        start = end = None
        for i, it in enumerate(items):
            if it[0] == 0x1001:
                start = it[3]
                end = items[i + 1][3] if i + 1 < len(items) else len(self.d)
                break
        if start is None or end is None or end <= start:
            return 4
        for w in (4, 2):
            p, ok = start, True
            while p < end:
                size = struct.unpack_from('<I', self.d, p)[0]
                if size > 1000 or p + 4 + size * w > end + 4:
                    ok = False
                    break
                p = (p + 4 + size * w + 3) & ~3
            # exact tile OR a final padding overhang of <=4 bytes (memory-
            # layout dexes place sections at NON-4-aligned offsets)
            if ok and end <= p <= end + 4:
                return w
        return 4

    def _read_type_list(self, off):
        """type_idx entries at the DETECTED width (see _detect_type_list_width)."""
        if not off:
            return []
        n = struct.unpack_from('<I', self.d, off)[0]
        w = self._tlw
        if w == 2:
            return list(struct.unpack_from('<%dH' % n, self.d, off + 4)) if n else []
        return list(struct.unpack_from('<%dI' % n, self.d, off + 4)) if n else []

    def strings(self):
        """All string_ids as decoded strings (MUTF-8 approximated as utf-8)."""
        out = []
        for i in range(self.string_ids_size):
            off = struct.unpack_from('<I', self.d, self.string_ids_off + i * 4)[0]
            _, p = uleb128(self.d, off)
            end = self.d.index(0, p)
            out.append(bytes(self.d[p:end]).decode('utf-8', errors='replace'))
        return out

    def type_name(self, idx, strs):
        t = struct.unpack_from('<I', self.d, self.type_ids_off + idx * 4)[0]
        s = strs[t]  # 'Lcom/foo/Bar;'
        return s[1:-1].replace('/', '.')

    def class_defs(self):
        """[(class_idx, name, offset_of_the_32B_def)]"""
        strs = self.strings()
        out = []
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            class_idx = struct.unpack_from('<I', self.d, off)[0]
            out.append((class_idx, self.type_name(class_idx, strs), off))
        return out

    def reference_edges(self):
        """class_idx -> set(class_idx) edges via superclasses, interfaces,
        field types, and method signatures (the encoded class_data arrays)."""
        edges = {}
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            class_idx, _access, super_idx, ifaces_off, _src, _ann, class_data_off, _sv = \
                struct.unpack_from('<IIIIIIII', self.d, off)
            out = set()
            if super_idx != 0xFFFFFFFF:
                out.add(super_idx)
            for t in self._read_type_list(ifaces_off):
                out.add(t)
            if class_data_off:
                p = class_data_off
                nsf, p = uleb128(self.d, p)
                nif, p = uleb128(self.d, p)
                ndm, p = uleb128(self.d, p)
                nvm, p = uleb128(self.d, p)
                # fields: (idx_delta, access) ulebs — type via field_ids
                fid = 0
                for _ in range(nsf + nif):
                    d_idx, p = uleb128(self.d, p)
                    _acc, p = uleb128(self.d, p)
                    fid += d_idx
                    if fid < self.field_ids_size:
                        t = struct.unpack_from('<H', self.d, self.field_ids_off + fid * 8 + 2)[0]
                        out.add(t)
                mid = 0
                for _ in range(ndm + nvm):
                    d_idx, p = uleb128(self.d, p)
                    _acc, p = uleb128(self.d, p)
                    _code, p = uleb128(self.d, p)
                    mid += d_idx
                    if mid < self.method_ids_size:
                        m = self.method_ids_off + mid * 8
                        # proto -> return + params
                        proto_idx = struct.unpack_from('<H', self.d, m + 2)[0]
                        pr = self.proto_ids_off + proto_idx * 12
                        out.add(struct.unpack_from('<I', self.d, pr + 4)[0])  # return type
                        poff = struct.unpack_from('<I', self.d, pr + 8)[0]
                        for t in self._read_type_list(poff):
                            out.add(t)
            edges[class_idx] = {t for t in out if t != class_idx and t < self.type_ids_size}
        return edges

    def classify(self, app_pkg: str, manifest_classes=None):
        """Reachability classification: roots = the manifest components + the
        app package; KEEP = anything the reference graph connects to the
        roots (obfuscated 1-3-char classes reachable from the app ARE the app —
        the name heuristic alone would murder them); FOREIGN = unreachable."""
        keep, shell, foreign = [], [], []
        mc = set(manifest_classes or [])
        # root class indices
        roots = set()
        for i, (idx, name, off) in enumerate(self.class_defs()):
            if name == app_pkg or name.startswith(app_pkg + '.'):
                roots.add(idx)
            elif name in mc:
                roots.add(idx)
        # BFS over the reference edges
        edges = self.reference_edges()
        seen = set(roots)
        queue = list(roots)
        while queue:
            c = queue.pop()
            for t in edges.get(c, ()):
                if t not in seen:
                    seen.add(t)
                    queue.append(t)
        for i, (idx, name, off) in enumerate(self.class_defs()):
            if any(name.startswith(p) for p in SHELL_PREFIXES):
                shell.append((i, name, off))
                continue
            segs = name.split('.')
            obfuscated = (len(segs) <= 2 and all(len(s) <= 3 for s in segs))
            # R8 inner classes: es0$a / op0$b — a '$' in a short segment
            obfuscated = obfuscated or any('$' in s and len(s.split('$')[0]) <= 3
                                           and all(len(p) <= 3 for p in s.split('$'))
                                           for s in segs)
            looks_lib = (any(name.startswith(p) for p in LIB_PREFIXES)
                         or name.startswith('android.'))
            if idx in seen or looks_lib or obfuscated:
                keep.append((i, name, off))
            else:
                foreign.append((i, name, off))
        return keep, shell, foreign

    def clean(self, drop_indices):
        """Drop the class_defs entries (by INDEX), fix map+header, refix sums."""
        keep_bytes = b''
        dropped = set(drop_indices)
        survivors = []
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            if i in dropped:
                continue
            keep_bytes += self.d[off:off + 32]
            survivors.append(i)
        # rewrite the class_defs array in place (survivors are contiguous)
        self.d[self.class_defs_off:self.class_defs_off + len(keep_bytes)] = keep_bytes
        n = len(survivors)
        struct.pack_into('<I', self.d, 96, n)  # header class_defs_size
        self.class_defs_size = n
        # map_list: find the TYPE_CLASS_DEF_ITEM(0x0006) entry, fix the size
        mo = self.map_off
        n_entries = struct.unpack_from('<I', self.d, mo)[0]
        for k in range(n_entries):
            e = mo + 4 + k * 12
            t, unused, cnt = struct.unpack_from('<HHI', self.d, e)
            if t == 0x0006:
                struct.pack_into('<I', self.d, e + 4, n)
                break
        # file_size stays (dead data remains); refix sha1 + adler
        self.d[12:32] = hashlib.sha1(self.d[32:]).digest()
        adler = zlib.adler32(self.d[12:]) & 0xFFFFFFFF
        struct.pack_into('<I', self.d, 8, adler)
        return bytes(self.d)

    def validate(self, names):
        """Sanity: the header sums are consistent with the content."""
        adler = zlib.adler32(self.d[12:]) & 0xFFFFFFFF
        sig_ok = self.d[12:32] == hashlib.sha1(self.d[32:]).digest()
        return {
            'adler_ok': struct.unpack_from('<I', self.d, 8)[0] == adler,
            'sha1_ok': sig_ok,
            'class_count': self.class_defs_size,
            'file_size_ok': self.file_size == len(self.d),
            'sample': names[:3],
        }


def manifest_classes_from_apk(apk_path):
    """Extract the component class names from a packed APK's manifest
    (via the sibling axmltool module)."""
    import zipfile
    import os
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from axmltool import Axml
    except ImportError:
        return [], None
    try:
        z = zipfile.ZipFile(apk_path)
        ax = Axml(z.read('AndroidManifest.xml'))
        pkg = None
        comps = []
        def walk(nodes):
            nonlocal pkg
            for n in nodes:
                if n['name'] == 'manifest':
                    for a in n['attrs']:
                        if a['name'] == 'package':
                            pkg = a['raw']
                if n['name'] in ('activity', 'service', 'provider', 'receiver', 'application'):
                    for a in n['attrs']:
                        if a['name'] == 'name' and a['raw'] and a['raw'] != 'com.stub.StubApp':
                            v = a['raw']
                            if not v.startswith(pkg or '\x00') and pkg:
                                v = pkg + v if v.startswith('.') else v
                            comps.append(v)
                walk(n['children'])
        walk(ax.tree)
        return comps, pkg
    except Exception as e:
        return [], None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('dex')
    ap.add_argument('--apk', help='the packed APK (for the manifest cross-reference)')
    ap.add_argument('--report', action='store_true', help='print only; do not write')
    ap.add_argument('-o', '--out', help='cleaned DEX output path')
    args = ap.parse_args()

    data = open(args.dex, 'rb').read()
    dex = Dex(data)
    comps, pkg = ([], None)
    if args.apk:
        comps, pkg = manifest_classes_from_apk(args.apk)
    print('app package: %s | manifest components: %d' % (pkg, len(comps)))
    keep, shell, foreign = dex.classify(pkg or '', comps)
    print('classes total=%d  keep=%d  shell=%d  foreign=%d'
          % (dex.class_defs_size, len(keep), len(shell), len(foreign)))
    if shell:
        print('SHELL classes (removed):')
        for _, n, _ in shell[:20]:
            print('  -', n)
    if foreign:
        top = {}
        for _, n, _ in foreign:
            top[n.split('.')[0] + '.' + (n.split('.')[1] if n.count('.') > 1 else '')] = top.get(
                n.split('.')[0] + '.' + (n.split('.')[1] if n.count('.') > 1 else ''), 0) + 1
        print('FOREIGN top namespaces:')
        for k, v in sorted(top.items(), key=lambda x: -x[1])[:15]:
            print('  ?', k, '×%d' % v)
    missing = [c for c in comps if c not in {n for _, n, _ in keep}]
    if missing:
        print('WARNING — manifest components MISSING from the keep set:')
        for m in missing:
            print('  !', m)

    if args.report:
        return
    out = args.out or args.dex.rsplit('.', 1)[0] + '.clean.dex'
    if shell or foreign:
        drops = [i for i, _, _ in shell] + [i for i, _, _ in foreign]
        cleaned = dex.clean(drops)
        open(out, 'wb').write(cleaned)
        print('cleaned DEX: %s (%d classes removed)' % (out, len(drops)))
        # re-validate
        d2 = Dex(cleaned)
        print('re-validate:', d2.validate([n for _, n, _ in keep]))
    else:
        # pipeline contract: ALWAYS produce the output
        open(out, 'wb').write(data)
        print('already pure — copied verbatim: %s' % out)


if __name__ == '__main__':
    main()
