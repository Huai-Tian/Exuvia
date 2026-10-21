#!/usr/bin/env python3
"""dexdoctor.py — triage & first-aid for third-party dumped DEX files.

Runtime dumpers (FART / frida-dexdump / 56.al-style services) copy DEX straight
out of process memory. The dump's header is whatever the SHELL left there at
that moment, and shells are known to sabotage exactly the fields a static
parser needs (checksum, map_off, file_size). So a dumped DEX often arrives
structurally wounded before any cleaning can even start. dexdoctor is the
triage station at the pipeline's front door:

  PATHOLOGY CATALOG (industry-known dump diseases):
    P1 checksum/signature invalid  — shell trashed them / dumper never fixed
    P2 file_size mismatch          — page-dumped (trailing padding) or truncated
    P3 map_off dead (=0 / OOB)     — shell wiped it to kill static parsers
    P4 magic version anomaly       — dex\n036\\0..039\\0 variants
    P5 endian/header_size anomaly  — hostile corruption or wrong-arch dump
    P6 header tables vs map_list disagreement — partial sabotage

  REPAIR (validated against synthetic wounds; --fix writes, default reports):
    P1 -> recompute sha1+adler32          P2 -> file_size := actual length
    P3 -> map_list signature scan (TYPE_HEADER_ITEM sentinel + sorted-offset
          invariant + cross-check against surviving header tables)
    P5 -> endian/header_size restored to spec constants

Usage:
  dexdoctor.py dumped.dex [-o out.dex] [--fix] [--json]
  dexdoctor.py dump_dir/            # triage every *.dex in a directory
"""
import argparse
import hashlib
import json
import struct
import sys
import zlib

HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
MAGIC = b'dex\n'
KNOWN_VERSIONS = (b'035\x00', b'036\x00', b'037\x00', b'038\x00', b'039\x00')

# map_list item types (DEX spec)
TYPE_HEADER = 0x0000
TYPE_STRING_ID = 0x0001
TYPE_TYPE_ID = 0x0002
TYPE_PROTO_ID = 0x0003
TYPE_FIELD_ID = 0x0004
TYPE_METHOD_ID = 0x0005
TYPE_CLASS_DEF = 0x0006
TYPE_MAP_LIST = 0x1000


class Triage:
    """One dumped DEX -> structured report (+ optional repair)."""

    def __init__(self, data: bytes, name='dumped.dex'):
        self.raw = data
        self.name = name
        self.issues = []
        self.fixes = []
        self.fixed = None
        self.meta = {}

    # ---------- diagnosis ----------
    def diagnose(self):
        self.issues = []  # idempotent: safe to call twice
        d = self.raw
        n = len(d)
        # P0: too short to even hold a header
        if n < HEADER_SIZE or d[:4] != MAGIC:
            self.issues.append('P0 not-a-dex (magic/size)')
            return self
        ver = bytes(d[4:8])
        if ver not in KNOWN_VERSIONS:
            self.issues.append('P4 magic version %r' % ver)
        endian = struct.unpack_from('<I', d, 40)[0]
        hs = struct.unpack_from('<I', d, 36)[0]
        if endian != ENDIAN_TAG:
            self.issues.append('P5 endian tag %08x' % endian)
        if hs != HEADER_SIZE:
            self.issues.append('P5 header_size %d' % hs)
        (file_size,) = struct.unpack_from('<I', d, 32)
        (map_off,) = struct.unpack_from('<I', d, 52)
        if file_size != n:
            self.issues.append('P2 file_size %d != actual %d' % (file_size, n))
        # checksum / signature
        adler = struct.unpack_from('<I', d, 8)[0]
        want_adler = zlib.adler32(d[12:]) & 0xFFFFFFFF
        sig = d[12:32]
        want_sig = hashlib.sha1(d[32:]).digest()
        if adler != want_adler:
            self.issues.append('P1 adler32 mismatch (header %08x, content %08x)' % (adler, want_adler))
        if sig != want_sig:
            self.issues.append('P1 sha1 signature mismatch')
        # map_off sanity
        map_ok = False
        if HEADER_SIZE <= map_off < n - 4:
            cnt = struct.unpack_from('<I', d, map_off)[0]
            if 1 <= cnt <= 128 and map_off + 4 + cnt * 12 <= n:
                map_ok = True  # P3 not present (basic bounds pass)
            else:
                self.issues.append('P3 map_off bounds fail (%d entries)' % cnt)
        else:
            self.issues.append('P3 map_off dead (%d)' % map_off)
        if map_ok:
            self.meta['map_entries'] = self._map_list(d, map_off)
            self._crosscheck_tables(d)
        self.meta.update({'file_size_field': file_size, 'actual_size': n, 'map_off': map_off,
                          'version': ver.decode('latin1')})
        return self

    def _map_list(self, d, map_off):
        cnt = struct.unpack_from('<I', d, map_off)[0]
        out = {}
        for i in range(cnt):
            t, _, c, off = struct.unpack_from('<HHII', d, map_off + 4 + i * 12)
            out.setdefault(t, (c, off))
        return out

    def _crosscheck_tables(self, d):
        """P6: header table offsets/sizes must agree with the map_list."""
        m = self.meta.get('map_entries', {})
        pairs = [(TYPE_STRING_ID, 56, 60), (TYPE_TYPE_ID, 64, 68), (TYPE_PROTO_ID, 72, 76),
                 (TYPE_FIELD_ID, 80, 84), (TYPE_METHOD_ID, 88, 92), (TYPE_CLASS_DEF, 96, 100)]
        for t, size_field, off_field in pairs:
            if t not in m:
                continue
            cnt, off = m[t]
            hsz = struct.unpack_from('<I', d, size_field)[0]
            hoff = struct.unpack_from('<I', d, off_field)[0]
            if hsz != cnt or hoff != off:
                self.issues.append('P6 table %04x: header(%d@%d) != map(%d@%d)' % (t, hsz, hoff, cnt, off))

    # ---------- repair ----------
    def fix(self):
        """Apply all repairs. Returns the fixed bytes (also cached in .fixed)."""
        if self.fixed is not None:
            return self.fixed
        self.diagnose()
        d = bytearray(self.raw)
        n = len(d)
        if d[:4] != MAGIC or n < HEADER_SIZE:
            self.fixed = bytes(d)  # nothing we can do
            return self.fixed
        for code in list(self.issues):
            if code.startswith('P5'):
                if 'endian' in code:
                    struct.pack_into('<I', d, 40, ENDIAN_TAG)
                elif 'header_size' in code:
                    struct.pack_into('<I', d, 36, HEADER_SIZE)
                self.fixes.append('restored %s' % code.split()[0])
            elif code.startswith('P2'):
                declared = struct.unpack_from('<I', d, 32)[0]
                if HEADER_SIZE < declared < len(d) and not any(d[declared:]):
                    # the dumper page-aligned: trailing zero fill past the real end
                    del d[declared:]
                    struct.pack_into('<I', d, 32, declared)
                    self.fixes.append('trimmed trailing page padding -> %d bytes' % declared)
                else:
                    struct.pack_into('<I', d, 32, len(d))
                    self.fixes.append('file_size := %d' % len(d))
            elif code.startswith('P3'):
                off = self._scan_map_list(d)
                if off is not None:
                    struct.pack_into('<I', d, 52, off)
                    self.fixes.append('map_off := %d (signature scan)' % off)
                    self.issues = [i for i in self.issues if not i.startswith('P3')]
                else:
                    print('  !! P3 unrepairable: map_list scan found no candidate', file=sys.stderr)
        # P1 last: sums cover the whole (possibly just-repaired) content
        d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
        adler = zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF
        struct.pack_into('<I', d, 8, adler)
        self.fixed = bytes(d)
        if any(i.startswith('P1') for i in self.issues):
            self.fixes.append('sha1+adler32 recomputed')
        return self.fixed

    @staticmethod
    def _scan_map_list(d):
        """P3 recovery: find the map_list by structural signature.
        Invariants (DEX spec): first entry = TYPE_HEADER_ITEM (0,0,1,0);
        entries sorted by offset; count sane; every offset in-bounds; a
        TYPE_STRING_ID entry must sit exactly at the header's string_ids_off
        when that field survived."""
        n = len(d)
        # probe the header's string table as a cross-check witness (count, offset)
        try:
            sids_size = struct.unpack_from('<I', d, 56)[0]
            sids_off = struct.unpack_from('<I', d, 60)[0]
            witness = (sids_size, sids_off) if 0 < sids_off < n else None
        except struct.error:
            witness = None
        for off in range(HEADER_SIZE, n - 16):  # stride 1: map_list is not guaranteed aligned
            cnt = struct.unpack_from('<I', d, off)[0]
            if not (1 <= cnt <= 128) or off + 4 + cnt * 12 > n:
                continue
            t0, u0, c0, o0 = struct.unpack_from('<HHII', d, off + 4)
            if (t0, c0, o0) != (TYPE_HEADER, 1, 0):
                continue
            prev = -1
            ok = True
            seen = set()
            for i in range(cnt):
                t, _, c, o = struct.unpack_from('<HHII', d, off + 4 + i * 12)
                if t in seen or o <= prev or o >= n or c == 0:
                    ok = False
                    break
                seen.add(t)
                prev = o
            if not ok or (TYPE_STRING_ID not in seen):
                continue
            if witness:
                for i in range(cnt):
                    t, _, c, o = struct.unpack_from('<HHII', d, off + 4 + i * 12)
                    if t == TYPE_STRING_ID and (c, o) != witness:
                        ok = False
                if not ok:
                    continue
            return off
        return None


def triage_file(path, do_fix=False, out=None, as_json=False):
    data = open(path, 'rb').read()
    t = Triage(data, path).diagnose()
    if as_json:
        rep = {'file': path, 'issues': t.issues, 'meta': {k: v for k, v in t.meta.items()}}
        if do_fix:
            t.fix()
            rep['fixes'] = t.fixes
        print(json.dumps(rep, default=str))
        return t
    print('[triage] %s (%d bytes, dex %s)' % (path, len(data), t.meta.get('version', '?')))
    if not t.issues:
        print('  healthy — no pathology found')
    for i in t.issues:
        print('  ISSUE', i)
    if do_fix:
        t.fix()
        for f in t.fixes:
            print('  FIXED', f)
        dest = out or (path.rsplit('.', 1)[0] + '.ok.dex')
        open(dest, 'wb').write(t.fixed)
        # post-op verification: the repaired file must triage clean
        post = Triage(t.fixed, dest).diagnose()
        remaining = post.issues
        print('  post-op: %s -> %s' % (dest, 'CLEAN' if not remaining else 'residual: ' + '; '.join(remaining)))
    return t


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('path', help='a dumped .dex file OR a directory of dumps')
    ap.add_argument('-o', '--out')
    ap.add_argument('--fix', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    import os
    if os.path.isdir(args.path):
        for f in sorted(os.listdir(args.path)):
            if f.endswith('.dex'):
                triage_file(os.path.join(args.path, f), args.fix, args.json)
    else:
        triage_file(args.path, args.fix, args.out, args.json)


if __name__ == '__main__':
    main()
