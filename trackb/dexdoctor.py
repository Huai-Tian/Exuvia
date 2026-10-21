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
    P7 data beyond the map_list     — whole-memory dumps carry the shell's
                                     runtime workspace (high-entropy crypto
                                     material) past the last legal structure
    P8 duplicate map section type   — ART REJECTS the whole DEX ("Duplicate
                                     map section of type %x"): some repack
                                     toolchains (56.al-style) split one
                                     section into two physically-adjacent
                                     segments and emit one map entry each
    P9 data section bounds broken    — data_off+data_size != file_size
                                     (ART: "Section end(%d) should be within
                                     file size(%d) for data") — any length-
                                     changing repair MUST resync data_size
    P10 corrupted annotations         — the shell's runtime rewrites parts of
                                     the annotation region into working data
                                     (ART: "Bogus encoded_value value_type %x");
                                     the dump freezes that state. Bad entries
                                     are surgically UNREFERENCED (off=0 is
                                     legal = "no annotations"); good entries
                                     are kept — runtime reflection over
                                     annotations (@SerializedName...) survives
    P11 map-declared sections lie     — memory-layout dumps carry a map whose
                                     section TYPE labels are systemically
                                     misplaced (our corpus: the map's
                                     annotation region physically contains
                                     debug_info streams). ART walks the
                                     MAP-DECLARED 2003/2004 sections entry by
                                     entry — not just the reference chains —
                                     and hits bogus encoded_values in data
                                     that no reference ever touches. Reference
                                     audits (P10) and dexlib2 never see this.
                                     Repair: zero the 2003/2004 counts — the
                                     map-driven walk then sees empty sections,
                                     while the good entries on the reference
                                     chains (and runtime reflection) survive.

  REPAIR (validated against synthetic wounds; --fix writes, default reports):
    P1 -> recompute sha1+adler32          P2 -> file_size := actual length
    P3 -> map_list signature scan (TYPE_HEADER_ITEM sentinel + sorted-offset
          invariant + cross-check against surviving header tables)
    P5 -> endian/header_size restored to spec constants
    P7 -> trim everything past map_end (dead to ART, secrets to the shell)
    P8 -> merge duplicate map entries (adjacency-verified: fixed-size types
          by item-size arithmetic, type_list by boundary-walking with the
          structurally-detected entry width) and rewrite the map_list

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
            # P7: anything past the map_list (the last legal structure) is
            # the shell's runtime workspace riding along in a whole-memory dump
            cnt2 = struct.unpack_from('<I', d, map_off)[0]
            map_end = map_off + 4 + cnt2 * 12
            if map_end < n:
                self.issues.append('P7 %d bytes beyond map_list (shell workspace)' % (n - map_end))
                self.meta['map_end'] = map_end
            # P8: ART demands each map section type appear EXACTLY ONCE
            seen = {}
            for k in range(cnt2):
                e = map_off + 4 + k * 12
                t, _u, c, off = struct.unpack_from('<HHII', d, e)
                if t in seen:
                    self.issues.append('P8 duplicate map section type %04x' % t)
                seen[t] = c
            self.meta['map_types_seen'] = seen
            # P9: the data section must end exactly at file end (the map_list
            # is its last item). ART rejects end > file_size outright.
            data_off2 = struct.unpack_from('<I', d, 108)[0]
            data_size2 = struct.unpack_from('<I', d, 104)[0]
            if HEADER_SIZE <= data_off2 < n and data_off2 + data_size2 != file_size:
                self.issues.append('P9 data section end(%d) != file_size(%d)'
                                    % (data_off2 + data_size2, file_size))
            # P10: parse every annotation the ART verifier would walk; any
            # structurally-broken entry is corruption frozen by the dump
            bad = self._annotation_audit(bytes(d))
            if bad:
                self.issues.append('P10 %d corrupted annotation entries' % bad)
                self.meta['ann_bad'] = bad
            # P11: ART also walks the MAP-DECLARED annotation/encoded-array
            # sections entry by entry — content that no reference chain ever
            # touches (the memory-layout map's type labels are unreliable and
            # often point at debug_info streams).
            # NOTE: correct DEX spec type codes (fixed 2026-10-21 — the original
            # implementation swapped 0x2003/0x2004/0x2005 and mislabeled them;
            # for raw dumps the deletion repair happened to work because the
            # dump's map was misaligned in *both* slots, but repacked dexes
            # from dexlib2 carry a *correct* debug_info section at 0x2003 that
            # must NOT be walked as annotations):
            #   0x2003 = DEBUG_INFO_ITEM    — not walked (variable-length state machine)
            #   0x2004 = ANNOTATION_ITEM    — [visibility u1][encoded_annotation]
            #   0x2005 = ENCODED_ARRAY_ITEM — [size uleb][encoded_value...]
            #   0x2006 = ANNOTATIONS_DIRECTORY_ITEM — [class u4][fields u4][methods u4][params u4]
            bad_types = self._map_section_audit(bytes(d))
            if bad_types:
                self.issues.append('P11 map-declared sections invalid: %s'
                                   % ', '.join('%04x' % t for t in sorted(bad_types)))
                self.meta['map_sec_bad'] = sorted(bad_types)
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

    # ---------- P10 annotation audit/repair ----------
    # encoded_value type codes (the REAL spec table — an earlier version of
    # this table was plain wrong and cost a full debug round):
    #   0x00 byte 0x02 short 0x03 char 0x04 int 0x06 long
    #   0x10 float 0x11 double
    #   0x15 method_type 0x16 method_handle 0x17 string 0x18 type
    #   0x19 field 0x1a method 0x1b enum   (all: payload = tag&0x1f bytes)
    #   0x1c array 0x1d annotation (nested) 0x1e null 0x1f boolean
    # everything else (including 8) is BOGUS — ART rejects the whole DEX.
    _EV_IDX = {0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b}
    _EV_NUMERIC = {0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11}
    _EV_ZERO = {0x1e, 0x1f}

    @staticmethod
    def _uleb(d, p):
        r = 0
        s = 0
        while True:
            if p >= len(d):
                raise IndexError
            b = d[p]
            p += 1
            r |= (b & 0x7f) << s
            s += 7
            if not b & 0x80:
                return r, p

    @classmethod
    def _read_ev(cls, d, p):
        """One encoded_value (recursing through 0x1c arrays and 0x1d
        annotations). Returns (value_type, next_p, ok).
        tag layout: (value_arg << 5) | value_type — the TYPE is the LOW
        five bits; the LENGTH HINT is the high bits (payload = arg+1 bytes
        for numeric/index kinds). An earlier version of this reader had the
        two fields SWAPPED — types were matched against the length hint and
        payloads were consumed by the type code, mis-walking everything
        (it "worked" on the dumps only because broken entries were
        unreferenced anyway, and good ones were collateral damage)."""
        if p >= len(d):
            return 0, p, False
        tag = d[p]
        vtype = tag & 0x1f
        varg = (tag >> 5) & 0x07
        p += 1
        if vtype == 0x1c:  # array
            try:
                n, p = cls._uleb(d, p)
            except IndexError:
                return vtype, p, False
            for _ in range(n):
                _, p, ok = cls._read_ev(d, p)
                if not ok:
                    return vtype, p, False
            return vtype, p, True
        if vtype == 0x1d:  # nested encoded_annotation
            try:
                _, p = cls._uleb(d, p)  # type_idx
                n, p = cls._uleb(d, p)  # element count
                for _ in range(n):
                    _, p = cls._uleb(d, p)  # name_idx
                    _, p, ok = cls._read_ev(d, p)
                    if not ok:
                        return vtype, p, False
            except IndexError:
                return vtype, p, False
            return vtype, p, True
        if vtype in cls._EV_IDX:
            return vtype, p + varg + 1, True
        if vtype in cls._EV_ZERO:
            return vtype, p, True
        if vtype in cls._EV_NUMERIC:
            return vtype, p + varg + 1, True
        return vtype, p, False  # unknown type = structural break

    @classmethod
    def _ann_item_ok(cls, d, ao):
        """annotation_item: [visibility u8][encoded_annotation: type_idx
        uleb, size uleb, (name_idx uleb, encoded_value)*]"""
        if not (0 < ao < len(d) - 1):
            return False
        p = ao + 1
        try:
            _, p = cls._uleb(d, p)  # type_idx
            n, p = cls._uleb(d, p)  # element count
            for _ in range(n):
                _, p = cls._uleb(d, p)  # name_idx
                _, p, ok = cls._read_ev(d, p)
                if not ok:
                    return False
        except IndexError:
            return False
        return p <= len(d)

    @classmethod
    def _ann_set_ok(cls, d, aso):
        """annotation_set_item: [size u32][entry offsets...]"""
        if not (0 < aso + 4 <= len(d)):
            return False
        n = struct.unpack_from('<I', d, aso)[0]
        if n > 65536 or aso + 4 + n * 4 > len(d):
            return False
        for k in range(n):
            ao = struct.unpack_from('<I', d, aso + 4 + k * 4)[0]
            if ao and not cls._ann_item_ok(d, ao):
                return False
        return True

    @staticmethod
    def _ann_dirs(d):
        """yield (class_def_row_offset, annotations_dir_offset) for every class"""
        cis, cdo = struct.unpack_from('<II', d, 96)
        for i in range(cis):
            row = cdo + i * 32
            ad = struct.unpack_from('<I', d, row + 20)[0]
            if ad:
                yield row, ad

    @classmethod
    def _annotation_audit(cls, d):
        """Count structurally-broken encoded_value carriers (P10): BOTH the
        annotations_directory chains AND the static_values chains (the
        earlier version only audited annotations — a static_values-encoded
        value_type 8 survived it and ART rejected the v7 build)."""
        bad = 0
        # static_values: encoded_array = [size uleb][encoded_value...]
        cis, cdo = struct.unpack_from('<II', d, 96)
        for i in range(cis):
            row = cdo + i * 32
            sv = struct.unpack_from('<I', d, row + 28)[0]
            if not sv:
                continue
            try:
                n, p = cls._uleb(d, sv)
                ok = True
                for _ in range(n):
                    _, p, ok = cls._read_ev(d, p)
                    if not ok:
                        break
                if not ok or p > len(d):
                    bad += 1
            except IndexError:
                bad += 1
        # annotations chains
        for row, ad in cls._ann_dirs(d):
            if not (0 < ad + 16 <= len(d)):
                bad += 1
                continue
            ca, nf, nm, npr = struct.unpack_from('<IIII', d, ad)
            if ca and not cls._ann_set_ok(d, ca):
                bad += 1
            if nf > 65536 or nm > 65536 or npr > 65536:
                bad += 1
                continue
            if ad + 16 + (nf + nm + npr) * 8 > len(d):
                bad += 1
                continue
            for k in range(nf + nm + npr):
                off = struct.unpack_from('<I', d, ad + 16 + k * 8 + 4)[0]
                if off and not cls._ann_set_ok(d, off):
                    bad += 1
        return bad

    @classmethod
    def _fix_annotations(cls, d):
        """Unreference every broken encoded_value carrier: static_values_off
        (bad -> 0 = no static values; R8 inlines compile-time constants, the
        runtime cost is reflection-read fields) and annotation entries
        (bad -> off := 0 = 'no annotations'). Good entries are untouched."""
        n = 0
        # static_values
        cis, cdo = struct.unpack_from('<II', d, 96)
        for i in range(cis):
            row = cdo + i * 32
            sv = struct.unpack_from('<I', d, row + 28)[0]
            if not sv:
                continue
            try:
                cnt, p = cls._uleb(d, sv)
                ok = True
                for _ in range(cnt):
                    _, p, ok = cls._read_ev(d, p)
                    if not ok:
                        break
                if not ok or p > len(d):
                    struct.pack_into('<I', d, row + 28, 0)
                    n += 1
            except IndexError:
                struct.pack_into('<I', d, row + 28, 0)
                n += 1
        # annotation chains
        for row, ad in cls._ann_dirs(bytes(d)):
            if not (0 < ad + 16 <= len(d)):
                struct.pack_into('<I', d, row + 20, 0)
                n += 1
                continue
            ca, nf, nm, npr = struct.unpack_from('<IIII', d, ad)
            if ca and not cls._ann_set_ok(bytes(d), ca):
                struct.pack_into('<I', d, ad, 0)
                n += 1
            if nf > 65536 or nm > 65536 or npr > 65536 or ad + 16 + (nf + nm + npr) * 8 > len(d):
                struct.pack_into('<I', d, row + 20, 0)
                n += 1
                continue
            for k in range(nf + nm + npr):
                eo = ad + 16 + k * 8 + 4
                off = struct.unpack_from('<I', d, eo)[0]
                if off and not cls._ann_set_ok(bytes(d), off):
                    struct.pack_into('<I', d, eo, 0)
                    n += 1
        return n

    @classmethod
    def _map_section_audit(cls, d):
        """P11: walk the MAP-DECLARED annotation_item (0x2004) and
        encoded_array_item (0x2005) sections entry by entry the way ART's
        verifier does. Returns the set of section TYPES holding at least one
        invalid entry (empty set = clean).

        Correct DEX spec type codes (fixed 2026-10-21):
          0x2003 = DEBUG_INFO_ITEM (not walked — variable-length state machine)
          0x2004 = ANNOTATION_ITEM [visibility u1][encoded_annotation]
          0x2005 = ENCODED_ARRAY_ITEM [size uleb][encoded_value...]
          0x2006 = ANNOTATIONS_DIRECTORY_ITEM (not walked — offsets only)
        """
        mo = struct.unpack_from('<I', d, 52)[0]
        n = struct.unpack_from('<I', d, mo)[0]
        items = [struct.unpack_from('<HHII', d, mo + 4 + k * 12) for k in range(n)]
        items.sort(key=lambda x: x[3])
        bad_types = set()
        for i, (t, _u, c, off) in enumerate(items):
            end = items[i + 1][3] if i + 1 < len(items) else len(d)
            if t == 0x2004:  # ANNOTATION_ITEM: [visibility u1][encoded_annotation]
                p = off
                for _ in range(c):
                    if not cls._ann_item_ok(d, p):
                        bad_types.add(t)
                        break
                    # advance: walk the full annotation to find the next entry
                    ok = True
                    np_ = p + 1
                    try:
                        _, np_ = cls._uleb(d, np_)       # type_idx
                        cnt, np_ = cls._uleb(d, np_)     # element count
                        for _ in range(cnt):
                            _, np_ = cls._uleb(d, np_)   # name_idx
                            _, np_, ok = cls._read_ev(d, np_)
                            if not ok:
                                break
                    except IndexError:
                        break
                    if not ok or np_ > end:
                        break
                    p = np_
            elif t == 0x2005:  # ENCODED_ARRAY_ITEM: [size uleb][encoded_value...]
                p = off
                for _ in range(c):
                    try:
                        cnt, np_ = cls._uleb(d, p)
                        ok = True
                        for _ in range(cnt):
                            _, np_, ok = cls._read_ev(d, np_)
                            if not ok:
                                break
                        if not ok or np_ > end:
                            bad_types.add(t)
                            break
                        p = np_
                    except IndexError:
                        bad_types.add(t)
                        break
        return bad_types

    @staticmethod
    def _fix_map_sections(d, bad_types):
        """P11 repair: REMOVE the offending map entries entirely and rewrite
        the map_list. (The earlier count=0 trick — 'empty section' — was
        rejected by real-hardware ART with 'Unknown map item type': the map
        is rigid, absent entries are fine, hollow ones are not. The required-
        entry checks cover header/map_list/string_ids/... — 0x2004/0x2005 are
        NOT in that list, so removal is legal.) Returns the number of entries
        removed."""
        if not bad_types:
            return 0
        mo = struct.unpack_from('<I', d, 52)[0]
        n = struct.unpack_from('<I', d, mo)[0]
        items = [list(struct.unpack_from('<HHII', d, mo + 4 + k * 12)) for k in range(n)]
        keep = [it for it in items if it[0] not in bad_types]
        if len(keep) == len(items):
            return 0
        keep.sort(key=lambda x: x[3])
        new_map = struct.pack('<I', len(keep)) + b''.join(
            struct.pack('<HHII', t, 0, c, o) for t, _u, c, o in keep)
        removed = len(items) - len(keep)
        del d[mo:]
        d += new_map
        struct.pack_into('<I', d, 32, len(d))
        return removed

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
            elif code.startswith('P7'):
                # map_end from triage; after a P3 repair it must be recomputed
                mo = struct.unpack_from('<I', d, 52)[0]
                cnt = struct.unpack_from('<I', d, mo)[0]
                map_end = mo + 4 + cnt * 12
                if HEADER_SIZE < map_end < len(d):
                    trimmed = len(d) - map_end
                    del d[map_end:]
                    struct.pack_into('<I', d, 32, len(d))
                    self.fixes.append('trimmed %d bytes past map_list (shell workspace)' % trimmed)
            elif code.startswith('P8'):
                merged = self._merge_duplicate_map_sections(d)
                if merged:
                    self.fixes.append('map sections merged: %s' % ', '.join(
                        'type %04x x%d' % (t, k) for t, k in merged))
                    self.issues = [i for i in self.issues if not i.startswith('P8')]
                else:
                    print('  !! P8 unrepairable: non-adjacent duplicate sections', file=sys.stderr)
            elif code.startswith('P10'):
                fixed_ann = self._fix_annotations(d)
                if fixed_ann:
                    self.fixes.append('unreferenced %d corrupted annotation entries (good ones kept)' % fixed_ann)
                    # re-audit: what remains?
                    remain = self._annotation_audit(bytes(d))
                    if remain == 0:
                        self.issues = [i for i in self.issues if not i.startswith('P10')]
                    else:
                        print('  !! P10 residual: %d bad entries unreachable to unreference' % remain,
                              file=sys.stderr)
            elif code.startswith('P11'):
                bad_types = self._map_section_audit(bytes(d))
                removed = self._fix_map_sections(d, bad_types)
                if removed:
                    self.fixes.append('removed %d invalid map section entries (%s) — map-driven walk no longer sees them; reference chains intact'
                                      % (removed, ', '.join('%04x' % t for t in sorted(bad_types))))
                    remain = self._map_section_audit(bytes(d))
                    if not remain:
                        self.issues = [i for i in self.issues if not i.startswith('P11')]
                    else:
                        print('  !! P11 residual: %s still invalid' % remain, file=sys.stderr)
        # P9 terminal invariant: any length-changing repair (P2 trim, P7 trim,
        # P8 map rewrite) must leave data_size in sync — the data section ends
        # at file end. Fix it AFTER all trims, BEFORE the sums.
        data_off_f = struct.unpack_from('<I', d, 108)[0]
        if HEADER_SIZE <= data_off_f < len(d) and \
                data_off_f + struct.unpack_from('<I', d, 104)[0] != len(d):
            struct.pack_into('<I', d, 104, len(d) - data_off_f)
            self.fixes.append('data_size := %d (section ends at file end)' % (len(d) - data_off_f))
            self.issues = [i for i in self.issues if not i.startswith('P9')]
        # P1 last: sums cover the whole (possibly just-repaired) content
        d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
        adler = zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF
        struct.pack_into('<I', d, 8, adler)
        self.fixed = bytes(d)
        if any(i.startswith('P1') for i in self.issues):
            self.fixes.append('sha1+adler32 recomputed')
        return self.fixed

    @staticmethod
    def _merge_duplicate_map_sections(d):
        """P8 repair: merge duplicate map entries (same type emitted twice by
        repack toolchains) into one, REWRITING the map_list in place. Only
        merges when the segments are physically adjacent — fixed-size types
        by item-size arithmetic, type_list by boundary-walking (entry width
        detected structurally: u16 vs u32). Returns [(type, merged_count)]
        or [] if unrepairable. The map_list shrinks by 12B per merge: the
        file tail is truncated and the caller recomputes header sums."""
        FIXED_SIZE = {0x0000: 112, 0x0001: 4, 0x0002: 4, 0x0003: 12,
                      0x0004: 8, 0x0005: 8, 0x0006: 32}
        mo = struct.unpack_from('<I', d, 52)[0]
        cnt = struct.unpack_from('<I', d, mo)[0]
        items = [list(struct.unpack_from('<HHII', d, mo + 4 + k * 12)) for k in range(cnt)]
        items.sort(key=lambda x: x[3])
        from collections import defaultdict
        groups = defaultdict(list)
        for it in items:
            groups[it[0]].append(it)

        def walk_width(off, end):
            """type_list boundary-walk from off to end — returns the width
            (2/4) that lands exactly on end, else None."""
            for w in (4, 2):
                p = off
                steps = 0
                while p < end:
                    size = struct.unpack_from('<I', d, p)[0]
                    if size > 1000 or p + 4 + size * w > end + 12:
                        p = -1
                        break
                    p = (p + 4 + size * w + 3) & ~3
                    steps += 1
                    if steps > 100000:
                        p = -1
                        break
                if p == end:
                    return w
            return None

        out, merged, changed = [], [], False
        for t, lst in sorted(groups.items()):
            if len(lst) == 1:
                out.append(lst[0])
                continue
            ok = True
            if t in FIXED_SIZE:
                sz = FIXED_SIZE[t]
                for i in range(len(lst) - 1):
                    if lst[i + 1][3] != lst[i][3] + lst[i][2] * sz:
                        ok = False
                        break
            elif t == 0x1001:
                for i in range(len(lst) - 1):
                    if walk_width(lst[i][3], lst[i + 1][3]) is None:
                        ok = False
                        break
            else:
                ok = False  # unknown variable-size layout — do not guess
            if not ok:
                return []
            out.append([t, 0, sum(e[2] for e in lst), lst[0][3]])
            merged.append((t, len(lst)))
            changed = True
        if not changed:
            return []
        out.sort(key=lambda x: x[3])
        # rewrite the map_list (12-byte entries, offset-ascending per spec)
        new_map = struct.pack('<I', len(out)) + b''.join(
            struct.pack('<HHII', t, 0, c, o) for t, _u, c, o in out)
        del d[mo:]
        d += new_map
        struct.pack_into('<I', d, 32, len(d))
        return merged

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
