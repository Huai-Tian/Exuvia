#!/usr/bin/env python3
"""covdebt.py — coverage-debt extractor (SKILL §7 device-coverage arm).

After a restore run, every remaining nop-wall method is COVERAGE DEBT: the
dump session never executed it, so no donor could carry its real body (the
extraction family re-materializes lazily, at execution time). This tool
turns "N walls left" into an actionable, machine-readable worklist:

  covdebt.py <repaired.dex> [-o coverage_debt.json]

Each debt entry carries everything a sweep planner needs: class, name,
proto, access flags, direct/virtual, and the parsed parameter descriptors.
Pair with fart_plan.py (debt -> invocation plan) and fart_sweep (device-side
FART-style forced materialization), then re-dump and feed --dump again —
the debt shrinks every round, measurably.

The nop-wall predicate mirrors Restore.isNopWall semantics-for-semantics
(calibrated on the family-3 sample: packed 8697, post-restore 3182 — the
same numbers dexlib2 reports). Zero-sample: no family-specific constants.
"""
import argparse
import json
import struct
import sys

# --- DEX opcode lengths in 16-bit units (spec formats; anything not listed
# --- below defaults to 1) -------------------------------------------------
_UNITS = [1] * 256
for _o in ([0x02, 0x05, 0x08, 0x0b, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c,
            0x1f, 0x20, 0x22, 0x23, 0x29]
           + list(range(0x2d, 0x32))   # float/double/long compares (23x)
           + list(range(0x32, 0x3e))   # if-*
           + list(range(0x44, 0x52))   # aget/aput family
           + list(range(0x52, 0x60))   # iget/iput family
           + list(range(0x60, 0x6e))   # sget/sput family
           + list(range(0x90, 0xb0))   # binop
           + list(range(0xd0, 0xe3))):  # binop/lit16, binop/lit8
    _UNITS[_o] = 2
for _o in ([0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a,
            0x2b, 0x2c]
           + list(range(0x6e, 0x73))   # invoke-*
           + list(range(0x74, 0x79))):  # invoke-*/range
    _UNITS[_o] = 3
_UNITS[0x18] = 5                        # const-wide (51l)

_RETURNS = (0x0e, 0x0f, 0x10, 0x11)
_CONSTS = (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19)

ACC_STATIC = 0x8
ACC_ABSTRACT = 0x400
ACC_NATIVE = 0x100
ACC_INTERFACE = 0x200


def _uleb(d, p):
    r = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        r |= (b & 0x7f) << s
        if not b & 0x80:
            return r, p
        s += 7


def _const_literal_zero(op, blob, i):
    """True when the const-family instruction at i carries a zero literal
    (the packer's null/false/0/0L return feed)."""
    if op == 0x12:                       # const/4: signed nibble, byte1 high
        hi = blob[i + 1] >> 4
        lit = hi - 16 if hi > 7 else hi
        return lit == 0
    if op in (0x13, 0x15, 0x16, 0x19):   # 16-bit field (shifted variants: zero iff 0)
        return int.from_bytes(blob[i + 2:i + 4], 'little') == 0
    if op in (0x14, 0x17):               # 32-bit
        return int.from_bytes(blob[i + 2:i + 6], 'little') == 0
    # 0x18 const-wide: 64-bit
    return int.from_bytes(blob[i + 2:i + 10], 'little') == 0


def is_nop_wall(blob):
    """Semantics-for-semantics mirror of Restore.isNopWall: the body is
    EXCLUSIVELY nops, zero-literal consts and returns, with >=1 nop and
    >=1 return. A legit empty method is exactly `return-void` (zero nops);
    anything else (an invoke, a field op, a non-zero literal) is real."""
    nops = 0
    returns = 0
    i = 0
    while i < len(blob):
        op = blob[i]
        if op == 0x00:
            if blob[i + 1] != 0:
                return False  # packed/sparse/fill-array payload, not a nop
            nops += 1
        elif op in _RETURNS:
            returns += 1
        elif op in _CONSTS:
            if not _const_literal_zero(op, blob, i):
                return False
        else:
            return False
        i += _UNITS[op] * 2
    return nops >= 1 and returns >= 1


def _is_ctor_stub(dx, blob, name):
    """StubSafe's synthesized nop-wall-constructor body (finding #10):
    zero or more zero-literal consts, exactly one invoke-direct naming an
    <init>, exactly one return-void, and NO nops (a nop would make it a
    wall again). Not debt — the class verifies now — but not a recovered
    body either, so it is counted separately (honest convergence metrics:
    ctor_stub exits the debt list without inflating 'real')."""
    if name != '<init>':
        return False
    invokes = 0
    returns = 0
    i = 0
    while i < len(blob):
        op = blob[i]
        if op == 0x0e:
            returns += 1
        elif op == 0x70:                       # invoke-direct (35c, 3 units)
            midx = struct.unpack_from('<H', blob, i + 2)[0]
            _cls, mname, _p = dx.method_ref(midx)
            if mname != '<init>':
                return False
            invokes += 1
        elif op in _CONSTS:
            if not _const_literal_zero(op, blob, i):
                return False
        else:
            return False
        i += _UNITS[op] * 2
    return invokes == 1 and returns == 1


class Dex:
    """Minimal table walker (header / strings / types / protos / methods /
    class_data). Self-contained: the type_list width is detected
    structurally (035 u32 vs 039 compact u16), never by version string."""

    def __init__(self, data: bytes):
        self.d = data
        if self.d[:4] != b'dex\n':
            raise ValueError('not a DEX')
        (self.file_size, self.header_size, self.endian, self.link_size,
         self.link_off, self.map_off) = struct.unpack_from('<IIIIII', data, 32)
        (self.string_ids_size, self.string_ids_off, self.type_ids_size,
         self.type_ids_off) = struct.unpack_from('<IIII', data, 56)
        (self.proto_ids_size, self.proto_ids_off, self.field_ids_size,
         self.field_ids_off) = struct.unpack_from('<IIII', data, 72)
        (self.method_ids_size, self.method_ids_off, self.class_defs_size,
         self.class_defs_off, self.data_size, self.data_off) = \
            struct.unpack_from('<IIIIII', data, 88)
        self._strs = None
        self._tlw = None

    def strings(self):
        if self._strs is None:
            out = []
            for i in range(self.string_ids_size):
                off = struct.unpack_from('<I', self.d, self.string_ids_off + 4 * i)[0]
                _, p = _uleb(self.d, off)
                end = self.d.index(b'\0', p)
                out.append(self.d[p:end].decode('utf-8', 'replace'))
            self._strs = out
        return self._strs

    def type_desc(self, idx):
        strs = self.strings()
        return strs[struct.unpack_from('<I', self.d, self.type_ids_off + 4 * idx)[0]]

    def _tl_width(self):
        if self._tlw is not None:
            return self._tlw
        mo = self.map_off
        w = 4
        if mo and mo + 4 <= len(self.d):
            n = struct.unpack_from('<I', self.d, mo)[0]
            items = [struct.unpack_from('<HHII', self.d, mo + 4 + k * 12)
                     for k in range(n)]
            items.sort(key=lambda x: x[3])
            start = end = None
            for i, it in enumerate(items):
                if it[0] == 0x1001:
                    start = it[3]
                    end = items[i + 1][3] if i + 1 < len(items) else len(self.d)
                    break
            if start is not None and end is not None and end > start:
                for cand in (4, 2):
                    p, ok = start, True
                    while p < end:
                        size = struct.unpack_from('<I', self.d, p)[0]
                        if size > 1000 or p + 4 + size * cand > end + 4:
                            ok = False
                            break
                        p = (p + 4 + size * cand + 3) & ~3
                    if ok and end <= p <= end + 4:
                        w = cand
                        break
        self._tlw = w
        return w

    def _type_list(self, off):
        if not off:
            return []
        n = struct.unpack_from('<I', self.d, off)[0]
        w = self._tl_width()
        fmt = '<%dH' % n if w == 2 else '<%dI' % n
        return list(struct.unpack_from(fmt, self.d, off + 4)) if n else []

    def proto(self, proto_idx):
        """-> (shorty, return_type_desc, [param_type_desc...])"""
        base = self.proto_ids_off + 12 * proto_idx
        shorty_idx, ret_idx, params_off = struct.unpack_from('<III', self.d, base)
        strs = self.strings()
        return (strs[shorty_idx], self.type_desc(ret_idx),
                [self.type_desc(t) for t in self._type_list(params_off)])

    def method_ref(self, method_idx):
        """-> (class_desc, name, proto_idx)"""
        base = self.method_ids_off + 8 * method_idx
        cls_idx, proto_idx, name_idx = struct.unpack_from('<HHI', self.d, base)
        return self.type_desc(cls_idx), self.strings()[name_idx], proto_idx

    def methods(self):
        """Yield (class_desc, class_access, name, proto_idx, access,
        code_off) for every declared method (direct then virtual per the
        class_data stream; method_idx_diff restarts at 0 for each list)."""
        for ci in range(self.class_defs_size):
            base = self.class_defs_off + 32 * ci
            cls_idx, cls_access = struct.unpack_from('<II', self.d, base)
            cdata = struct.unpack_from('<I', self.d, base + 24)[0]
            if not cdata:
                continue
            cls = self.type_desc(cls_idx)
            p = cdata
            nsf, p = _uleb(self.d, p)
            nif, p = _uleb(self.d, p)
            nd, p = _uleb(self.d, p)
            nv, p = _uleb(self.d, p)
            for _ in range(nsf + nif):
                _, p = _uleb(self.d, p)
                _, p = _uleb(self.d, p)
            for kind, n in (('direct', nd), ('virtual', nv)):
                midx = 0
                for _ in range(n):
                    diff, p = _uleb(self.d, p)
                    midx += diff
                    access, p = _uleb(self.d, p)
                    code_off, p = _uleb(self.d, p)
                    name = self.strings()[struct.unpack_from(
                        '<I', self.d, self.method_ids_off + 8 * midx + 4)[0]]
                    proto_idx = struct.unpack_from(
                        '<H', self.d, self.method_ids_off + 8 * midx + 2)[0]
                    yield cls, cls_access, name, proto_idx, access, code_off, kind

    def code_blob(self, code_off):
        insns_size = struct.unpack_from('<I', self.d, code_off + 12)[0]
        return self.d[code_off + 16:code_off + 16 + 2 * insns_size]


def extract_debt(data: bytes):
    """-> (stats, [debt...]); debt entries carry the full sweep-planner
    metadata. Walls only — real bodies and abstract/native no-code
    declarations are not debt."""
    dx = Dex(data)
    stats = {'classes': dx.class_defs_size, 'methods': 0, 'coded': 0,
             'nop_wall': 0, 'real': 0, 'no_code': 0, 'ctor_stub': 0}
    debt = []
    for cls, cls_access, name, proto_idx, access, code_off, kind in dx.methods():
        stats['methods'] += 1
        if not code_off:
            stats['no_code'] += 1
            continue
        stats['coded'] += 1
        blob = dx.code_blob(code_off)
        if not is_nop_wall(blob):
            if _is_ctor_stub(dx, blob, name):
                stats['ctor_stub'] += 1  # synthesized, verifies — not debt
            else:
                stats['real'] += 1
            continue
        stats['nop_wall'] += 1
        shorty, ret, params = dx.proto(proto_idx)
        debt.append({
            'class': cls,
            'name': name,
            'proto': '(%s)%s' % (''.join(params), ret),
            'access': access,
            'class_abstract': bool(cls_access & (ACC_ABSTRACT | ACC_INTERFACE)),
            'static': bool(access & ACC_STATIC),
            'abstract': bool(access & ACC_ABSTRACT),
            'constructor': name == '<init>',
            'clinit': name == '<clinit>',
            'kind': kind,
            'params': params,
            'return': ret,
            'body_bytes': len(blob),
        })
    return stats, debt


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('dex', help='the REPAIRED (post-restore) product dex')
    ap.add_argument('-o', '--out', default=None,
                    help='debt JSON path (default: <dex>.coverage_debt.json)')
    args = ap.parse_args()
    data = open(args.dex, 'rb').read()
    stats, debt = extract_debt(data)
    out = args.out or args.dex + '.coverage_debt.json'
    with open(out, 'w') as f:
        json.dump({'tool': 'covdebt', 'dex': args.dex, 'stats': stats,
                   'debt': debt}, f, indent=1)
    print('[covdebt] %s: %d methods (%d coded), nop-wall debt=%d, real=%d, '
          'ctor-stub=%d -> %s'
          % (args.dex, stats['methods'], stats['coded'], stats['nop_wall'],
             stats['real'], stats['ctor_stub'], out))


if __name__ == '__main__':
    main()
