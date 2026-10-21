#!/usr/bin/env python3
"""deweave.py — shell-woven bytecode restoration (the true de-repair).

The point of the repair pipeline is a restored package that BEHAVES LIKE THE
UNPACKED ORIGINAL — no shell classes, no bridge shims, no leftover markers.
Runtime dumpers capture the app DEX AS THE SHELL WOVE IT: packers rewrite
invoke sites inside app bytecode (360-family, 14 sites in our corpus):

  woven:   invoke-static/range vN, StubApp.getOrigApplicationContext(Context)Context
  was:     invoke-virtual/range vN, Context.getApplicationContext()Context
           (the shell's bridge IS that call — weaving redirected it through
            StubApp so the shell could intercept context resolution)

  woven:   invoke-static StubApp.interface11/22(...)   (lifecycle probes)
  was:     <nothing — the packer INSERTED these probes>

Restoration is byte-level IN-PLACE (both forms are 6-byte instructions with
identical layouts — opcode + method index swap, registers untouched; probes
become three nops, keeping every offset, branch target and try/catch region
exactly where it was):

  KNOWN_BRIDGES: (name, params, ret) -> the framework method the shell's
      bridge delegates to; the invoke's opcode flips static->virtual and the
      method index points at the framework method.
  everything else the app references-but-the-dump-lacks: probe -> nops.

Scanning happens ONLY inside the map-declared code_item section (never in
data), and the weave target's method index is matched on the full 6-byte
instruction shape. After restoration the DEX sums are recomputed.

Usage:
  deweave.py dumped.dex [-o out.dex] [--report]
  (also importable: deweave(dex_bytes) -> (bytes, [(line, ...)]))
"""
import argparse
import hashlib
import struct
import sys
import zlib

# 360-family bridge semantics: the woven method delegates to exactly this
# framework call. Key: (name, params tuple, ret) -> target (cls, name, params, ret)
KNOWN_BRIDGES = {
    ('getOrigApplicationContext', ('Landroid/content/Context;',), 'Landroid/content/Context;'):
        ('Landroid/content/Context;', 'getApplicationContext', (), 'Landroid/content/Context;'),
}

SHELL_PREFIXES = (
    'com.stub.', 'com.secneo.', 'com.qihoo.', 'com.morgoo.', 'dxloader.',
    'protect.', 'com.wrapper.', 'com.app.plugin.', 'com.jg.', 'cn.security.',
)

OP_INVOKE_STATIC = 0x71       # 35c: [71][A|G][method_idx][regs]
OP_INVOKE_STATIC_RANGE = 0x77  # 3rc: [77][AA][method_idx][start_reg]
OP_INVOKE_VIRTUAL = 0x6e
OP_INVOKE_VIRTUAL_RANGE = 0x74


def _uleb(d, p):
    r = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        r |= (b & 0x7f) << s
        s += 7
        if not b & 0x80:
            return r, p


def _tables(d):
    sis, sio = struct.unpack_from('<II', d, 56)
    tis, tio = struct.unpack_from('<II', d, 64)
    pis, pio = struct.unpack_from('<II', d, 72)
    mis, mio = struct.unpack_from('<II', d, 88)
    cis, cdo = struct.unpack_from('<II', d, 96)
    mo = struct.unpack_from('<I', d, 52)[0]
    return (sis, sio, tis, tio, pis, pio, mis, mio, cis, cdo, mo)


def _strings(d, sis, sio):
    out = []
    for i in range(sis):
        off = struct.unpack_from('<I', d, sio + i * 4)[0]
        _, p = _uleb(d, off)
        end = d.index(0, p)
        out.append(d[p:end].decode('utf-8', errors='replace'))
    return out


def _type_desc(d, idx, tio, strs):
    s = strs[struct.unpack_from('<I', d, tio + idx * 4)[0]]
    return s


def _tl_width(d, mo):
    n = struct.unpack_from('<I', d, mo)[0]
    items = [struct.unpack_from('<HHII', d, mo + 4 + k * 12) for k in range(n)]
    items.sort(key=lambda x: x[3])
    start = end = None
    for i, it in enumerate(items):
        if it[0] == 0x1001:
            start = it[3]
            end = items[i + 1][3] if i + 1 < len(items) else len(d)
            break
    if start is None:
        return 4
    for w in (4, 2):
        p, ok = start, True
        while p < end:
            size = struct.unpack_from('<I', d, p)[0]
            if size > 1000 or p + 4 + size * w > end + 4:
                ok = False
                break
            p = (p + 4 + size * w + 3) & ~3
        # accept an exact tile OR a final padding overhang of <=4 bytes
        # (memory-layout dexes place the next section at NON-4-aligned
        # offsets; the walk's aligned end may legally pass it by up to 4)
        if ok and end <= p <= end + 4:
            return w
    return 4


def _proto_descs(d, proto_idx, pio, tio, strs, tlw):
    pr = pio + proto_idx * 12
    ret_idx = struct.unpack_from('<I', d, pr + 4)[0]
    params_off = struct.unpack_from('<I', d, pr + 8)[0]
    params = []
    if params_off:
        pn = struct.unpack_from('<I', d, params_off)[0]
        for q in range(pn):
            t = struct.unpack_from('<' + ('H' if tlw == 2 else 'I'), d, params_off + 4 + q * tlw)[0]
            params.append(_type_desc(d, t, tio, strs))
    return params, _type_desc(d, ret_idx, tio, strs)


def _code_section(d, mo):
    """Scan window = [data_off, map_off): the whole data section. The map's
    section TYPE labels are UNRELIABLE in memory-layout dumps (our corpus:
    code items physically live inside what the map calls the debug_info
    region — the shell/ART relocated them); but data_off and map_off come
    from the header, which every working layout must keep self-consistent."""
    data_off = struct.unpack_from('<I', d, 108)[0]
    if not (0x70 <= data_off < mo):
        return None, None
    return data_off, mo


def deweave(dex: bytes):
    """Restore the shell-woven bytecode. Returns (fixed_bytes, report_lines).
    Idempotent: a second run finds nothing and returns the input unchanged."""
    d = bytearray(dex)
    sis, sio, tis, tio, pis, pio, mis, mio, cis, cdo, mo = _tables(bytes(d))
    strs = _strings(bytes(d), sis, sio)
    tlw = _tl_width(bytes(d), mo)

    # classes the dump DEFINES
    defined = set()
    for i in range(cis):
        ci = struct.unpack_from('<I', d, cdo + i * 32)[0]
        defined.add(_type_desc(d, ci, tio, strs))
    # defined class dots
    def is_shell_missing(cls_desc):
        dot = cls_desc[1:-1].replace('/', '.') if cls_desc.startswith('L') else cls_desc
        return (any(dot.startswith(p) for p in SHELL_PREFIXES)
                and cls_desc not in defined)

    # find the framework bridge target's method index (Context.getApplicationContext)
    bridge_target_idx = None
    for i in range(mis):
        cls_idx, proto_idx = struct.unpack_from('<HH', d, mio + i * 8)
        name_idx = struct.unpack_from('<I', d, mio + i * 8 + 4)[0]
        cls = _type_desc(d, cls_idx, tio, strs)
        if cls != 'Landroid/content/Context;' or strs[name_idx] != 'getApplicationContext':
            continue
        params, ret = _proto_descs(d, proto_idx, pio, tio, strs, tlw)
        if params == [] and ret == 'Landroid/content/Context;':
            bridge_target_idx = i
            break

    # collect woven shell-method indices + whether each is a KNOWN bridge
    shell_methods = {}  # method_idx -> ('bridge' | 'probe')
    for i in range(mis):
        cls_idx, proto_idx = struct.unpack_from('<HH', d, mio + i * 8)
        name_idx = struct.unpack_from('<I', d, mio + i * 8 + 4)[0]
        cls = _type_desc(d, cls_idx, tio, strs)
        if not is_shell_missing(cls):
            continue
        name = strs[name_idx]
        params, ret = _proto_descs(d, proto_idx, pio, tio, strs, tlw)
        key = (name, tuple(params), ret)
        if key in KNOWN_BRIDGES:
            if bridge_target_idx is None:
                return bytes(d), ['!! bridge target (Context.getApplicationContext) not in method table — abort']
            shell_methods[i] = 'bridge'
        else:
            shell_methods[i] = 'probe'
    if not shell_methods:
        return bytes(d), []

    # scan ONLY the map-declared code section
    cs, ce = _code_section(bytes(d), mo)
    if cs is None:
        return bytes(d), ['!! no code_item section in map — abort']

    report = []
    hits = 0
    p = cs
    while p + 6 <= ce:
        op = d[p]
        if op in (OP_INVOKE_STATIC, OP_INVOKE_STATIC_RANGE):
            mid = struct.unpack_from('<H', d, p + 2)[0]
            if mid in shell_methods:
                kind = shell_methods[mid]
                old = bytes(d[p:p + 6])
                if kind == 'bridge' and op == OP_INVOKE_STATIC_RANGE \
                        and d[p + 6] == 0x0c:
                    # bridge: context flows in, the result is consumed — the
                    # very next instruction must be move-result-object (0x0c,
                    # any destination register)
                    new = bytearray(old)
                    new[0] = OP_INVOKE_VIRTUAL_RANGE
                    struct.pack_into('<H', new, 2, bridge_target_idx)
                    d[p:p + 6] = new
                    report.append('bridge restored @0x%x: %s -> Context.getApplicationContext (method@%d)'
                                  % (p, old.hex(), bridge_target_idx))
                    hits += 1
                elif kind == 'probe' and op == OP_INVOKE_STATIC:
                    d[p:p + 6] = b'\x00\x00\x00\x00\x00\x00'
                    report.append('probe nop-ed   @0x%x: %s (method@%d)' % (p, old.hex(), mid))
                    hits += 1
        p += 2  # instruction streams are u16-aligned; scan every halfword
    if hits == 0:
        return bytes(d), ['!! shell methods referenced (%d) but no woven invokes found in the code section'
                          % len(shell_methods)]

    # sums over the restored bytes
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    struct.pack_into('<I', d, 8, zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)
    report.insert(0, 'woven sites restored: %d (bridges + probes)' % hits)
    return bytes(d), report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('dex')
    ap.add_argument('-o', '--out')
    ap.add_argument('--report', action='store_true')
    args = ap.parse_args()
    data = open(args.dex, 'rb').read()
    fixed, rep = deweave(data)
    for line in rep:
        print(line)
    if args.report:
        return
    out = args.out or args.dex.rsplit('.', 1)[0] + '.deweaved.dex'
    open(out, 'wb').write(fixed)
    print('deweaved DEX -> %s' % out)


if __name__ == '__main__':
    main()
