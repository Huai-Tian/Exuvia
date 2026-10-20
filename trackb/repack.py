#!/usr/bin/env python3
"""Exuvia Track B: repack assembler v0 — the final assembly stage (README_AGENT §2.1).

Goal state: a behaviorally-identical installable APK. For the whole-file-encrypt
family (fence families.wholefile-encrypt) the recovered DEX is the intact
business code — no DEX writer is needed; assembly is zip re-composition:

  recovered DEX + original AndroidManifest.xml (the shell rewrote it) + base APK
  resources => repacked-unsigned.apk

Zero-distribution discipline: zipalign and apksigner (v2/v3) belong to the
user-side Android SDK — this tool deliberately stops at the unsigned package:

  zipalign -f -p 4 repacked-unsigned.apk aligned.apk
  apksigner sign --ks <keystore> --ks-key-alias <alias> \\
    --ks-pass pass:<pw> --key-pass pass:<pw> --out final.apk aligned.apk

Behavioral-parity note: repacking re-signs the APK by construction; a shell's
signature self-check (if present) failing after re-sign is the faithful-restoration
behavior, not a recovery defect (README_AGENT §2.1 signature clause).
"""

import argparse
import json
import sys
import zipfile


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--dex', required=True, help='recovered business DEX (the decrypt output, whole and intact)')
    ap.add_argument('--base', required=True, help='base APK providing resources/so/remaining entries')
    ap.add_argument('--manifest-from', help='APK whose AndroidManifest.xml to use (default: --base)')
    ap.add_argument('--prune', action='append', default=[],
                    help='substring — entries whose name contains it are dropped (e.g. shell assets)')
    ap.add_argument('--out', required=True, help='output APK path (unsigned)')
    args = ap.parse_args()

    manifest_src = zipfile.ZipFile(args.manifest_from) if args.manifest_from else None
    manifest = None
    if manifest_src is not None:
        manifest = manifest_src.read('AndroidManifest.xml')

    replaced_dex = open(args.dex, 'rb').read()
    if not replaced_dex.startswith(b'dex\n'):
        print('{"error":"E_STRUCT_INVALID","detail":"recovered DEX lacks dex magic — refuse to assemble"}')
        sys.exit(1)

    stats = {'entries': 0, 'copied': 0, 'pruned': 0, 'dex_replaced': 0, 'manifest_replaced': 0}
    with zipfile.ZipFile(args.base) as src, \
         zipfile.ZipFile(args.out, 'w', zipfile.ZIP_DEFLATED) as out:
        for info in src.infolist():
            name = info.filename
            stats['entries'] += 1
            if any(p in name for p in args.prune):
                stats['pruned'] += 1
                continue
            if name == 'AndroidManifest.xml' and manifest is not None:
                out.writestr(name, manifest)
                stats['manifest_replaced'] += 1
                continue
            if name.startswith('classes') and name.endswith('.dex'):
                stats['dex_replaced'] += 1
                continue  # base dex entries are dropped; the recovered DEX lands below
            if info.filename.endswith('/'):
                continue
            out.writestr(info, src.read(name))
            stats['copied'] += 1
        # the recovered business DEX lands as the (only) classes.dex
        zi = zipfile.ZipInfo('classes.dex')
        zi.compress_type = zipfile.ZIP_DEFLATED
        out.writestr(zi, replaced_dex)

    print(json.dumps({'out': args.out, **stats}, indent=2))


if __name__ == '__main__':
    main()
