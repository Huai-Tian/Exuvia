#!/usr/bin/env python3
"""repair_all.py — the ONE-COMMAND repair pipeline (third-party-dump friendly).

The industry gap this closes: dumpers (56.al, FART, frida hooks...) produce
DEX, but nobody repairs the APK so the dumped DEX actually LAUNCHES — the
shell's markers (the wrapper Application in the manifest, the stub dex, the
native loader assets) are still in the APK. This wraps the full pipeline:

  repair_all.py <packed.apk> <dumped.dex> -o <restored.apk> [--key k --cert c]

  0. DOCTOR  dexdoctor:  triage the dump for shell sabotage (zeroed checksums,
                          wiped map_off, page padding) and heal it — every
                          pathology must heal to structurally-clean DEX.
  1. CLEAN   dexclean:   classify the dumped DEX (shell stubs / foreign-app
                          pollution / R8-obfuscated app classes) and drop the
                          junk class_defs (map+checksum refixed).
  2. SURGERY repair:     parse the packed APK's binary manifest, remove the
                          <application android:name="WRAPPER"> attribute
                          (auto-detect or the definitive "the class is not in
                          the cleaned DEX" test), remove the shell's asset
                          entries, swap classes.dex.
  3. SIGN    sign2:      fresh APK v2 signature (RSASSA-PKCS1+SHA2-256), or a
                          provided key/cert pair.

All five stages are importable modules (dexdoctor / axmltool / dexclean /
sign2 / repair). Zero-sample policy: no sample knowledge embedded — the
wrapper patterns are generic and the definitive test is always the DEX
cross-reference.
"""
import argparse
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('packed')
    ap.add_argument('dumped_dex')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--key')
    ap.add_argument('--cert')
    ap.add_argument('--keep-shell-classes', action='store_true')
    args = ap.parse_args()

    import os
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dexclean
    import repair
    import sign2
    import dexdoctor

    # 0. triage the dump — third-party dumps arrive wounded (shell-sabotaged
    #    checksums, wiped map_off, page padding); heal before any parsing
    dump = open(args.dumped_dex, 'rb').read()
    tri = dexdoctor.Triage(dump, args.dumped_dex).diagnose()
    if tri.issues:
        dump = tri.fix()
        print('[doctor] wounds healed: %s' % '; '.join(tri.fixes))
    else:
        print('[doctor] dump healthy')

    # 1. clean
    dex = dexclean.Dex(dump)
    comps, pkg = dexclean.manifest_classes_from_apk(args.packed)
    keep, shell, foreign = dex.classify(pkg or '', comps)
    drops = [] if args.keep_shell_classes else [i for i, _, _ in shell] + [i for i, _, _ in foreign]
    if drops:
        cleaned = dex.clean(drops)
    else:
        cleaned = dump
    print('[clean] keep=%d shell=%d foreign=%d -> %s' % (len(keep), len(shell), len(foreign),
          'cleaned' if drops else 'already pure'))

    # 2. repair (reuse the module's main flow)
    import zipfile
    klasses = set(n for _, n, _ in keep)
    manifest = zipfile.ZipFile(args.packed).read('AndroidManifest.xml')
    surgery = repair.find_manifest_surgery(manifest, klasses)
    if surgery:
        attr_off, attr_size, chunk_off, chunk_csize, val = surgery
        manifest = repair.apply_surgery(manifest, attr_off, attr_size, chunk_off, chunk_csize)
        print('[surgery] removed android:name="%s"' % val)
    else:
        print('[surgery] no wrapper attribute found')
    dex_fixed, fixes = repair.dex_validate_fix(cleaned)
    if fixes:
        print('[dex-fix] %s' % ', '.join(fixes))
    removed = []
    with zipfile.ZipFile(args.out, 'w') as zo:
        for info in zipfile.ZipFile(args.packed).infolist():
            name = info.filename
            if name == 'AndroidManifest.xml':
                zo.writestr(name, manifest)
                continue
            if name == 'classes.dex':
                zo.writestr(name, dex_fixed)
                continue
            if any(p in name for p in repair.SHELL_ASSET_PATTERNS) and name.startswith('assets/'):
                removed.append(name)
                continue
            zo.writestr(info, zipfile.ZipFile(args.packed).read(name))
    print('[repair] shell assets removed: %d' % len(removed))

    # 3. sign
    data = open(args.out, 'rb').read()
    if args.key:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(open(args.key, 'rb').read(), password=None)
        cert_der = open(args.cert, 'rb').read()
    else:
        key, cert = sign2.gen_key_cert()
        cert_der = cert.public_bytes(sign2.serialization.Encoding.DER)
    signed = sign2.sign_v2(data, key, cert_der)
    open(args.out, 'wb').write(signed)
    print('[sign] v2 signed -> %s' % args.out)


if __name__ == '__main__':
    main()
