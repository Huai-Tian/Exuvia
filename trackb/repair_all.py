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
import os
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('packed')
    ap.add_argument('dumped_dex')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--key')
    ap.add_argument('--cert')
    ap.add_argument('--keep-shell-classes', action='store_true')
    ap.add_argument('--dump', action='append', metavar='DEX',
                    help='additional dump DEX (third-party dumps — FART, frida '
                    'hooks, earlier unpack-stage output) — shell-extracted '
                    'methods are restored from any source that carries the '
                    'body; may be given multiple times, sources are tried in '
                    'order and are complementary')
    ap.add_argument('--reference', help='reference DEX (the unpacked original — '
                    'INTERNAL TESTING ONLY; production runs have no original) — '
                    'same merge mechanism as --dump, highest-trust source')
    args = ap.parse_args()

    import os
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dexclean
    import repair
    import sign2
    import dexdoctor
    import deweave

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

    # 1.5 deweave: restore the shell's woven bytecode in place (invokes the
    # app makes to shell bridge/probe methods become the framework calls /
    # nops they were before the packer wove them). The restored DEX must
    # behave like the unpacked ORIGINAL — no shell classes, no shims.
    cleaned, weave_report = deweave.deweave(cleaned)
    if weave_report:
        print('[deweave] %s' % '; '.join(weave_report[:2]) + (' (+%d more lines)' % (len(weave_report) - 2) if len(weave_report) > 2 else ''))
        open(args.out + '.deweave.log', 'w').write('\n'.join(weave_report))
    else:
        print('[deweave] no shell weaving found')

    # 1.6 restore + stubsafe + repack (dexlib2).
    #
    # The shell's method EXTRACTION froze app methods as native+no-code stubs
    # (the real body lived in the runtime hook). The shell removed, such a
    # stub is lethal: the JNI hook is gone -> UnsatisfiedLinkError. Body
    # sources, tried in order:
    #   --dump      third-party dumps / earlier unpack-stage output — THE
    #               PRODUCTION PATH. A dump taken at the right moment carries
    #               decrypted bodies; several dumps are complementary.
    #   --reference the unpacked original — internal testing only.
    # Restore merges back every body any source carries. What NO source has
    # is handled by StubSafe:
    #   native + framework-lifecycle name  -> contract-equivalent super-delegate
    #   body synthesized (a legal native lifecycle override cannot exist — the
    #   template-method contract requires the super chain, so this is the
    #   shell's tell). Lethal stub state is eliminated; the app launches.
    #   native + no lifecycle contract    -> KEPT as-is: a legal JNI
    #   declaration backed by a .so still shipped in the APK is a necessary,
    #   side-effect-free leftover we reuse rather than re-invent.
    # The final stage re-serializes the whole DEX into a fresh, spec-standard
    # layout. Patching a memory-layout dump's map NEVER converges (ART's
    # padding/overlap/walk checks each reject the next irregularity);
    # re-serialization rebuilds every section compactly with a canonical map —
    # the same layout the smali ecosystem has shipped for two decades.
    # Semantics preserved (classes/methods/code/annotations).
    # heavy toolchain jars live user-side (workspace root /tools/dexlib) —
    # same policy as apktool.jar; the git repo ships only source
    repack_dir = os.environ.get('EXUVIA_DEXLIB', '/workspace/tools/dexlib')
    jars = 'dexlib2-2.5.2.jar:util-2.5.2.jar:guava-31.1-jre.jar:.'
    have_dexlib = os.path.exists(os.path.join(repack_dir, 'dexlib2-2.5.2.jar'))
    have_restore = have_dexlib and os.path.exists(os.path.join(repack_dir, 'Restore.class'))
    have_stubsafe = have_dexlib and os.path.exists(os.path.join(repack_dir, 'StubSafe.class'))
    have_repack = have_dexlib and os.path.exists(os.path.join(repack_dir, 'Repack.class'))

    sources = []
    for d in (args.dump or []):
        if os.path.exists(d):
            sources.append(('dump', d))
        else:
            print('[restore] dump source not found, skipped: %s' % d)
    if args.reference:
        if os.path.exists(args.reference):
            sources.append(('reference', args.reference))
        else:
            print('[restore] reference not found, skipped: %s' % args.reference)

    if have_dexlib:
        cur = args.out + '.stage.dex'
        open(cur, 'wb').write(cleaned)
        # restore: merge bodies from every source that carries them
        for kind, src in sources:
            if not have_restore:
                break
            nxt = args.out + '.stage_next.dex'
            r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                'Restore', cur, src, nxt],
                               cwd=repack_dir, capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and os.path.exists(nxt):
                os.remove(cur)
                cur = nxt
                for line in [l for l in (r.stdout + '').strip().split('\n') if l.strip()]:
                    print('[restore:%s] %s' % (kind, line))
            else:
                print('[restore:%s] FAILED on %s — continuing without it' % (kind, src))
                print(r.stdout + r.stderr)
        # stubsafe: synthesize contract-equivalent bodies for whatever lethal
        # stubs no source could fill; also the final standard-layout repack
        if have_stubsafe:
            nxt = args.out + '.stage_final.dex'
            r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                'StubSafe', cur, nxt],
                               cwd=repack_dir, capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and os.path.exists(nxt):
                os.remove(cur)
                cleaned = open(nxt, 'rb').read()
                os.remove(nxt)
                for line in [l for l in (r.stdout + '').strip().split('\n') if l.strip()]:
                    print('[stubsafe] %s' % line)
                print('[stubsafe] dexlib2 standard layout (%d bytes)' % len(cleaned))
            else:
                print('[stubsafe] FAILED — falling back to the restore-stage DEX')
                print(r.stdout + r.stderr)
                cleaned = open(cur, 'rb').read()
                os.remove(cur)
        elif have_repack:
            # legacy fallback when StubSafe.class is absent
            nxt = args.out + '.stage_final.dex'
            r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                'Repack', cur, nxt],
                               cwd=repack_dir, capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and os.path.exists(nxt):
                os.remove(cur)
                cleaned = open(nxt, 'rb').read()
                os.remove(nxt)
                print('[repack] dexlib2 standard layout (%d bytes)' % len(cleaned))
            else:
                print('[repack] FAILED — falling back to the patched dump layout')
                print(r.stdout + r.stderr)
                cleaned = open(cur, 'rb').read()
                os.remove(cur)
        else:
            cleaned = open(cur, 'rb').read()
            os.remove(cur)
            print('[repack] dexlib2 tools unavailable — using the patched dump layout')
    else:
        print('[repack] dexlib2 not available — using the patched dump layout')

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
    # zipalign semantics (the R+ install gate): every entry's DATA section
    # 4-byte aligned via local-header extra-field padding, resources.arsc
    # kept STORED. Python's zipfile never aligns — an unaligned arsc is
    # REJECTED on Android 11+ with "-124 Failed parse during installPackageLI".
    with zipfile.ZipFile(args.out, 'w') as zo:
        zin = zipfile.ZipFile(args.packed)
        for info in zin.infolist():
            name = info.filename
            if any(p in name for p in repair.SHELL_ASSET_PATTERNS) and name.startswith('assets/'):
                removed.append(name)
                continue
            if name == 'AndroidManifest.xml':
                content = manifest
            elif name == 'classes.dex':
                content = dex_fixed
            else:
                content = zin.read(name)
            if name == 'resources.arsc':
                info.compress_type = zipfile.ZIP_STORED  # R+ requires uncompressed
            # predict the local header: [30B fixed][name][extra] -> align data
            # (replace extra with pure padding, zipalign-style — never append
            # behind a possibly-structured extra)
            while True:
                data_off = zo.fp.tell() + 30 + len(info.filename) + len(info.extra)
                need = (-data_off) % 4
                if not need:
                    break
                info.extra = b'\x00' * (len(info.extra) + need)
            zo.writestr(info, content)
    print('[repair] shell assets removed: %d (all entries 4-byte aligned)' % len(removed))

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
