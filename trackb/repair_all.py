#!/usr/bin/env python3
"""repair_all.py — the ONE-COMMAND repair pipeline (third-party-dump friendly).

The industry gap this closes: dumpers (56.al, FART, frida hooks...) produce
DEX, but nobody repairs the APK so the dumped DEX actually LAUNCHES — the
shell's markers (the wrapper Application in the manifest, the stub dex, the
native loader assets) are still in the APK. This wraps the full pipeline:

  repair_all.py <packed.apk> <dump...> -o <restored.apk> [--key k --cert c]

  <dump> is one or more of: a .dex file, a directory of classes*.dex, or a
  dump container (inner APK / zip) carrying classes*.dex — memory dumps of a
  running process arrive as multi-dex sets, and several dumps are
  complementary. Every dump dex is triaged, cleaned, dewoven, restored and
  re-serialized individually; dexes that carry no app classes (shell stub
  dexes, boot-framework pollution a full-process dump captures) are dropped,
  the survivors ship as classes.dex, classes2.dex, ... in order.

  0. DOCTOR  dexdoctor:  triage the dump for shell sabotage (zeroed checksums,
                          wiped map_off, page padding) and heal it — every
                          pathology must heal to structurally-clean DEX.
  1. CLEAN   dexclean:   classify the dumped DEX (shell stubs / foreign-app
                          pollution / R8-obfuscated app classes) and drop the
                          junk class_defs (map+checksum refixed). A whole dex
                          carrying zero app classes is dropped entirely —
                          full-process memory dumps pick up boot-classpath
                          shadow dexes (android.*/com.android.*/java.*, all
                          resolved parent-first from the boot image; the
                          360-family fulldump's classes2-6 were 2900+ such
                          classes), and shell stub dexes the same. Mixed
                          dexes keep their boot-prefixed classes: androidx
                          back-compat stubs under android.* are real app
                          classes the original APK also ships.
  2. SURGERY repair:     parse the packed APK's binary manifest, remove the
                          <application android:name="WRAPPER"> attribute
                          (auto-detect or the definitive "the class is not in
                          the cleaned DEX" test, over the UNION of all
                          surviving dexes), remove the shell's asset entries,
                          swap classes.dex, classes2.dex, ... (any extra
                          classesN.dex the packed APK carried are dropped).
  3. SIGN    sign2:      fresh APK v2 signature (RSASSA-PKCS1+SHA2-256), or a
                          provided key/cert pair.

All five stages are importable modules (dexdoctor / axmltool / dexclean /
sign2 / repair). Zero-sample policy: no sample knowledge embedded — the
wrapper patterns are generic and the definitive test is always the DEX
cross-reference.
"""
import argparse
import os
import re
import subprocess
import sys
import zipfile

# Boot-classpath packages: resolved by parent-first delegation from the boot
# image at runtime, so a copy inside a memory dump is pollution, never a
# class the APK must ship. kotlin.*/androidx.* are NOT here — real apps ship
# those in their own dexes. The exemptions cover the legacy app-shipped
# packages that live under an otherwise-boot prefix.
BOOT_PREFIXES = (
    'android.', 'com.android.', 'java.', 'javax.', 'sun.', 'com.sun.',
    'dalvik.', 'libcore.', 'org.w3c.', 'org.xml.', 'org.xmlpull.', 'org.ietf.',
)
BOOT_EXEMPT = (
    'android.support.', 'android.arch.', 'android.databinding.',
    'javax.annotation.', 'javax.inject.',
)


def is_boot_class(name):
    return (name.startswith(BOOT_PREFIXES)
            and not name.startswith(BOOT_EXEMPT))


_DEXN_RE = re.compile(r'^classes(\d*)\.dex$')


def dex_order(name):
    """classes.dex < classes2.dex < classes3.dex < ... (natural order)."""
    m = _DEXN_RE.match(name)
    return int(m.group(1) or 1) if m else 0


def expand_dex_inputs(path):
    """One CLI value -> ordered [(label, dex_bytes)].

    Accepts a single .dex file, a directory of classes*.dex, or a zip
    container (inner dump APK) carrying classes*.dex entries. Memory dumps
    of a running process arrive in all three shapes."""
    if os.path.isdir(path):
        names = sorted((n for n in os.listdir(path) if _DEXN_RE.match(n)),
                       key=dex_order)
        if not names:
            print('[expand] no classes*.dex in directory, skipped: %s' % path)
            return []
        return [('%s/%s' % (path, n), open(os.path.join(path, n), 'rb').read())
                for n in names]
    if zipfile.is_zipfile(path):
        out = []
        with zipfile.ZipFile(path) as z:
            names = sorted((n for n in z.namelist()
                            if _DEXN_RE.match(os.path.basename(n))),
                           key=lambda n: dex_order(os.path.basename(n)))
            for n in names:
                out.append(('%s!%s' % (path, n), z.read(n)))
        if not out:
            print('[expand] no classes*.dex in container, skipped: %s' % path)
        return out
    if os.path.exists(path):
        return [(path, open(path, 'rb').read())]
    print('[expand] source not found, skipped: %s' % path)
    return []


def restore_stage_path(out, di, si):
    """Per-(stage-dex, source) restore temp name. Both dimensions are
    required: a name indexed by the stage dex alone is shared by every
    --dump source, so from the second source on the restore input and
    output are the SAME file — the success cleanup (os.remove of the
    previous input) then deletes the very file the chain continues from,
    and every later source plus StubSafe dies on DexFileNotFound.
    Empirical (family-3 爱加密, 7-donor mHook dump): donor 1 merged fine,
    the whole chain collapsed behind it."""
    return '%s.stage_next%d_%d.dex' % (out, di, si)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('packed')
    ap.add_argument('dumped', nargs='+', metavar='DUMP',
                    help='dump .dex / directory / container (repeatable)')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--key')
    ap.add_argument('--cert')
    ap.add_argument('--keep-shell-classes', action='store_true')
    ap.add_argument('--extra-dex', action='append', metavar='DEX',
                    help='pass-through dex appended AFTER the repaired dump '
                    'dexes as-is (e.g. a trace2smali-synthesized, smali-'
                    'assembled dex that must not be re-serialized); may be '
                    'given multiple times, order preserved')
    ap.add_argument('--dump', action='append', metavar='DEX',
                    help='additional dump DEX (third-party dumps — FART, frida '
                    'hooks, earlier unpack-stage output) — shell-extracted '
                    'methods are restored from any source that carries the '
                    'body; may be given multiple times, sources are tried in '
                    'order and are complementary; each value may itself be a '
                    'dex / directory / container. A large dump SET (mHook/'
                    'FART per-class output runs to thousands of dexes — one '
                    'restore pass each) should be collapsed first: '
                    'DonorMerge out.dex <dir> merges every donatable body '
                    'into a single donor (finding #11)')
    ap.add_argument('--reference', help='reference DEX (the unpacked original — '
                    'INTERNAL TESTING ONLY; production runs have no original) — '
                    'same merge mechanism as --dump, highest-trust source')
    args = ap.parse_args()

    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dexclean
    import repair
    import sign2
    import dexdoctor
    import deweave

    comps, pkg = dexclean.manifest_classes_from_apk(args.packed)

    # stages 0-1.5 per dump dex: doctor -> clean (+boot-pollution drop) ->
    # deweave. Dexes with no surviving app classes are dropped whole.
    stage_dexes = []   # (label, cleaned bytes, kept class list)
    weave_log = []
    for label, dump in (e for p in args.dumped for e in expand_dex_inputs(p)):
        # 0. triage the dump — third-party dumps arrive wounded (shell-
        #    sabotaged checksums, wiped map_off, page padding); heal first
        tri = dexdoctor.Triage(dump, label).diagnose()
        if tri.issues:
            dump = tri.fix()
            print('[doctor:%s] wounds healed: %s' % (label, '; '.join(tri.fixes)))
        else:
            print('[doctor:%s] dump healthy' % label)

        # 1. clean
        dex = dexclean.Dex(dump)
        keep, shell, foreign = dex.classify(pkg or '', comps)
        # Whole-dex pollution verdict: a dump dex carrying ZERO app classes
        # (everything it holds is a boot-classpath shadow — parent-first
        # delegation resolves those from the boot image, and a boot copy is
        # API-level-specific dead weight a shipped APK must never contain) or
        # only shell/foreign junk is dropped ENTIRELY. Mixed dexes keep
        # their boot-PREFIXED classes: androidx ships android.* back-compat
        # stubs (OnBackInvokedCallback & friends) the original APK also
        # carries — dropping those class-by-class would murder real app
        # classes (regression-verified against the original release).
        boot = [(i, n, o) for i, n, o in keep if is_boot_class(n)]
        app = [(i, n, o) for i, n, o in keep if not is_boot_class(n)]
        if not app and (boot or shell or foreign):
            print('[clean:%s] app=0 boot=%d shell=%d foreign=%d -> pollution '
                  'dex dropped whole' % (label, len(boot), len(shell), len(foreign)))
            continue
        drops = [] if args.keep_shell_classes else [i for i, _, _ in shell] + [i for i, _, _ in foreign]
        if drops:
            cleaned = dex.clean(drops)
        else:
            cleaned = dump
        print('[clean:%s] keep=%d (%d boot-prefixed) shell=%d foreign=%d -> %s'
              % (label, len(keep), len(boot), len(shell), len(foreign),
                 'cleaned' if drops else 'already pure'))

        # 1.5 deweave: restore the shell's woven bytecode in place (invokes
        # the app makes to shell bridge/probe methods become the framework
        # calls / nops they were before the packer wove them).
        cleaned, weave_report = deweave.deweave(cleaned)
        if weave_report:
            print('[deweave:%s] %s' % (label, '; '.join(weave_report[:2]) + (' (+%d more lines)' % (len(weave_report) - 2) if len(weave_report) > 2 else '')))
            weave_log.append('== %s ==' % label)
            weave_log.extend(weave_report)
        else:
            print('[deweave:%s] no shell weaving found' % label)
        stage_dexes.append([label, cleaned, keep])
    if weave_log:
        open(args.out + '.deweave.log', 'w').write('\n'.join(weave_log))
    if not stage_dexes:
        sys.exit('[repair] no app-carrying dex survived triage — nothing to ship')

    # 1.6 restore + stubsafe + repack (dexlib2), per dex.
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
        sources += [('dump', lbl, b) for lbl, b in expand_dex_inputs(d)]
    if args.reference:
        sources += [('reference', lbl, b)
                    for lbl, b in expand_dex_inputs(args.reference)]
    # Restore reads sources from disk — expanded bytes go to per-run temps
    src_paths = []
    for kind, lbl, b in sources:
        sp = args.out + '.src%d.dex' % len(src_paths)
        open(sp, 'wb').write(b)
        src_paths.append((kind, lbl, sp))

    # shippable-class universe for Restore's donor reference gate (finding
    # #11): a donor body calling into a class that ships nowhere (a packer
    # bridge cleaned away) must stay an honest wall, not become a dangling
    # call that NoSuchMethodErrors at runtime
    universe_path = args.out + '.universe.txt'
    with open(universe_path, 'w') as uf:
        for _, _, keep in stage_dexes:
            for _, n, _ in keep:
                uf.write(n + '\n')

    if have_dexlib:
        for di, (label, cleaned, keep) in enumerate(stage_dexes):
            cur = args.out + '.stage%d.dex' % di
            open(cur, 'wb').write(cleaned)
            # restore: merge bodies from every source that carries them
            for si, (kind, lbl, sp) in enumerate(src_paths):
                if not have_restore:
                    break
                nxt = restore_stage_path(args.out, di, si)
                r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                    'Restore', cur, sp, nxt, universe_path],
                                   cwd=repack_dir, capture_output=True, text=True, timeout=600)
                if r.returncode == 0 and os.path.exists(nxt):
                    os.remove(cur)
                    cur = nxt
                    for line in [l for l in (r.stdout + '').strip().split('\n') if l.strip()]:
                        print('[restore:%s:%s] %s' % (kind, lbl, line))
                else:
                    print('[restore:%s:%s] FAILED on %s — continuing without it' % (kind, lbl, label))
                    print(r.stdout + r.stderr)
            # stubsafe: synthesize contract-equivalent bodies for whatever
            # lethal stubs no source could fill; also the final standard-
            # layout repack
            if have_stubsafe:
                nxt = args.out + '.stage_final%d.dex' % di
                r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                    'StubSafe', cur, nxt],
                                   cwd=repack_dir, capture_output=True, text=True, timeout=600)
                if r.returncode == 0 and os.path.exists(nxt):
                    os.remove(cur)
                    cleaned = open(nxt, 'rb').read()
                    os.remove(nxt)
                    for line in [l for l in (r.stdout + '').strip().split('\n') if l.strip()]:
                        print('[stubsafe:%s] %s' % (label, line))
                    print('[stubsafe:%s] dexlib2 standard layout (%d bytes)' % (label, len(cleaned)))
                else:
                    print('[stubsafe:%s] FAILED — falling back to the restore-stage DEX' % label)
                    print(r.stdout + r.stderr)
                    cleaned = open(cur, 'rb').read()
                    os.remove(cur)
            elif have_repack:
                # legacy fallback when StubSafe.class is absent
                nxt = args.out + '.stage_final%d.dex' % di
                r = subprocess.run(['java', '-Xmx2g', '-cp', jars,
                                    'Repack', cur, nxt],
                                   cwd=repack_dir, capture_output=True, text=True, timeout=600)
                if r.returncode == 0 and os.path.exists(nxt):
                    os.remove(cur)
                    cleaned = open(nxt, 'rb').read()
                    os.remove(nxt)
                    print('[repack:%s] dexlib2 standard layout (%d bytes)' % (label, len(cleaned)))
                else:
                    print('[repack:%s] FAILED — falling back to the patched dump layout' % label)
                    print(r.stdout + r.stderr)
                    cleaned = open(cur, 'rb').read()
                    os.remove(cur)
            else:
                cleaned = open(cur, 'rb').read()
                os.remove(cur)
                print('[repack:%s] dexlib2 tools unavailable — using the patched dump layout' % label)
            stage_dexes[di][1] = cleaned
    else:
        print('[repack] dexlib2 not available — using the patched dump layout')
    for _, _, sp in src_paths:
        if os.path.exists(sp):
            os.remove(sp)
    if os.path.exists(universe_path):
        os.remove(universe_path)

    # 2. repair (reuse the module's main flow). The definitive wrapper test
    #    cross-references the UNION of every surviving dex's classes.
    klasses = set(n for _, _, keep in stage_dexes for _, n, _ in keep)
    manifest = zipfile.ZipFile(args.packed).read('AndroidManifest.xml')
    surgery = repair.find_manifest_surgery(manifest, klasses)
    if surgery:
        for attr_off, _size, _co, _cs, aname, val in surgery:
            print('[surgery] removed android:%s="%s" (attr @0x%x)' % (aname, val, attr_off))
        manifest = repair.apply_surgery(manifest, surgery)
    else:
        print('[surgery] no wrapper launch attribute found')
    for di, (label, cleaned, _) in enumerate(stage_dexes):
        dex_fixed, fixes = repair.dex_validate_fix(cleaned)
        if fixes:
            print('[dex-fix:%s] %s' % (label, ', '.join(fixes)))
        stage_dexes[di][1] = dex_fixed
    extra = []
    for d in (args.extra_dex or []):
        if os.path.exists(d):
            extra.append((d, open(d, 'rb').read()))
        else:
            print('[extra-dex] not found, skipped: %s' % d)
    ship = [b for _, b, _ in stage_dexes] + [b for _, b in extra]
    ship_names = ['classes.dex'] + ['classes%d.dex' % i
                                    for i in range(2, len(ship) + 1)]
    removed = []
    # zipalign semantics (the R+ install gate): every entry's DATA section
    # 4-byte aligned via local-header extra-field padding, resources.arsc
    # kept STORED. Python's zipfile never aligns — an unaligned arsc is
    # REJECTED on Android 11+ with "-124 Failed parse during installPackageLI".
    with zipfile.ZipFile(args.out, 'w') as zo:
        zin = zipfile.ZipFile(args.packed)
        dex_written = False
        for info in zin.infolist():
            name = info.filename
            if repair.is_shell_asset(name):
                removed.append(name)
                continue
            if _DEXN_RE.match(name):
                # every packed classesN.dex is replaced by the repaired set,
                # written once at the first dex slot (extras dropped); the
                # first shipped dex reuses the packed entry's own ZipInfo
                # (single-dex runs then reproduce the historical zip exactly)
                if dex_written:
                    removed.append(name)
                    continue
                dex_written = True
                for sname, content in zip(ship_names, ship):
                    if sname == name:
                        sinfo = info
                    else:
                        sinfo = zipfile.ZipInfo(sname, date_time=info.date_time)
                        sinfo.compress_type = info.compress_type
                        sinfo.external_attr = info.external_attr
                        sinfo.create_system = info.create_system
                    while True:
                        data_off = zo.fp.tell() + 30 + len(sinfo.filename) + len(sinfo.extra)
                        need = (-data_off) % 4
                        if not need:
                            break
                        sinfo.extra = b'\x00' * (len(sinfo.extra) + need)
                    zo.writestr(sinfo, content)
                continue
            if name == 'AndroidManifest.xml':
                content = manifest
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
        if not dex_written:
            for sname, content in zip(ship_names, ship):
                sinfo = zipfile.ZipInfo(sname)
                while True:
                    data_off = zo.fp.tell() + 30 + len(sinfo.filename) + len(sinfo.extra)
                    need = (-data_off) % 4
                    if not need:
                        break
                    sinfo.extra = b'\x00' * (len(sinfo.extra) + need)
                zo.writestr(sinfo, content)
    print('[repair] shell assets removed: %d; shipped dexes: %s (all entries 4-byte aligned)'
          % (len(removed), ', '.join(ship_names)))

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
