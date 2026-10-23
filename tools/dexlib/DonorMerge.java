import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.writer.pool.DexPool;

/**
 * DonorMerge: collapse N body-donor DEXes (mHook/FART per-dump or per-class
 * output — thousands of files are the norm) into ONE donor DEX carrying the
 * union of all donatable bodies, so the restore stage runs a single pass
 * instead of one pass per dump file.
 *
 * Donatable = has an implementation AND is not a nop wall (the same
 * information rule as Restore's donor side, finding #11: a shell-shaped
 * one-line delegate IS a genuine body and must survive the merge; any
 * bridge-reference impostor is rejected later by Restore's universe gate).
 * When several donors carry a body for the same class+signature the FIRST
 * donor in argument order wins (same-build dumps should agree anyway; a
 * disagreement is logged as a conflict count, never fatal).
 *
 * Two phases so thousands of inputs never exhaust file handles: phase 1
 * scans (in parallel) and records the winning donor index per method,
 * phase 2 reopens only donors that won at least one body and deep-copies
 * those bodies into immutable form before the merged write.
 *
 * `--universe <file>` (one shippable class per line, dotted or L-form —
 * e.g. the packed dex's class list) restricts the merge to classes the
 * repair target can actually contain. Without it a many-donor union can
 * overflow the 64k type-reference limit of a single DEX (empirical: a
 * 3062-donor mHook sweep unions >66k types — boot shadows, shell classes,
 * runtime strays) with bodies nobody can ever graft.
 *
 * Usage: java -cp ... DonorMerge <out.dex> [--universe universe.txt] <donor.dex | donor-dir>...
 */
public class DonorMerge {

    static boolean isNopWall(Method m) {
        MethodImplementation impl = m.getImplementation();
        if (impl == null) {
            return false;
        }
        int nops = 0, returns = 0;
        for (Instruction insn : impl.getInstructions()) {
            switch (insn.getOpcode()) {
                case NOP:
                    nops++;
                    break;
                case RETURN_VOID: case RETURN: case RETURN_WIDE: case RETURN_OBJECT:
                    returns++;
                    break;
                case CONST_4: case CONST_16: case CONST: case CONST_HIGH16:
                    if (((NarrowLiteralInstruction) insn).getNarrowLiteral() != 0) {
                        return false;
                    }
                    break;
                case CONST_WIDE_16: case CONST_WIDE_32: case CONST_WIDE:
                case CONST_WIDE_HIGH16:
                    if (((WideLiteralInstruction) insn).getWideLiteral() != 0L) {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
        }
        return nops >= 1 && returns >= 1;
    }

    static String sig(Method m) {
        return m.getName() + ":" + m.getReturnType() + ":" + m.getParameterTypes();
    }

    static List<File> expand(List<String> args) {
        List<File> out = new ArrayList<>();
        for (String a : args) {
            File f = new File(a);
            if (f.isDirectory()) {
                File[] dexes = f.listFiles((d, n) -> n.matches("classes\\d*\\.dex"));
                if (dexes != null) {
                    List<File> dl = new ArrayList<>();
                    Collections.addAll(dl, dexes);
                    dl.sort(Comparator.comparingInt(DonorMerge::dexOrder));
                    out.addAll(dl);
                }
            } else if (f.exists()) {
                out.add(f);
            } else {
                System.out.println("donormerge: source not found, skipped: " + f);
            }
        }
        return out;
    }

    static int dexOrder(File f) {
        String n = f.getName();
        String d = n.substring("classes".length(), n.length() - ".dex".length());
        return d.isEmpty() ? 1 : Integer.parseInt(d);
    }

    /** Phase-1 partial result for one donor. */
    static class Scan {
        int idx;
        boolean ok;
        // classType -> sig list of donatable methods
        Map<String, List<String>> donatable = new HashMap<>();
    }

    static Scan scan(File f, int idx, java.util.Set<String> universe) {
        Scan s = new Scan();
        s.idx = idx;
        try {
            DexFile dex = DexFileFactory.loadDexFile(f, Opcodes.getDefault());
            for (ClassDef c : dex.getClasses()) {
                if (universe != null && !universe.contains(c.getType())) {
                    continue; // not a class the repair target can ship
                }
                for (Method m : c.getMethods()) {
                    if (m.getImplementation() != null && !isNopWall(m)) {
                        s.donatable.computeIfAbsent(c.getType(), k -> new ArrayList<>())
                                  .add(sig(m));
                    }
                }
            }
            s.ok = true;
        } catch (Exception | Error e) {
            System.out.println("donormerge: unreadable donor " + f + " (" + e + ")");
        }
        return s;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--selftest".equals(args[0])) {
            selftest();
            return;
        }
        if (args.length < 2) {
            System.err.println("usage: DonorMerge <out.dex> [--universe universe.txt] <donor.dex | donor-dir>...");
            System.exit(2);
        }
        List<String> rest = new ArrayList<>();
        java.util.Set<String> universe = null;
        for (int i = 1; i < args.length; i++) {
            if ("--universe".equals(args[i]) && i + 1 < args.length) {
                universe = Restore.loadUniverse(new File(args[++i]));
            } else {
                rest.add(args[i]);
            }
        }
        List<File> donors = expand(rest);
        System.out.println("donormerge: " + donors.size() + " donor(s) to scan"
                + (universe != null ? ", universe=" + universe.size() + " classes" : ""));

        // ---- phase 1: parallel scan, merged INCREMENTALLY as each donor
        // completes (first = lowest-index donor wins); per-donor results are
        // released right after their merge — holding thousands of scans at
        // once OOMs (empirical: 3062-donor mHook sweep) ----
        ExecutorService pool = Executors.newFixedThreadPool(8);
        Map<String, Map<String, Integer>> methodWinner = new HashMap<>();
        long conflicts = 0;
        int unreadable = 0;
        int[] perDonorWins = new int[donors.size()];
        java.util.concurrent.ExecutorCompletionService<Scan> ecs =
                new java.util.concurrent.ExecutorCompletionService<>(pool);
        for (int i = 0; i < donors.size(); i++) {
            final int idx = i;
            final java.util.Set<String> uni = universe;
            ecs.submit(() -> scan(donors.get(idx), idx, uni));
        }
        for (int i = 0; i < donors.size(); i++) {
            Scan s = ecs.take().get();
            if (!s.ok) {
                unreadable++;
                continue;
            }
            for (Map.Entry<String, List<String>> e : s.donatable.entrySet()) {
                Map<String, Integer> wm = methodWinner.computeIfAbsent(e.getKey(), k -> new HashMap<>());
                for (String sg : e.getValue()) {
                    Integer cur = wm.get(sg);
                    if (cur == null) {
                        wm.put(sg, s.idx);
                        perDonorWins[s.idx]++;
                    } else {
                        conflicts++;
                        if (s.idx < cur) { // out-of-order completion: lowest index wins
                            wm.put(sg, s.idx);
                            perDonorWins[s.idx]++;
                            perDonorWins[cur]--;
                        }
                    }
                }
            }
            s.donatable.clear(); // release before the next completion arrives
        }
        pool.shutdown();
        if (conflicts > 0) {
            System.out.println("donormerge: " + conflicts + " duplicate "
                    + "class+signature bod(ies) across donors (lowest-index kept)");
        }

        // ---- phase 2: reopen only winners, deep-copy winning bodies ----
        Map<Integer, List<String>> donorWins = new TreeMap<>();
        for (Map.Entry<String, Map<String, Integer>> e : methodWinner.entrySet()) {
            for (Map.Entry<String, Integer> w : e.getValue().entrySet()) {
                donorWins.computeIfAbsent(w.getValue(), k -> new ArrayList<>())
                         .add(e.getKey() + " " + w.getKey());
            }
        }
        Map<String, ImmutableClassDef> baseClass = new HashMap<>();
        Map<String, Map<String, ImmutableMethod>> bodies = new HashMap<>();
        long copied = 0;
        for (Map.Entry<Integer, List<String>> e : donorWins.entrySet()) {
            int idx = e.getKey();
            DexFile dex = DexFileFactory.loadDexFile(donors.get(idx), Opcodes.getDefault());
            Map<String, List<String>> wanted = new HashMap<>();
            for (String key : e.getValue()) {
                int sp = key.indexOf(' ');
                wanted.computeIfAbsent(key.substring(0, sp), k -> new ArrayList<>())
                      .add(key.substring(sp + 1));
            }
            for (ClassDef c : dex.getClasses()) {
                // class attrs/fields come from the first REOPENED (winning)
                // donor that carries the class — the lowest-index donor that
                // contains it may hold walls only and never get reopened
                if (!baseClass.containsKey(c.getType())) {
                    baseClass.put(c.getType(), ImmutableClassDef.of(c));
                }
                List<String> want = wanted.get(c.getType());
                if (want == null) {
                    continue;
                }
                for (Method m : c.getMethods()) {
                    if (want.contains(sig(m))) {
                        bodies.computeIfAbsent(c.getType(), k -> new HashMap<>())
                              .put(sig(m), ImmutableMethod.of(m));
                        copied++;
                    }
                }
            }
        }

        // ---- emit: attrs/fields from the class-source donor, methods = the
        // winning bodies only (wall-only classes are dropped: nothing to give)
        DexPool out = new DexPool(Opcodes.getDefault());
        int classes = 0;
        for (Map.Entry<String, Map<String, ImmutableMethod>> e : bodies.entrySet()) {
            ImmutableClassDef base = baseClass.get(e.getKey());
            if (base == null) {
                continue;
            }
            out.internClass(new ImmutableClassDef(
                    base.getType(), base.getAccessFlags(), base.getSuperclass(),
                    base.getInterfaces(), base.getSourceFile(), base.getAnnotations(),
                    base.getFields(), new ArrayList<>(e.getValue().values())));
            classes++;
        }
        out.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(new File(args[0])));
        System.out.println("donormerge: " + donors.size() + " donors ("
                + unreadable + " unreadable) -> " + classes + " classes, "
                + copied + " bodies, " + conflicts + " conflict(s) first-wins, "
                + "winners=" + donorWins.size() + " -> " + args[0]);
    }

    /* ---------------- synthetic anchors (DonorMerge --selftest) ----------------
     * Two donors through the real CLI: donor1 carries a wall + a real body,
     * donor2 carries the same method real (conflict — first wins), another
     * real body, and a shell-shaped genuine delegate (must survive). */

    static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("DonorMerge --selftest FAILED: " + msg);
        }
    }

    static void selftest() throws Exception {
        Opcodes opcodes = Opcodes.getDefault();
        org.jf.dexlib2.iface.reference.MethodReference work =
                new org.jf.dexlib2.immutable.reference.ImmutableMethodReference(
                        "Lxt/Help;", "work", Collections.emptyList(), "V");

        Method wall = Restore.mk("Lxt/A;", "w", 1, Restore.insns(
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x(
                        org.jf.dexlib2.Opcode.NOP),
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x(
                        org.jf.dexlib2.Opcode.RETURN_VOID)));
        Method delegate = Restore.mk("Lxt/A;", "fw", 1, Restore.insns(
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction35c(
                        org.jf.dexlib2.Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, work),
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x(
                        org.jf.dexlib2.Opcode.RETURN_VOID)));
        // r1/r2: same signature, two different real consts — conflict
        Method r1 = Restore.mk("Lxt/A;", "r", 1, Restore.insns(
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n(
                        org.jf.dexlib2.Opcode.CONST_4, 0, 1),
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x(
                        org.jf.dexlib2.Opcode.RETURN_VOID)));
        Method r2 = Restore.mk("Lxt/A;", "r", 1, Restore.insns(
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n(
                        org.jf.dexlib2.Opcode.CONST_4, 0, 2),
                new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x(
                        org.jf.dexlib2.Opcode.RETURN_VOID)));

        File d1 = Files.createTempFile("donormerge-st-1", ".dex").toFile();
        File d2 = Files.createTempFile("donormerge-st-2", ".dex").toFile();
        File out = Files.createTempFile("donormerge-st-out", ".dex").toFile();
        d1.deleteOnExit();
        d2.deleteOnExit();
        out.deleteOnExit();
        writeOne(d1, opcodes, java.util.Arrays.asList(wall, r1, delegate));
        writeOne(d2, opcodes, java.util.Arrays.asList(r2));

        main(new String[]{out.getPath(), d1.getPath(), d2.getPath()});

        DexFile merged = DexFileFactory.loadDexFile(out, opcodes);
        int found = 0;
        for (ClassDef c : merged.getClasses()) {
            check(c.getType().equals("Lxt/A;"), "only the body-carrying class ships");
            for (Method m : c.getMethods()) {
                found++;
                if (m.getName().equals("w")) {
                    check(false, "nop wall must not survive the merge");
                }
                if (m.getName().equals("fw")) {
                    check(m.getImplementation().getInstructions().iterator().next()
                            .getOpcode() == org.jf.dexlib2.Opcode.INVOKE_STATIC,
                            "shell-shaped genuine delegate must survive the merge");
                }
                if (m.getName().equals("r")) {
                    for (Instruction i : m.getImplementation().getInstructions()) {
                        if (i instanceof NarrowLiteralInstruction) {
                            check(((NarrowLiteralInstruction) i).getNarrowLiteral() == 1,
                                    "conflict must resolve first-donor-wins (const 1)");
                        }
                    }
                }
            }
        }
        check(found == 2, "merged class carries exactly the two real bodies");
        System.out.println("DonorMerge --selftest: ALL GREEN "
                + "(wall dropped, delegate kept, conflict first-wins)");
    }

    static void writeOne(File f, Opcodes opcodes, List<Method> methods) throws Exception {
        DexPool pool = new DexPool(opcodes);
        pool.internClass(new ImmutableClassDef("Lxt/A;", 0x1, "Ljava/lang/Object;",
                Collections.<String>emptyList(), null, Collections.emptySet(),
                Collections.<org.jf.dexlib2.iface.Field>emptyList(), methods));
        pool.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(f));
    }
}
