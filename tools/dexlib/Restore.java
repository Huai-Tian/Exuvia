import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.FiveRegisterInstruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.RegisterRangeInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.VariableRegisterInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.iface.reference.TypeReference;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableDexFile;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11x;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction35c;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.writer.pool.DexPool;

/**
 * Restore: merge method bodies for shell-extracted stubs from every source
 * that carries them (SKILL §7 restore stage).
 *
 * A packer's method extraction/VMP freezes app methods as `native + no
 * code_item` (or otherwise implementation-less): the body lived in the
 * shell's runtime hook. A second family shape (extraction + nop-fill —
 * 爱加密-style) instead leaves a LEGAL code_item whose body is a nop wall:
 * every instruction is a nop, a zero-literal const, or a return — the
 * original body was gutted and its size padded with nops. Both shapes are
 * equally empty; a dump/reference/earlier-stage DEX that carries the same
 * class+signature WITH a real body donates it. Sources are tried in order
 * (the pipeline invokes Restore once per source); the first source carrying
 * a body wins — methods that already have a REAL implementation are never
 * touched, abstract declarations are never given bodies, and a source body
 * that is itself hollow is never donated (a wall over a wall restores
 * nothing).
 *
 * A third family shape (empirical, family-3 爱加密): framework-callback
 * overrides keep a PURE FORWARDING SHELL — exactly one invoke and one
 * return, optionally with move-result value plumbing between them (an 8B
 * `onCreate() { super.onCreate(); }` standing in for a real 104B body).
 * Not a nop-wall, so a wall-only predicate never fills it; the target-side
 * fillable predicate therefore treats a forwarding shell as hollow too.
 *
 * Donor-side the rule is INFORMATION, not shape (finding #11): a real
 * one-line delegate (`return WindowInsets.Type.statusBars();`,
 * `c.setSystemBarsAppearance(i, i);`) is shell-SHAPED while being the
 * genuine body — rejecting shell-shaped donors wholesale starves exactly
 * the walls those delegates fill (a wall target is already proof of
 * extraction; any non-wall donor body is a strict information gain). So a
 * source body is rejected only when it cannot carry information or cannot
 * run in the product:
 *   - it is itself a nop wall (a wall over a wall restores nothing);
 *   - it is INSTRUCTION-IDENTICAL to the body it would replace (the same
 *     shell on both sides — grafting would only fake the restored count);
 *   - with a universe file, any reference inside the donor body dangles
 *     against the shippable class set + boot classpath (a packer bridge
 *     call would otherwise be imported into a product where the bridge
 *     class was cleaned away — NoSuchMethodError at runtime).
 *
 * The grafted body keeps the source method's implementation and access
 * flags (ACC_NATIVE cleared — a restored body is Dalvik again); everything
 * else comes from the primary class definition. DexPool re-interns all
 * cross-dex references, so the output is a fresh standard-layout DEX.
 *
 * Usage: java -cp ... Restore <in.dex> <source.dex> <out.dex> [universe.txt] [api]
 *   universe.txt — one shippable class per line (dotted or L-form); when
 *   given, donor bodies carrying dangling references are rejected. When
 *   absent the gate is OFF (standalone use) and a warning is printed.
 */
public class Restore {
    static final int ACC_NATIVE = 0x100;
    static final int ACC_ABSTRACT = 0x400;

    static String sig(Method m) {
        return m.getName() + ":" + m.getReturnType() + ":" + m.getParameterTypes();
    }

    /**
     * Nop-wall predicate: the extraction+nop-fill family's gutted body.
     * True when the implementation's instructions are EXCLUSIVELY nops,
     * zero-literal consts (the packer's null/false/0/0L return feed) and
     * returns, with at least one nop — a legit empty method is exactly
     * `return-void` (zero nops) and a real body never carries a trailing
     * nop wall (compilers emit no dead code). A residual try table does NOT
     * disqualify: this family keeps the try structure while gutting handler
     * code to nops too — and the instruction scan already covers handler
     * code (a real handler would trip the default case). Restore grafts the
     * source implementation wholesale, so the wall's try table is discarded
     * with it. Purely structural: no family-specific constants.
     */
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
                case RETURN_VOID:
                case RETURN:
                case RETURN_WIDE:
                case RETURN_OBJECT:
                    returns++;
                    break;
                case CONST_4:
                case CONST_16:
                case CONST:
                case CONST_HIGH16:
                    if (((NarrowLiteralInstruction) insn).getNarrowLiteral() != 0) {
                        return false;
                    }
                    break;
                case CONST_WIDE_16:
                case CONST_WIDE_32:
                case CONST_WIDE:
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

    /**
     * Pure-forwarding-shell predicate: exactly one invoke-* and one return,
     * with nothing else in the body (move-result* between them is value
     * plumbing from the invoke to the return). The extraction family's
     * shape for gutted framework-callback overrides that must stay callable
     * before re-materialization; the try-table reasoning from isNopWall
     * applies verbatim (grafting replaces the implementation wholesale).
     * Purely structural: no family-specific constants.
     */
    static boolean isForwardingShell(Method m) {
        MethodImplementation impl = m.getImplementation();
        if (impl == null) {
            return false;
        }
        int invokes = 0, returns = 0;
        for (Instruction insn : impl.getInstructions()) {
            switch (insn.getOpcode()) {
                case INVOKE_VIRTUAL:
                case INVOKE_SUPER:
                case INVOKE_DIRECT:
                case INVOKE_STATIC:
                case INVOKE_INTERFACE:
                case INVOKE_VIRTUAL_RANGE:
                case INVOKE_SUPER_RANGE:
                case INVOKE_DIRECT_RANGE:
                case INVOKE_STATIC_RANGE:
                case INVOKE_INTERFACE_RANGE:
                    invokes++;
                    break;
                case MOVE_RESULT:
                case MOVE_RESULT_WIDE:
                case MOVE_RESULT_OBJECT:
                    break;
                case RETURN_VOID:
                case RETURN:
                case RETURN_WIDE:
                case RETURN_OBJECT:
                    returns++;
                    break;
                default:
                    return false;
            }
        }
        return invokes == 1 && returns == 1;
    }

    /**
     * Hollow = nothing to donate / everything to gain. Applied
     * SYMMETRICALLY: a target is fillable when hollow; a source body is
     * donatable only when NOT hollow. The symmetry is the safety proof —
     * a genuinely trivial method is hollow on both sides, so it can never
     * be "restored" (a graft would fake the count without changing
     * semantics), while an extracted shell is hollow on the target side
     * but carries a real body on the source side.
     */
    static boolean isHollowShell(Method m) {
        return isNopWall(m) || isForwardingShell(m);
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--selftest".equals(args[0])) {
            selftest();
            return;
        }
        if (args.length < 3) {
            System.err.println("usage: Restore <in.dex> <source.dex> <out.dex> [universe.txt] [api]");
            System.err.println("       Restore --selftest   (synthetic predicate + graft anchors)");
            System.exit(2);
        }
        Opcodes opcodes = Opcodes.getDefault();
        Set<String> universe = null;
        for (int i = 3; i < args.length; i++) {
            if (args[i].matches("\\d+")) {
                opcodes = Opcodes.forApi(Integer.parseInt(args[i]));
            } else {
                universe = loadUniverse(new File(args[i]));
            }
        }
        if (universe == null) {
            System.err.println("restore: no universe file — donor reference "
                    + "gating OFF (dangling-bridge imports unchecked)");
        }

        DexFile in = DexFileFactory.loadDexFile(new File(args[0]), opcodes);
        DexFile src = DexFileFactory.loadDexFile(new File(args[1]), opcodes);

        // index the source: class -> sig -> method carrying a donatable body.
        // Donor-side rejection is by INFORMATION, not shape (finding #11): a
        // nop wall donates nothing, but a shell-SHAPED one-line delegate is a
        // genuine body — a wall target is already proof of extraction, so any
        // non-wall donor body is a strict gain. Shell-bridge impostors are
        // caught at graft time by the reference-universe gate instead.
        Map<String, Map<String, Method>> srcIdx = new HashMap<>();
        for (ClassDef c : src.getClasses()) {
            for (Method m : c.getMethods()) {
                if (m.getImplementation() != null && !isNopWall(m)) {
                    srcIdx.computeIfAbsent(c.getType(), k -> new HashMap<>())
                          .put(sig(m), m);
                }
            }
        }

        int restored = 0, skipIdentical = 0, skipUnresolved = 0;
        List<ClassDef> outClasses = new ArrayList<>();
        for (ClassDef c : in.getClasses()) {
            Map<String, Method> smap = srcIdx.get(c.getType());
            if (smap == null) {
                outClasses.add(c);
                continue;
            }
            List<Method> patched = new ArrayList<>();
            boolean changed = false;
            for (Method m : c.getMethods()) {
                // fillable = no body at all (extraction stub) OR a hollow
                // body: a nop-wall (extraction+nop-fill: a legal code_item
                // whose gutted body verifies as a no-op) or a pure
                // forwarding shell (the gutted callback kept callable as
                // invoke+return). Real bodies are never touched.
                boolean nopWall = isNopWall(m);
                boolean fwdShell = !nopWall && isForwardingShell(m);
                boolean fillable = (m.getAccessFlags() & ACC_ABSTRACT) == 0
                        && (m.getImplementation() == null || nopWall || fwdShell);
                Method sm = fillable ? smap.get(sig(m)) : null;
                if (sm != null && bodiesIdentical(sm, m)) {
                    // the same body on both sides carries no information —
                    // grafting would only fake the restored count
                    skipIdentical++;
                    sm = null;
                }
                if (sm != null && universe != null && !refsResolvable(sm, universe)) {
                    skipUnresolved++;
                    System.out.println("restore-skip-unresolved " + c.getType()
                            + "->" + m.getName() + m.getParameterTypes()
                            + " (donor body references classes outside the shippable set)");
                    sm = null;
                }
                if (sm != null) {
                    patched.add(new ImmutableMethod(
                            c.getType(), sm.getName(), sm.getParameters(),
                            sm.getReturnType(),
                            sm.getAccessFlags() & ~ACC_NATIVE,
                            sm.getAnnotations(), sm.getHiddenApiRestrictions(),
                            sm.getImplementation()));
                    restored++;
                    System.out.println("restored " + c.getType() + "->"
                            + m.getName() + m.getParameterTypes()
                            + (nopWall ? " (nop-wall body replaced from source)"
                               : fwdShell ? " (forwarding-shell body replaced from source)"
                                          : " (body merged from source)"));
                    changed = true;
                } else {
                    patched.add(m);
                }
            }
            if (changed) {
                List<org.jf.dexlib2.iface.Field> allFields = new ArrayList<>();
                for (org.jf.dexlib2.iface.Field f : c.getFields()) {
                    allFields.add(f);
                }
                outClasses.add(new ImmutableClassDef(
                        c.getType(), c.getAccessFlags(), c.getSuperclass(),
                        c.getInterfaces(), c.getSourceFile(), c.getAnnotations(),
                        allFields, patched));
            } else {
                outClasses.add(c);
            }
        }

        DexPool pool = new DexPool(opcodes);
        for (ClassDef c : outClasses) {
            pool.internClass(c);
        }
        pool.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(new File(args[2])));
        System.out.println("restore: " + restored + " method body/bodies merged"
                + (skipIdentical > 0 ? ", " + skipIdentical + " identical-skip" : "")
                + (skipUnresolved > 0 ? ", " + skipUnresolved + " unresolved-ref-skip" : "")
                + " -> " + args[2]);
    }

    /* ---------------- donor admissibility gates (finding #11) ---------------- */

    /** Boot-classpath prefixes — mirrored from repair_all.is_boot_class so
     *  reference gating uses the exact same rule as the cleaner. A donor ref
     *  to a boot type resolves at runtime from the boot image; anything else
     *  must be in the shippable class set. */
    static final String[] BOOT_PREFIXES = {
        "android.", "com.android.", "java.", "javax.", "sun.", "com.sun.",
        "dalvik.", "libcore.", "org.w3c.", "org.xml.", "org.xmlpull.", "org.ietf.",
    };
    static final String[] BOOT_EXEMPT = {
        "android.support.", "android.arch.", "android.databinding.",
        "javax.annotation.", "javax.inject.",
    };

    static boolean isBootType(String type) {
        if (!type.startsWith("L")) {
            return true; // primitives/arrays-of-primitives never dangle
        }
        String dotted = type.substring(1, type.length() - 1).replace('/', '.');
        for (String p : BOOT_PREFIXES) {
            if (dotted.startsWith(p)) {
                for (String e : BOOT_EXEMPT) {
                    if (dotted.startsWith(e)) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    /** Normalize a class line (dotted or L-form, array or not) to L-form. */
    static String toLForm(String s) {
        s = s.trim();
        if (s.isEmpty()) {
            return s;
        }
        while (s.startsWith("[")) {
            s = s.substring(1);
        }
        if (s.startsWith("L")) {
            return s.endsWith(";") ? s : s + ";";
        }
        if (s.length() == 1 && "VZBSCIJFD".contains(s)) {
            return s; // primitive descriptor (a one-letter CLASS name is not one)
        }
        return "L" + s.replace('.', '/').replaceAll(";$", "") + ";";
    }

    static Set<String> loadUniverse(File f) throws Exception {
        Set<String> out = new HashSet<>();
        for (String line : Files.readAllLines(f.toPath())) {
            String t = toLForm(line);
            if (t.length() > 2) {
                out.add(t);
            }
        }
        return out;
    }

    /** Every class a donor body points at must either ship in the product
     *  (universe) or resolve from the boot image. A packer bridge class is
     *  cleaned out of the product, so a body still calling into it dangles —
     *  better to keep the honest wall than import a NoSuchMethodError. */
    static boolean refsResolvable(Method donor, Set<String> universe) {
        MethodImplementation impl = donor.getImplementation();
        for (Instruction insn : impl.getInstructions()) {
            if (!(insn instanceof ReferenceInstruction)) {
                continue;
            }
            Reference ref = ((ReferenceInstruction) insn).getReference();
            String owner;
            if (ref instanceof MethodReference) {
                owner = ((MethodReference) ref).getDefiningClass();
            } else if (ref instanceof FieldReference) {
                owner = ((FieldReference) ref).getDefiningClass();
            } else if (ref instanceof TypeReference) {
                owner = ((TypeReference) ref).getType();
            } else {
                continue; // strings/numbers/call-sites carry no class
            }
            owner = toLForm(owner);
            if (owner.length() <= 2) {
                continue; // primitive descriptor
            }
            if (!universe.contains(owner) && !isBootType(owner)) {
                return false;
            }
        }
        return true;
    }

    /** Instruction-by-instruction value equality (opcode, reference, literal,
     *  registers). Two bodies with the same instruction VALUES carry the same
     *  information; grafting one over the other fakes the restored count. */
    static boolean insnEqual(Instruction a, Instruction b) {
        if (a.getOpcode() != b.getOpcode()) {
            return false;
        }
        if (a instanceof ReferenceInstruction
                && !((ReferenceInstruction) a).getReference().toString()
                    .equals(((ReferenceInstruction) b).getReference().toString())) {
            return false;
        }
        if (a instanceof NarrowLiteralInstruction
                && ((NarrowLiteralInstruction) a).getNarrowLiteral()
                   != ((NarrowLiteralInstruction) b).getNarrowLiteral()) {
            return false;
        }
        if (a instanceof WideLiteralInstruction
                && ((WideLiteralInstruction) a).getWideLiteral()
                   != ((WideLiteralInstruction) b).getWideLiteral()) {
            return false;
        }
        if (a instanceof OneRegisterInstruction
                && ((OneRegisterInstruction) a).getRegisterA()
                   != ((OneRegisterInstruction) b).getRegisterA()) {
            return false;
        }
        if (a instanceof TwoRegisterInstruction
                && ((TwoRegisterInstruction) a).getRegisterB()
                   != ((TwoRegisterInstruction) b).getRegisterB()) {
            return false;
        }
        if (a instanceof ThreeRegisterInstruction
                && ((ThreeRegisterInstruction) a).getRegisterC()
                   != ((ThreeRegisterInstruction) b).getRegisterC()) {
            return false;
        }
        if (a instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction va = (FiveRegisterInstruction) a;
            FiveRegisterInstruction vb = (FiveRegisterInstruction) b;
            if (va.getRegisterC() != vb.getRegisterC()
                    || va.getRegisterD() != vb.getRegisterD()
                    || va.getRegisterE() != vb.getRegisterE()
                    || va.getRegisterF() != vb.getRegisterF()
                    || va.getRegisterG() != vb.getRegisterG()) {
                return false;
            }
        } else if (a instanceof VariableRegisterInstruction
                && ((VariableRegisterInstruction) a).getRegisterCount()
                   != ((VariableRegisterInstruction) b).getRegisterCount()) {
            return false;
        }
        if (a instanceof RegisterRangeInstruction
                && (((RegisterRangeInstruction) a).getStartRegister()
                    != ((RegisterRangeInstruction) b).getStartRegister()
                || ((RegisterRangeInstruction) a).getRegisterCount()
                    != ((RegisterRangeInstruction) b).getRegisterCount())) {
            return false;
        }
        return true;
    }

    static boolean bodiesIdentical(Method donor, Method target) {
        MethodImplementation di = donor.getImplementation();
        MethodImplementation ti = target.getImplementation();
        if (di == null || ti == null) {
            return di == ti;
        }
        List<Instruction> da = new ArrayList<>();
        for (Instruction i : di.getInstructions()) {
            da.add(i);
        }
        List<Instruction> ta = new ArrayList<>();
        for (Instruction i : ti.getInstructions()) {
            ta.add(i);
        }
        if (da.size() != ta.size()) {
            return false;
        }
        for (int i = 0; i < da.size(); i++) {
            if (!insnEqual(da.get(i), ta.get(i))) {
                return false;
            }
        }
        return true;
    }

    /* ---------------- synthetic anchors (Restore --selftest) ----------------
     * No fixture files: every method/dex below is built in memory, the graft
     * e2e goes through the real CLI on temp files. Positive, negative and
     * non-interference anchors for the hollow-shell predicates. */

    static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("Restore --selftest FAILED: " + msg);
        }
    }

    static final int ACC_PUBLIC_STATIC = 0x1 | 0x8;

    static ImmutableMethod mk(String cls, String name, int registers,
                              List<Instruction> insns) {
        return new ImmutableMethod(cls, name,
                Collections.emptyList(), "V", ACC_PUBLIC_STATIC,
                Collections.emptySet(), Collections.emptySet(),
                new ImmutableMethodImplementation(registers, insns,
                        Collections.emptyList(), Collections.emptyList()));
    }

    static ImmutableClassDef mkClass(String type, List<Method> methods) {
        return new ImmutableClassDef(type, 0x1, "Ljava/lang/Object;",
                Collections.emptyList(), null, Collections.emptySet(),
                Collections.emptyList(), methods);
    }

    static List<Instruction> insns(Instruction... ii) {
        List<Instruction> out = new ArrayList<>();
        Collections.addAll(out, ii);
        return out;
    }

    static ImmutableMethodReference call(String cls, String name) {
        return new ImmutableMethodReference(cls, name,
                Collections.emptyList(), "V");
    }

    static void writeDex(File f, Opcodes opcodes, List<ClassDef> classes) throws Exception {
        DexPool pool = new DexPool(opcodes);
        for (ClassDef c : classes) {
            pool.internClass(c);
        }
        pool.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(f));
    }

    static Method theMethod(DexFile dex, String cls, String name) {
        for (ClassDef c : dex.getClasses()) {
            if (!c.getType().equals(cls)) {
                continue;
            }
            for (Method m : c.getMethods()) {
                if (m.getName().equals(name)) {
                    return m;
                }
            }
        }
        throw new AssertionError("method not found: " + cls + "->" + name);
    }

    static int insnCount(Method m) {
        int n = 0;
        for (Instruction ignored : m.getImplementation().getInstructions()) {
            n++;
        }
        return n;
    }

    static Opcode firstOpcode(Method m) {
        return m.getImplementation().getInstructions().iterator().next().getOpcode();
    }

    static void selftest() throws Exception {
        Opcodes opcodes = Opcodes.getDefault();
        ImmutableMethodReference nop = call("Lxt/Help;", "nop");
        ImmutableMethodReference work = call("Lxt/Help;", "work");

        // --- predicate anchors -------------------------------------------
        Method wall = mk("Lxt/A;", "wall", 1, insns(
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)));
        check(isNopWall(wall) && !isForwardingShell(wall) && isHollowShell(wall),
                "nop-wall must be wall+hollow, not shell");

        Method shell = mk("Lxt/A;", "shell", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)));
        check(!isNopWall(shell) && isForwardingShell(shell) && isHollowShell(shell),
                "invoke+return must be shell+hollow, not wall");

        Method shellPlumbing = mk("Lxt/A;", "shellPlumbing", 2, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction11x(Opcode.MOVE_RESULT, 1),
                new ImmutableInstruction11x(Opcode.RETURN, 1)));
        check(isForwardingShell(shellPlumbing),
                "invoke + move-result + return (value plumbing) must be shell");

        Method realConst = mk("Lxt/A;", "realConst", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 5),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)));
        check(!isNopWall(realConst) && !isForwardingShell(realConst)
                        && !isHollowShell(realConst),
                "non-zero const body is real, never hollow");

        Method twoInvokes = mk("Lxt/A;", "twoInvokes", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)));
        check(!isForwardingShell(twoInvokes) && !isHollowShell(twoInvokes),
                "two invokes is a real body, not a shell");

        Method shellPlusNop = mk("Lxt/A;", "shellPlusNop", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)));
        check(!isForwardingShell(shellPlusNop) && !isNopWall(shellPlusNop),
                "extra nop breaks the shell shape (and the wall shape)");

        // toLForm anchors (finding #11 follow-up: obfuscated one-letter class
        // names must not be mistaken for primitive descriptors)
        check(toLForm("a").equals("La;"), "one-letter dotted class is a class");
        check(toLForm("I").equals("I"), "primitive descriptor stays");
        check(toLForm("[I").equals("I"), "array-of-primitive unwraps");
        check(toLForm("Lxt/A;").equals("Lxt/A;"), "L-form passes through");
        check(toLForm("xt.Help").equals("Lxt/Help;"), "dotted converts");
        check(toLForm("[Lxt/Help;").equals("Lxt/Help;"), "array-of-class unwraps");
        System.out.println("Restore --selftest OK: hollow-shell predicates "
                + "(wall / shell / value-plumbing / real / two-invoke / nop-break)");

        // --- graft e2e through the real CLI --------------------------------
        List<Method> tgtMethods = new ArrayList<>();
        tgtMethods.add(mk("Lxt/A;", "wall", 1, insns(
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        tgtMethods.add(mk("Lxt/A;", "shell", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        tgtMethods.add(mk("Lxt/A;", "trivial", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        tgtMethods.add(mk("Lxt/A;", "real", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 5),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // finding #11 anchors: three nop-wall targets
        tgtMethods.add(mk("Lxt/A;", "wallfw", 1, insns(
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        tgtMethods.add(mk("Lxt/A;", "walldangle", 1, insns(
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        tgtMethods.add(mk("Lxt/A;", "wallboot", 1, insns(
                new ImmutableInstruction10x(Opcode.NOP),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));

        List<Method> srcMethods = new ArrayList<>();
        // donors for wall/shell: a real body (3 instructions)
        srcMethods.add(mk("Lxt/A;", "wall", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, work),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        srcMethods.add(mk("Lxt/A;", "shell", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, work),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // donor for trivial: instruction-identical to the target — zero
        // information, must be skipped (the graft would fake the count)
        srcMethods.add(mk("Lxt/A;", "trivial", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // donor for real: a different real body — must never graft over real
        srcMethods.add(mk("Lxt/A;", "real", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 7),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // finding #11: a shell-SHAPED donor that is the genuine one-line
        // delegate body — with resolvable refs it must donate
        srcMethods.add(mk("Lxt/A;", "wallfw", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, work),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // finding #11: a shell-shaped donor calling into a class that ships
        // nowhere (a packer bridge) — the universe gate must reject it
        srcMethods.add(mk("Lxt/A;", "walldangle", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                        call("Lxt/Gone;", "poof")),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // finding #11: a shell-shaped donor calling the boot classpath —
        // resolvable without universe membership
        srcMethods.add(mk("Lxt/A;", "wallboot", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                        call("Ljava/lang/System;", "gc")),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));

        File in = Files.createTempFile("restore-st-in", ".dex").toFile();
        File src = Files.createTempFile("restore-st-src", ".dex").toFile();
        File out = Files.createTempFile("restore-st-out", ".dex").toFile();
        File uni = Files.createTempFile("restore-st-universe", ".txt").toFile();
        in.deleteOnExit();
        src.deleteOnExit();
        out.deleteOnExit();
        uni.deleteOnExit();
        writeDex(in, opcodes, Collections.singletonList(mkClass("Lxt/A;", tgtMethods)));
        writeDex(src, opcodes, Collections.singletonList(mkClass("Lxt/A;", srcMethods)));
        Files.write(uni.toPath(), "Lxt/A;\nxt.Help\n".getBytes("UTF-8"));

        main(new String[]{in.getPath(), src.getPath(), out.getPath(), uni.getPath()});

        DexFile od = DexFileFactory.loadDexFile(out, opcodes);
        check(insnCount(theMethod(od, "Lxt/A;", "wall")) == 3,
                "wall target must be grafted (3 insns from donor)");
        check(insnCount(theMethod(od, "Lxt/A;", "shell")) == 3,
                "forwarding-shell target must be grafted (3 insns from donor)");
        check(insnCount(theMethod(od, "Lxt/A;", "trivial")) == 2,
                "instruction-identical donor: zero information, no graft");
        Method realAfter = theMethod(od, "Lxt/A;", "real");
        check(insnCount(realAfter) == 2, "real body must stay untouched");
        check(firstOpcode(theMethod(od, "Lxt/A;", "wallfw")) == Opcode.INVOKE_STATIC,
                "finding #11: shell-shaped genuine delegate must donate");
        check(firstOpcode(theMethod(od, "Lxt/A;", "walldangle")) == Opcode.NOP,
                "finding #11: donor with dangling (bridge) ref must be rejected");
        check(firstOpcode(theMethod(od, "Lxt/A;", "wallboot")) == Opcode.INVOKE_STATIC,
                "finding #11: boot-classpath ref is resolvable without universe");
        System.out.println("Restore --selftest OK: graft e2e "
                + "(wall+shell grafted, identical skipped, real untouched, "
                + "shell-delegate donated, bridge ref rejected, boot ref donated)");
        System.out.println("Restore --selftest: ALL GREEN");
    }
}
