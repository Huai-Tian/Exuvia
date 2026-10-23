import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;
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
 * Not a nop-wall, so a wall-only predicate never fills it. The shell
 * predicate is applied SYMMETRICALLY: a genuinely trivial method (the
 * developer really did write `super.onX(); return;`) is shell-shaped on
 * the donor side too and is rejected there — a graft fires only when the
 * same signature carries a larger real body in the source, which for a
 * same-build dump can only mean the target was extracted.
 *
 * The grafted body keeps the source method's implementation and access
 * flags (ACC_NATIVE cleared — a restored body is Dalvik again); everything
 * else comes from the primary class definition. DexPool re-interns all
 * cross-dex references, so the output is a fresh standard-layout DEX.
 *
 * Usage: java -cp ... Restore <in.dex> <source.dex> <out.dex> [api]
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
            System.err.println("usage: Restore <in.dex> <source.dex> <out.dex> [api]");
            System.err.println("       Restore --selftest   (synthetic predicate + graft anchors)");
            System.exit(2);
        }
        Opcodes opcodes = args.length > 3
                ? Opcodes.forApi(Integer.parseInt(args[3]))
                : Opcodes.getDefault();

        DexFile in = DexFileFactory.loadDexFile(new File(args[0]), opcodes);
        DexFile src = DexFileFactory.loadDexFile(new File(args[1]), opcodes);

        // index the source: class -> sig -> method carrying a REAL body
        // (a hollow source body is no donor — grafting shell over shell
        // restores nothing and would fake a "restored" count)
        Map<String, Map<String, Method>> srcIdx = new HashMap<>();
        for (ClassDef c : src.getClasses()) {
            for (Method m : c.getMethods()) {
                if (m.getImplementation() != null && !isHollowShell(m)) {
                    srcIdx.computeIfAbsent(c.getType(), k -> new HashMap<>())
                          .put(sig(m), m);
                }
            }
        }

        int restored = 0;
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
        System.out.println("restore: " + restored + " method body/bodies merged -> " + args[2]);
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
        // donor for trivial: the SAME hollow shell — must be rejected
        srcMethods.add(mk("Lxt/A;", "trivial", 1, insns(
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, nop),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));
        // donor for real: a different real body — must never graft over real
        srcMethods.add(mk("Lxt/A;", "real", 1, insns(
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 7),
                new ImmutableInstruction10x(Opcode.RETURN_VOID))));

        File in = Files.createTempFile("restore-st-in", ".dex").toFile();
        File src = Files.createTempFile("restore-st-src", ".dex").toFile();
        File out = Files.createTempFile("restore-st-out", ".dex").toFile();
        in.deleteOnExit();
        src.deleteOnExit();
        out.deleteOnExit();
        writeDex(in, opcodes, Collections.singletonList(mkClass("Lxt/A;", tgtMethods)));
        writeDex(src, opcodes, Collections.singletonList(mkClass("Lxt/A;", srcMethods)));

        main(new String[]{in.getPath(), src.getPath(), out.getPath()});

        DexFile od = DexFileFactory.loadDexFile(out, opcodes);
        check(insnCount(theMethod(od, "Lxt/A;", "wall")) == 3,
                "wall target must be grafted (3 insns from donor)");
        check(insnCount(theMethod(od, "Lxt/A;", "shell")) == 3,
                "forwarding-shell target must be grafted (3 insns from donor)");
        check(insnCount(theMethod(od, "Lxt/A;", "trivial")) == 2,
                "genuine trivial method: hollow donor rejected, no graft");
        Method realAfter = theMethod(od, "Lxt/A;", "real");
        check(insnCount(realAfter) == 2, "real body must stay untouched");
        System.out.println("Restore --selftest OK: graft e2e "
                + "(wall+shell grafted, trivial donor rejected, real untouched)");
        System.out.println("Restore --selftest: ALL GREEN");
    }
}
