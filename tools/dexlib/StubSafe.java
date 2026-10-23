import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.MethodParameter;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;
import org.jf.dexlib2.immutable.ImmutableMethodParameter;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11x;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21s;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction35c;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.writer.pool.DexPool;

/**
 * StubSafe: the no-reference fallback for shell-extracted methods.
 *
 * A packer's method extraction freezes app methods as `native + no code_item`
 * (the shell served the body from its runtime hook). Once the shell is gone
 * that stub is a LETHAL leftover: the JNI hook no longer exists, so the call
 * dies with UnsatisfiedLinkError. The extraction+nop-fill family (爱加密-style)
 * leaves the twin lethal leftover: a LEGAL code_item whose body is a nop wall
 * (nops + zero-literal consts + return only). Such a method verifies and
 * runs — and does NOTHING, which for a framework lifecycle override means the
 * mandatory super call never happens (SuperNotCalledException at launch).
 * Restore.java merges bodies back when a reference/source DEX carries them;
 * StubSafe handles what NO source has:
 *
 *   FRAMEWORK-LIFECYCLE CONTRACT (the strong tell): an Activity/Application/
 *   Service/Fragment lifecycle override is NEVER a legal native method — the
 *   framework template-method contract requires the super chain. native +
 *   lifecycle name == shell-extracted, with near certainty; a nop wall under
 *   a lifecycle name ON A FRAMEWORK-CARRIER CLASS is the same tell in the
 *   nop-fill family. For those we synthesize the contract-equivalent minimal
 *   body:
 *
 *     invoke-super {p0..pN}, Super.sameSignature   +  return(-void)
 *
 *   which is exactly what an empty app-side override must do (satisfy the
 *   super obligation and return). If the true body had business code, the
 *   app still LAUNCHES and runs; only that method's extra behavior is
 *   absent — recovered later when any dump/reference that carries the body
 *   is supplied (Restore stage runs FIRST in the pipeline; StubSafe only
 *   handles what no source could provide).
 *
 *   Everything else native+no-code is KEPT — a legal JNI declaration
 *   (e.g. androidx PathIterator natives backed by lib/*.so in the APK) is
 *   a necessary, side-effect-free leftover we deliberately reuse instead
 *   of synthesizing fake bodies ("not equivalence for equivalence's sake").
 *   Non-lifecycle nop walls are likewise KEPT — but ONLY when the wall
 *   actually VERIFIES as a no-op. The one wall shape that never verifies is
 *   the nop-wall CONSTRUCTOR: the ART verifier rejects any <init> that
 *   returns without calling a this/super constructor ("[0x0] Constructor
 *   returning without calling superclass constructor"), the rejection
 *   cascades to every subclass at dexopt, and the class dies with
 *   VerifyError at first touch shell-free (in the packed app the wall is
 *   invisible — the shell re-materializes the body before class load).
 *   For those we synthesize the minimal legal body:
 *
 *     invoke-direct {p0, dummy...}, DirectSuper.<init>(cheapest)  +
 *     return-void          (or a this-call to a real sibling ctor)
 *
 *   The ref MUST name the direct superclass (verifier rule) even when the
 *   signature comes from an ancestor up the chain (an in-dex superclass
 *   that declares no ctor resolves upward — Object terminates every chain).
 *   Non-constructor nop walls keep verifying as no-ops, so they are kept
 *   as-is: Restore (with a dump) is their only real cure, and the residue
 *   is harmless until then.
 *
 * Either way the whole DEX is re-serialized through DexPool (standard
 * smali-ecosystem layout), so StubSafe doubles as the final repack.
 *
 * Usage: java -cp ... StubSafe <in.dex> <out.dex> [api]
 */
public class StubSafe {
    static final int ACC_NATIVE = 0x100;
    static final int ACC_STATIC = 0x8;
    static final int ACC_ABSTRACT = 0x400;
    static final int ACC_PUBLIC = 0x1;
    static final int ACC_PRIVATE = 0x2;
    static final int ACC_PROTECTED = 0x4;

    /** Framework template-method names (Activity/Application/Service/Fragment
     *  lifecycle + must-call-super callbacks). A native method with one of
     *  these names is a shell-extracted stub, not a legal JNI declaration. */
    static final Set<String> LIFECYCLE = new HashSet<>(Arrays.asList(
            "onCreate", "onStart", "onResume", "onPause", "onStop", "onRestart",
            "onDestroy", "onDestroyView", "onDetach", "onAttach", "onViewCreated",
            "onSaveInstanceState", "onRestoreInstanceState", "onNewIntent",
            "onBackPressed", "onActivityResult", "onRequestPermissionsResult",
            "onConfigurationChanged", "onLowMemory", "onTrimMemory",
            "onWindowFocusChanged", "onAttachedToWindow", "onDetachedFromWindow",
            "onCreateOptionsMenu", "onPrepareOptionsMenu", "onOptionsItemSelected",
            "onContextItemSelected", "onCreateContextMenu", "onCreatePanelView",
            "onCreatePanelMenu", "onPreparePanel", "onMenuOpened", "onPanelClosed",
            "onContextMenuClosed", "onMultiWindowModeChanged",
            "onPictureInPictureModeChanged", "onTopResumedActivityChanged",
            "attachBaseContext", "onStartCommand", "onBind", "onUnbind", "onRebind"));

    /**
     * Nop-wall predicate: the extraction family's gutted body.
     * Instructions exclusively nops / zero-literal consts / returns, with at
     * least one return. Nop padding is NOT required (finding #12): the
     * family walls a getter-sized body as a bare zero-return stub
     * (`const-wide/16 0; return-wide`, even a lone `return-void`). A
     * genuine zero-shaped body is indistinguishable without donor evidence
     * and safe either way: non-constructor walls are kept verbatim, and a
     * genuine <init> always carries a super/this invoke so it never matches
     * this shape. A residual try table does NOT disqualify: this
     * family keeps the try structure while gutting handler code to nops too,
     * and the instruction scan covers handler code (a real handler trips the
     * default case); a synthesized/grafted body replaces the implementation
     * wholesale, try table included. Purely structural, no family-specific
     * constants.
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
        return returns >= 1;
    }

    /**
     * Framework-carrier guard for the nop-wall branch: a lifecycle NAME on a
     * class that does NOT inherit the framework template-method contract
     * (e.g. a POJO callback `onStart` whose superclass chain ends at
     * java/lang/Object) is not a lifecycle override — synthesizing
     * invoke-super there would reference a super method that does not exist
     * (VerifyError). Carrier = walking the in-dex superclass chain meets an
     * EXTERNAL class other than java/lang/Object (androidx/appcompat/...
     * — the contract lives up that chain). The native-stub branch keeps its
     * historical semantics (a native lifecycle name is lethal wherever it
     * sits); this guard scopes only the widened nop-wall tell.
     */
    static boolean isFrameworkCarrier(ClassDef c, Map<String, ClassDef> classIdx) {
        String sup = c.getSuperclass();
        Set<String> seen = new HashSet<>();
        while (sup != null && seen.add(sup)) {
            if (sup.equals("Ljava/lang/Object;")) {
                return false;
            }
            ClassDef sc = classIdx.get(sup);
            if (sc == null) {
                return true;  // external non-Object ancestor: framework/library
            }
            sup = sc.getSuperclass();
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--selftest".equals(args[0])) {
            selftest();
            return;
        }
        if (args.length < 2) {
            System.err.println("usage: StubSafe <in.dex> <out.dex> [api]");
            System.err.println("       StubSafe --selftest   (synthetic ctor-stub anchors)");
            System.exit(2);
        }
        Opcodes opcodes = args.length > 2
                ? Opcodes.forApi(Integer.parseInt(args[2]))
                : Opcodes.getDefault();

        DexFile dex = DexFileFactory.loadDexFile(new File(args[0]), opcodes);

        // index this dex: class -> (sig -> Method), to inspect a stub's
        // super-method when the super class lives in the same dump; plus a
        // type -> ClassDef map for the nop-wall branch's carrier guard
        Map<String, Map<String, Method>> index = new HashMap<>();
        Map<String, ClassDef> classIdx = new HashMap<>();
        for (ClassDef c : dex.getClasses()) {
            Map<String, Method> mmap = new HashMap<>();
            for (Method m : c.getMethods()) {
                mmap.put(m.getName() + ":" + m.getReturnType() + ":"
                        + m.getParameterTypes(), m);
            }
            index.put(c.getType(), mmap);
            classIdx.put(c.getType(), c);
        }

        // External-constructor evidence for the ctor-stub branch: every
        // invoke-site reference to an <init> whose defining class is NOT in
        // this dex proves that exact signature exists on-device (some real
        // body once linked it). Collected dex-wide, cheapest signature first.
        Map<String, List<MethodReference>> extCtorRefs = new HashMap<>();
        for (ClassDef c2 : dex.getClasses()) {
            for (Method m2 : c2.getMethods()) {
                MethodImplementation impl = m2.getImplementation();
                if (impl == null) {
                    continue;
                }
                for (Instruction insn : impl.getInstructions()) {
                    if (!(insn instanceof ReferenceInstruction)) {
                        continue;
                    }
                    Object ref = ((ReferenceInstruction) insn).getReference();
                    if (!(ref instanceof MethodReference)) {
                        continue;
                    }
                    MethodReference mr = (MethodReference) ref;
                    if (!mr.getName().equals("<init>")
                            || classIdx.containsKey(mr.getDefiningClass())) {
                        continue;
                    }
                    extCtorRefs.computeIfAbsent(mr.getDefiningClass(),
                            k -> new ArrayList<>()).add(mr);
                }
            }
        }

        List<ClassDef> outClasses = new ArrayList<>();
        int synthesized = 0;
        int keptNative = 0;
        int keptNopWall = 0;
        int ctorStubbed = 0;
        for (ClassDef c : dex.getClasses()) {
            List<Method> patched = new ArrayList<>();
            boolean changed = false;
            for (Method m : c.getMethods()) {
                int flags = m.getAccessFlags();
                boolean nativeStub = (flags & ACC_NATIVE) != 0
                        && m.getImplementation() == null;
                // the nop-fill family's twin lethal leftover: a legal
                // code_item whose gutted body does nothing — lethal when a
                // framework contract (super chain) rides on it
                boolean nopWall = (flags & (ACC_NATIVE | ACC_ABSTRACT)) == 0
                        && isNopWall(m);
                if (!nativeStub && !nopWall) {
                    patched.add(m);
                    continue;
                }
                boolean isLifecycle = LIFECYCLE.contains(m.getName())
                        && (flags & ACC_STATIC) == 0
                        && (flags & ACC_ABSTRACT) == 0
                        // a lifecycle NAME without the framework contract
                        // (POJO callback) is not the shell's tell — guard
                        // the widened nop-wall predicate against it
                        && (!nopWall || isFrameworkCarrier(c, classIdx));
                if (!isLifecycle) {
                    if (nativeStub) {
                        // no framework contract -> probably a legal JNI
                        // declaration backed by a .so still shipped in the
                        // APK: keep it as-is
                        keptNative++;
                        System.out.println("stubsafe: keep-native " + c.getType()
                                + "." + m.getName() + " (no lifecycle contract)");
                    } else if (m.getName().equals("<init>")) {
                        // finding #10: a nop-wall CONSTRUCTOR never verifies
                        // ("Constructor returning without calling superclass
                        // constructor") — a load-time VerifyError landmine
                        // shell-free, cascading to every subclass at dexopt.
                        // Synthesize the minimal legal body (this/super call
                        // + return-void).
                        MethodImplementation body = synthesizeCtorStub(
                                c, m, index, classIdx, extCtorRefs);
                        if (body != null) {
                            System.out.println("stubsafe: ctor-stub "
                                    + c.getType() + "-><init>"
                                    + m.getParameterTypes()
                                    + " (nop-wall constructor never verifies)");
                            patched.add(new ImmutableMethod(
                                    m.getDefiningClass(), m.getName(),
                                    m.getParameters(), m.getReturnType(),
                                    m.getAccessFlags(), m.getAnnotations(),
                                    m.getHiddenApiRestrictions(), body));
                            ctorStubbed++;
                            changed = true;
                            continue;
                        }
                        keptNopWall++;
                        System.out.println("stubsafe: ctor-stub-unresolved "
                                + c.getType() + "-><init>" + m.getParameterTypes()
                                + " (no invocable this/super signature fits the"
                                + " register plan — kept; the class stays"
                                + " verifier-invalid until a source carries"
                                + " the body)");
                    } else {
                        // non-lifecycle, non-constructor nop wall: verifies as
                        // a no-op — the shell-free run is unaffected; only
                        // Restore with a body-carrying source truly refills it
                        keptNopWall++;
                        System.out.println("stubsafe: keep-nopwall " + c.getType()
                                + "." + m.getName()
                                + " (no lifecycle contract; no-op body verifies)");
                    }
                    patched.add(m);
                    continue;
                }
                MethodImplementation body = synthesizeSuperCall(c, m, index);
                String tell = nopWall ? " (nop-wall body)" : "";
                if (body == null) {
                    // super-method is itself abstract/stubbed in-dex: delegate
                    // would not verify; keep the declaration but NOT as a
                    // lethal native stub — synthesize a default-return body
                    body = synthesizeDefaultReturn(m);
                    System.out.println("stubsafe: default-return " + c.getType()
                            + "." + m.getName() + " (super not invocable)" + tell);
                } else {
                    System.out.println("stubsafe: super-delegate " + c.getType()
                            + "." + m.getName()
                            + " (framework lifecycle contract)" + tell);
                }
                patched.add(new ImmutableMethod(
                        m.getDefiningClass(),
                        m.getName(),
                        m.getParameters(),
                        m.getReturnType(),
                        m.getAccessFlags() & ~ACC_NATIVE,
                        m.getAnnotations(),
                        m.getHiddenApiRestrictions(),
                        body));
                synthesized++;
                changed = true;
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
        pool.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(new File(args[1])));
        System.out.println("stubsafe: " + synthesized + " method(s) synthesized, "
                + ctorStubbed + " ctor-stub(s), "
                + keptNative + " native kept, " + keptNopWall
                + " nop-wall kept -> " + args[1]);
    }

    /**
     * invoke-super {v0..} + return(-void): the contract-equivalent minimal
     * body for a lifecycle override. Returns null when the super method is
     * known (in-dex) to be abstract or itself a stub — a delegate there would
     * fail verification.
     */
    static MethodImplementation synthesizeSuperCall(ClassDef c, Method m,
            Map<String, Map<String, Method>> index) {
        String sig = m.getName() + ":" + m.getReturnType() + ":"
                + m.getParameterTypes();
        String superType = c.getSuperclass();
        if (superType != null) {
            Map<String, Method> superMethods = index.get(superType);
            if (superMethods != null) {  // super lives in this dex: inspect it
                Method sm = superMethods.get(sig);
                if (sm == null) {
                    // not overridden below us; the call resolves further up the
                    // chain — in-dex super has no such method at all, so the
                    // real target is above (or absent). Absent is impossible
                    // for framework lifecycle names in practice; delegate.
                } else {
                    int sf = sm.getAccessFlags();
                    if ((sf & ACC_ABSTRACT) != 0 || sm.getImplementation() == null) {
                        return null;  // abstract or stubbed super: not invocable
                    }
                }
            }
            // super not in this dex: external framework/library class — the
            // lifecycle contract guarantees a concrete method up the chain
        } else {
            return null;  // java/lang/Object-level: has no lifecycle methods
        }

        // register plan: v0 = this, params from v1 (wide types take 2 regs)
        List<MethodParameter> params = new ArrayList<>(m.getParameters());
        List<Integer> invokeRegs = new ArrayList<>();  // first reg per arg slot
        int words = 1;  // this
        int next = 1;
        invokeRegs.add(0);
        for (MethodParameter p : params) {
            invokeRegs.add(next);
            int w = isWide(p.getType()) ? 2 : 1;
            words += w;
            next += w;
        }

        MethodReference ref = new ImmutableMethodReference(
                superType, m.getName(),
                new ArrayList<>(m.getParameterTypes()), m.getReturnType());

        List<ImmutableInstruction> insns = new ArrayList<>();
        if (invokeRegs.size() <= 5) {  // 35c
            int[] rg = new int[5];
            for (int i = 0; i < invokeRegs.size(); i++) {
                rg[i] = invokeRegs.get(i);
            }
            insns.add(new ImmutableInstruction35c(
                    Opcode.INVOKE_SUPER, words,
                    rg[0], rg[1], rg[2], rg[3], rg[4], ref));
        } else {  // 3rc
            insns.add(new ImmutableInstruction3rc(
                    Opcode.INVOKE_SUPER_RANGE, 0, words, ref));
        }
        String ret = m.getReturnType();
        if (ret.equals("V")) {
            insns.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        } else if (isWide(ret)) {
            // move-result must immediately follow the invoke
            insns.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
            insns.add(new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0));
        } else if (isPrimitive(ret)) {
            insns.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT, 0));
            insns.add(new ImmutableInstruction11x(Opcode.RETURN, 0));
        } else {
            insns.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            insns.add(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        return new ImmutableMethodImplementation(words, insns, null, null);
    }

    /** const v0, 0 + return(-void/-wide): a neutral body that just returns. */
    static MethodImplementation synthesizeDefaultReturn(Method m) {
        List<ImmutableInstruction> insns = new ArrayList<>();
        String ret = m.getReturnType();
        if (ret.equals("V")) {
            insns.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
            return new ImmutableMethodImplementation(1, insns, null, null);
        }
        if (isWide(ret)) {
            insns.add(new ImmutableInstruction21s(Opcode.CONST_WIDE_16, 0, 0));
            insns.add(new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0));
            return new ImmutableMethodImplementation(2, insns, null, null);
        }
        insns.add(new ImmutableInstruction11n(Opcode.CONST_4, 0, 0));
        if (isPrimitive(ret)) {
            insns.add(new ImmutableInstruction11x(Opcode.RETURN, 0));
        } else {
            insns.add(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        return new ImmutableMethodImplementation(1, insns, null, null);
    }

    /**
     * The minimal legal body for a nop-wall constructor (finding #10):
     * one invoke-direct to a this/super constructor, then return-void.
     *
     * Candidate targets, in order:
     *   A. a SIBLING constructor of the same class that has a real body —
     *      the this-call reuses the whole original init sequence for free;
     *   B. the direct superclass chain: the cheapest accessible ctor
     *      declared by the nearest in-dex ancestor that declares any. The
     *      invoke-direct REF always names the DIRECT superclass (verifier
     *      rule); when the declaring class is further up, resolution walks
     *      there on its own. The chain can only exit the dex at an external
     *      class — Object terminates it with the universal ()V, any other
     *      external class needs on-device signature evidence (a dex-wide
     *      invoke-site reference to that class's <init>);
     *   D. last resort: assume a no-arg super ctor. Always right for the
     *      system-instantiated component classes (Activity/Service/
     *      Provider/Receiver/Application/Fragment all have a public no-arg
     *      ctor) and for Object; possibly wrong elsewhere — logged loudly
     *      (ctor-stub-assumed-noarg), and a body-carrying source remains
     *      the real cure. A wrong guess is never worse than the wall it
     *      replaces (both fail verification; the guess at least has a
     *      chance).
     *
     * Register plan: the stub keeps the wall's signature, so its own
     * params occupy the last insWords registers and p0 (this) sits at
     * index <locals>. With k = target param words: when 1+k <= 5 use
     * 35c with k fresh locals holding the dummies (all referenced
     * registers <= 4, inside the 4-bit fields); otherwise, when the stub's
     * own (unused, never-read) params provide k contiguous words after
     * p0, use 3rc over p0..p0+k and const the dummies into p1... Returns
     * null when no candidate fits either plan.
     */
    static MethodImplementation synthesizeCtorStub(ClassDef c, Method m,
            Map<String, Map<String, Method>> index,
            Map<String, ClassDef> classIdx,
            Map<String, List<MethodReference>> extCtorRefs) {
        String self = c.getType();
        String sup = c.getSuperclass();
        if (sup == null) {
            return null;  // Object itself declares no super — no wall there
        }
        List<Object[]> cands = new ArrayList<>();  // {refClass, params, assumed}
        // A: real sibling constructor -> this-call (cheapest first)
        Map<String, Method> selfMethods = index.get(self);
        if (selfMethods != null) {
            String mySig = "<init>:" + m.getReturnType() + ":"
                    + m.getParameterTypes();
            List<Method> sibs = new ArrayList<>();
            for (Map.Entry<String, Method> e : selfMethods.entrySet()) {
                Method s = e.getValue();
                if (!s.getName().equals("<init>") || e.getKey().equals(mySig)) {
                    continue;
                }
                int sf = s.getAccessFlags();
                if ((sf & (ACC_ABSTRACT | ACC_NATIVE)) != 0
                        || s.getImplementation() == null || isNopWall(s)) {
                    continue;
                }
                sibs.add(s);
            }
            sibs.sort(Comparator.comparingInt(
                    s -> paramWordsTypes(s.getParameterTypes())));
            for (Method s : sibs) {
                List<String> tp = new ArrayList<>();
                for (CharSequence p : s.getParameterTypes()) {
                    tp.add(p.toString());
                }
                cands.add(new Object[]{self, tp, Boolean.FALSE});
            }
        }
        // B: the direct-superclass chain. Collect the cheapest accessible
        // ctor PER LEVEL, nearest first — a nearer level preserves more of
        // the original init chain, but when nothing there fits the register
        // plan the walk must continue (a level whose ctors are all too wide
        // does not end the search: Object terminates every chain with ()V).
        String cur = sup;
        Set<String> seen = new HashSet<>();
        while (cur != null && seen.add(cur)) {
            ClassDef sc = classIdx.get(cur);
            if (sc == null) {
                // chain exits the dex here (external class)
                if (cur.equals("Ljava/lang/Object;")) {
                    cands.add(new Object[]{sup, new ArrayList<String>(),
                            Boolean.FALSE});  // Object.<init>()V: universal
                } else {
                    List<MethodReference> refs = extCtorRefs.get(cur);
                    if (refs != null && !refs.isEmpty()) {
                        refs.sort(Comparator.comparingInt(
                                r -> paramWordsTypes(r.getParameterTypes())));
                        List<String> tp = new ArrayList<>();
                        for (CharSequence p : refs.get(0).getParameterTypes()) {
                            tp.add(p.toString());
                        }
                        cands.add(new Object[]{sup, tp, Boolean.FALSE});
                    }
                }
                break;
            }
            List<Method> usable = new ArrayList<>();
            Map<String, Method> sm = index.get(cur);
            if (sm != null) {
                for (Map.Entry<String, Method> e : sm.entrySet()) {
                    Method s = e.getValue();
                    if (!s.getName().equals("<init>")) {
                        continue;
                    }
                    int sf = s.getAccessFlags();
                    if ((sf & (ACC_PRIVATE | ACC_ABSTRACT)) != 0) {
                        continue;
                    }
                    if ((sf & (ACC_PUBLIC | ACC_PROTECTED)) == 0
                            && !packageOf(cur).equals(packageOf(self))) {
                        continue;  // package-private across packages
                    }
                    usable.add(s);
                }
            }
            if (!usable.isEmpty()) {
                usable.sort(Comparator.comparingInt(
                        s -> paramWordsTypes(s.getParameterTypes())));
                List<String> tp = new ArrayList<>();
                for (CharSequence p : usable.get(0).getParameterTypes()) {
                    tp.add(p.toString());
                }
                cands.add(new Object[]{sup, tp, Boolean.FALSE});
            }
            cur = sc.getSuperclass();
        }
        if (cands.isEmpty()) {
            // D: last resort — assume a no-arg super ctor (see javadoc)
            cands.add(new Object[]{sup, new ArrayList<String>(), Boolean.TRUE});
        }
        int insWords = 1 + paramWordsTypes(m.getParameterTypes());
        for (Object[] cand : cands) {
            String refClass = (String) cand[0];
            @SuppressWarnings("unchecked")
            List<String> tps = (List<String>) cand[1];
            boolean assumed = (Boolean) cand[2];
            int k = paramWordsTypes(tps);
            MethodReference ref = new ImmutableMethodReference(
                    refClass, "<init>", tps, "V");
            List<ImmutableInstruction> ins = new ArrayList<>();
            if (1 + k <= 5) {  // 35c: dummies in fresh locals v0..v(k-1)
                int v = 0;
                for (String t : tps) {
                    if (isWide(t)) {
                        ins.add(new ImmutableInstruction21s(
                                Opcode.CONST_WIDE_16, v, 0));
                        v += 2;
                    } else {
                        ins.add(new ImmutableInstruction11n(
                                Opcode.CONST_4, v, 0));
                        v += 1;
                    }
                }
                ins.add(new ImmutableInstruction35c(Opcode.INVOKE_DIRECT,
                        1 + k, k,                       // p0 at index <locals>=k
                        0, k > 1 ? 1 : 0,
                        k > 2 ? 2 : 0, k > 3 ? 3 : 0, ref));
                ins.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
                if (assumed) {
                    System.out.println("stubsafe: ctor-stub-assumed-noarg "
                            + self + "-><init>" + m.getParameterTypes()
                            + " (super " + refClass
                            + ": no on-device signature evidence)");
                }
                return new ImmutableMethodImplementation(k + insWords, ins,
                        null, null);
            }
            if (insWords - 1 >= k) {
                // 3rc: dummies overwrite the stub's own unused params p1..
                int v = 1;
                for (String t : tps) {
                    if (isWide(t)) {
                        ins.add(new ImmutableInstruction21s(
                                Opcode.CONST_WIDE_16, v, 0));
                        v += 2;
                    } else {
                        ins.add(new ImmutableInstruction11n(
                                Opcode.CONST_4, v, 0));
                        v += 1;
                    }
                }
                ins.add(new ImmutableInstruction3rc(Opcode.INVOKE_DIRECT_RANGE,
                        0, 1 + k, ref));
                ins.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
                if (assumed) {
                    System.out.println("stubsafe: ctor-stub-assumed-noarg "
                            + self + "-><init>" + m.getParameterTypes()
                            + " (super " + refClass
                            + ": no on-device signature evidence)");
                }
                return new ImmutableMethodImplementation(insWords, ins,
                        null, null);
            }
        }
        return null;
    }

    static int paramWordsTypes(List<? extends CharSequence> types) {
        int w = 0;
        for (CharSequence t : types) {
            w += isWide(t.toString()) ? 2 : 1;
        }
        return w;
    }

    static String packageOf(String type) {
        int i = type.lastIndexOf('/');
        return i < 0 ? "" : type.substring(1, i);
    }

    static boolean isPrimitive(String type) {
        return type.length() == 1;  // V Z B C S I J F D — single-letter types
    }

    static boolean isWide(String type) {
        return type.equals("J") || type.equals("D");
    }

    /* ---------------- synthetic anchors (StubSafe --selftest) --------------
     * No fixture files: every class below is built in memory, the pass goes
     * through the real CLI on temp files. Anchors for the ctor-stub branch
     * (finding #10) plus the historical keep/regression behavior. */

    static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("StubSafe --selftest FAILED: " + msg);
        }
    }

    static final int ACC_CTOR_PUBLIC = 0x10001;

    static ImmutableMethod mkCtorWall(String cls, List<MethodParameter> params,
                                      int registers) {
        List<Instruction> body = new ArrayList<>();
        body.add(new ImmutableInstruction10x(Opcode.NOP));
        body.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        return new ImmutableMethod(cls, "<init>", params, "V", ACC_CTOR_PUBLIC,
                new HashSet<>(), new HashSet<>(),
                new ImmutableMethodImplementation(registers, body,
                        new ArrayList<>(), new ArrayList<>()));
    }

    static ImmutableMethod mkRealCtor(String cls) {
        List<Instruction> body = new ArrayList<>();
        body.add(new ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1,
                0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "<init>",
                        new ArrayList<>(), "V")));
        body.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        return new ImmutableMethod(cls, "<init>", new ArrayList<>(), "V",
                ACC_CTOR_PUBLIC, new HashSet<>(), new HashSet<>(),
                new ImmutableMethodImplementation(1, body,
                        new ArrayList<>(), new ArrayList<>()));
    }

    static ImmutableMethod mkVoidWall(String cls, String name) {
        List<Instruction> body = new ArrayList<>();
        body.add(new ImmutableInstruction10x(Opcode.NOP));
        body.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        return new ImmutableMethod(cls, name, new ArrayList<>(), "V", 0x1,
                new HashSet<>(), new HashSet<>(),
                new ImmutableMethodImplementation(1, body,
                        new ArrayList<>(), new ArrayList<>()));
    }

    static ImmutableMethod mkRealVoid(String cls, String name) {
        List<Instruction> body = new ArrayList<>();
        body.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        return new ImmutableMethod(cls, name, new ArrayList<>(), "V", 0x1,
                new HashSet<>(), new HashSet<>(),
                new ImmutableMethodImplementation(1, body,
                        new ArrayList<>(), new ArrayList<>()));
    }

    static ImmutableClassDef mkClass(String type, String sup,
                                     List<Method> methods) {
        return new ImmutableClassDef(type, 0x1, sup, new ArrayList<>(), null,
                new HashSet<>(), new ArrayList<>(), methods);
    }

    static Method theMethod(DexFile dex, String cls, String name,
                            String protoRet, List<String> protoParams) {
        for (ClassDef c : dex.getClasses()) {
            if (!c.getType().equals(cls)) {
                continue;
            }
            for (Method m : c.getMethods()) {
                if (m.getName().equals(name)
                        && m.getReturnType().equals(protoRet)
                        && m.getParameterTypes().equals(protoParams)) {
                    return m;
                }
            }
        }
        throw new AssertionError("method not found: " + cls + "->" + name);
    }

    static MethodReference firstInvokeTarget(Method m) {
        for (Instruction insn : m.getImplementation().getInstructions()) {
            if (insn instanceof ReferenceInstruction) {
                Object ref = ((ReferenceInstruction) insn).getReference();
                if (ref instanceof MethodReference) {
                    return (MethodReference) ref;
                }
            }
        }
        return null;
    }

    static void selftest() throws Exception {
        Opcodes opcodes = Opcodes.getDefault();

        List<Method> wallCls = new ArrayList<>();
        wallCls.add(mkCtorWall("Lst/Wall;", new ArrayList<>(), 1));
        wallCls.add(mkVoidWall("Lst/Wall;", "v"));   // non-ctor wall: must stay
        // Pair: wall <init>(I)V + real <init>()V -> this-chain to the sibling
        List<MethodParameter> intParam = new ArrayList<>();
        intParam.add(new ImmutableMethodParameter("I", null, null));
        List<Method> pairCls = new ArrayList<>();
        pairCls.add(mkCtorWall("Lst/Pair;", intParam, 2));
        pairCls.add(mkRealCtor("Lst/Pair;"));
        // Mid declares no ctor; Sub extends Mid -> ref names Mid, sig ()V
        List<Method> midCls = new ArrayList<>();
        midCls.add(mkRealVoid("Lst/Mid;", "d"));
        List<Method> subCls = new ArrayList<>();
        subCls.add(mkCtorWall("Lst/Sub;", new ArrayList<>(), 1));
        // Orphan extends an external class with zero on-device evidence
        List<Method> orphanCls = new ArrayList<>();
        orphanCls.add(mkCtorWall("Lst/Orphan;", new ArrayList<>(), 1));
        // WideSuper declares ONLY a 5-word ctor (a 6-register call — 35c can
        // never fit it); Wide's wall ctor must fall through the chain to
        // Object's ()V while the ref still names the DIRECT super
        List<MethodParameter> fiveObj = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            fiveObj.add(new ImmutableMethodParameter("Ljava/lang/Object;",
                    null, null));
        }
        List<Instruction> wideBody = new ArrayList<>();
        wideBody.add(new ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1,
                5, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "<init>",
                        new ArrayList<>(), "V")));
        wideBody.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        List<Method> wideSuperCls = new ArrayList<>();
        wideSuperCls.add(new ImmutableMethod("Lst/WideSuper;", "<init>",
                fiveObj, "V", ACC_CTOR_PUBLIC, new HashSet<>(), new HashSet<>(),
                new ImmutableMethodImplementation(6, wideBody,
                        new ArrayList<>(), new ArrayList<>())));
        List<Method> wideCls = new ArrayList<>();
        wideCls.add(mkCtorWall("Lst/Wide;", new ArrayList<>(), 1));

        List<ClassDef> classes = new ArrayList<>();
        classes.add(mkClass("Lst/Wall;", "Ljava/lang/Object;", wallCls));
        classes.add(mkClass("Lst/Pair;", "Ljava/lang/Object;", pairCls));
        classes.add(mkClass("Lst/Mid;", "Ljava/lang/Object;", midCls));
        classes.add(mkClass("Lst/Sub;", "Lst/Mid;", subCls));
        classes.add(mkClass("Lst/Orphan;", "Lst/Ext;", orphanCls));
        classes.add(mkClass("Lst/WideSuper;", "Ljava/lang/Object;", wideSuperCls));
        classes.add(mkClass("Lst/Wide;", "Lst/WideSuper;", wideCls));

        File in = Files.createTempFile("stubsafe-st-in", ".dex").toFile();
        File out = Files.createTempFile("stubsafe-st-out", ".dex").toFile();
        in.deleteOnExit();
        out.deleteOnExit();
        DexPool pool = new DexPool(opcodes);
        for (ClassDef cd : classes) {
            pool.internClass(cd);
        }
        pool.writeTo(new org.jf.dexlib2.writer.io.FileDataStore(in));

        main(new String[]{in.getPath(), out.getPath()});

        DexFile od = DexFileFactory.loadDexFile(out, opcodes);
        // wall ctor stubbed: invoke-direct to Object.<init>()V, no longer a wall
        Method w = theMethod(od, "Lst/Wall;", "<init>", "V", new ArrayList<>());
        check(!isNopWall(w), "stubbed ctor must not remain a nop wall");
        MethodReference wr = firstInvokeTarget(w);
        check(wr != null && wr.getDefiningClass().equals("Ljava/lang/Object;")
                && wr.getName().equals("<init>")
                && wr.getParameterTypes().isEmpty(),
                "Wall.<init> must call Object.<init>()V, got " + wr);
        // non-ctor wall untouched
        check(isNopWall(theMethod(od, "Lst/Wall;", "v", "V", new ArrayList<>())),
                "non-ctor nop wall must be KEPT (regression anchor)");
        // sibling this-chain
        Method p = theMethod(od, "Lst/Pair;", "<init>", "V",
                java.util.Collections.singletonList("I"));
        MethodReference pr = firstInvokeTarget(p);
        check(pr != null && pr.getDefiningClass().equals("Lst/Pair;")
                && pr.getParameterTypes().isEmpty(),
                "Pair.<init>(I)V must this-chain to the real sibling, got " + pr);
        // undeclared-ctor superclass: ref names the DIRECT super, sig from the
        // chain top (Object) — resolution walks up on-device
        Method s = theMethod(od, "Lst/Sub;", "<init>", "V", new ArrayList<>());
        MethodReference sr = firstInvokeTarget(s);
        check(sr != null && sr.getDefiningClass().equals("Lst/Mid;")
                && sr.getParameterTypes().isEmpty(),
                "Sub.<init> must name Lst/Mid;.<init>()V (upward resolution), got " + sr);
        // external super, no evidence: assumed no-arg fallback
        Method o = theMethod(od, "Lst/Orphan;", "<init>", "V", new ArrayList<>());
        MethodReference or = firstInvokeTarget(o);
        check(or != null && or.getDefiningClass().equals("Lst/Ext;")
                && or.getParameterTypes().isEmpty(),
                "Orphan.<init> must assume Lst/Ext;.<init>()V, got " + or);
        // too-wide nearest super ctor: fall through the chain to Object's
        // ()V, ref still naming the DIRECT super (regression: single-level
        // candidate collection stranded this shape as ctor-stub-unresolved)
        Method wc = theMethod(od, "Lst/Wide;", "<init>", "V", new ArrayList<>());
        check(!isNopWall(wc), "Wide.<init> must be stubbed, not kept as wall");
        MethodReference wcr = firstInvokeTarget(wc);
        check(wcr != null && wcr.getDefiningClass().equals("Lst/WideSuper;")
                && wcr.getParameterTypes().isEmpty(),
                "Wide.<init> must name Lst/WideSuper;.<init>()V (chain-top "
                + "signature, direct-super ref), got " + wcr);
        System.out.println("StubSafe --selftest OK: ctor-stub anchors "
                + "(object super / sibling this-chain / undeclared-super ref /"
                + " assumed-noarg fallback / too-wide super falls to chain top /"
                + " non-ctor wall kept)");
        System.out.println("StubSafe --selftest: ALL GREEN");
    }
}
