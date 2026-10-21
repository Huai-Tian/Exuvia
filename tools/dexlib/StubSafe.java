import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;
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
 * dies with UnsatisfiedLinkError. Restore.java merges bodies back when a
 * reference/source DEX carries them; StubSafe handles what NO source has:
 *
 *   FRAMEWORK-LIFECYCLE CONTRACT (the strong tell): an Activity/Application/
 *   Service/Fragment lifecycle override is NEVER a legal native method — the
 *   framework template-method contract requires the super chain. native +
 *   lifecycle name == shell-extracted, with near certainty. For those we
 *   synthesize the contract-equivalent minimal body:
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

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: StubSafe <in.dex> <out.dex> [api]");
            System.exit(2);
        }
        Opcodes opcodes = args.length > 2
                ? Opcodes.forApi(Integer.parseInt(args[2]))
                : Opcodes.getDefault();

        DexFile dex = DexFileFactory.loadDexFile(new File(args[0]), opcodes);

        // index this dex: class -> (sig -> Method), to inspect a stub's
        // super-method when the super class lives in the same dump
        Map<String, Map<String, Method>> index = new HashMap<>();
        for (ClassDef c : dex.getClasses()) {
            Map<String, Method> mmap = new HashMap<>();
            for (Method m : c.getMethods()) {
                mmap.put(m.getName() + ":" + m.getReturnType() + ":"
                        + m.getParameterTypes(), m);
            }
            index.put(c.getType(), mmap);
        }

        List<ClassDef> outClasses = new ArrayList<>();
        int synthesized = 0;
        int keptNative = 0;
        for (ClassDef c : dex.getClasses()) {
            List<Method> patched = new ArrayList<>();
            boolean changed = false;
            for (Method m : c.getMethods()) {
                boolean nativeStub = (m.getAccessFlags() & ACC_NATIVE) != 0
                        && m.getImplementation() == null;
                if (!nativeStub) {
                    patched.add(m);
                    continue;
                }
                boolean isLifecycle = LIFECYCLE.contains(m.getName())
                        && (m.getAccessFlags() & ACC_STATIC) == 0
                        && (m.getAccessFlags() & ACC_ABSTRACT) == 0;
                if (!isLifecycle) {
                    // no framework contract -> probably a legal JNI declaration
                    // backed by a .so still shipped in the APK: keep it as-is
                    keptNative++;
                    System.out.println("stubsafe: keep-native " + c.getType()
                            + "." + m.getName() + " (no lifecycle contract)");
                    patched.add(m);
                    continue;
                }
                MethodImplementation body = synthesizeSuperCall(c, m, index);
                if (body == null) {
                    // super-method is itself abstract/stubbed in-dex: delegate
                    // would not verify; keep the declaration but NOT as a
                    // lethal native stub — synthesize a default-return body
                    body = synthesizeDefaultReturn(m);
                    System.out.println("stubsafe: default-return " + c.getType()
                            + "." + m.getName() + " (super not invocable)");
                } else {
                    System.out.println("stubsafe: super-delegate " + c.getType()
                            + "." + m.getName() + " (framework lifecycle contract)");
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
                + keptNative + " native kept -> " + args[1]);
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

    static boolean isPrimitive(String type) {
        return type.length() == 1;  // V Z B C S I J F D — single-letter types
    }

    static boolean isWide(String type) {
        return type.equals("J") || type.equals("D");
    }
}
