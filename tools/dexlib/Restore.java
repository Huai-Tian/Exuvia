import java.io.File;
import java.util.ArrayList;
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
import org.jf.dexlib2.immutable.ImmutableMethod;
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
 * that is itself a nop wall is never donated (a wall over a wall restores
 * nothing).
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

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: Restore <in.dex> <source.dex> <out.dex> [api]");
            System.exit(2);
        }
        Opcodes opcodes = args.length > 3
                ? Opcodes.forApi(Integer.parseInt(args[3]))
                : Opcodes.getDefault();

        DexFile in = DexFileFactory.loadDexFile(new File(args[0]), opcodes);
        DexFile src = DexFileFactory.loadDexFile(new File(args[1]), opcodes);

        // index the source: class -> sig -> method carrying a REAL body
        // (a nop-wall source body is no donor — grafting wall over wall
        // restores nothing and would fake a "restored" count)
        Map<String, Map<String, Method>> srcIdx = new HashMap<>();
        for (ClassDef c : src.getClasses()) {
            for (Method m : c.getMethods()) {
                if (m.getImplementation() != null && !isNopWall(m)) {
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
                // fillable = no body at all (extraction stub) OR a nop-wall
                // body (extraction+nop-fill: a legal code_item whose gutted
                // body verifies as a no-op). Real bodies are never touched.
                boolean nopWall = isNopWall(m);
                boolean fillable = (m.getAccessFlags() & ACC_ABSTRACT) == 0
                        && (m.getImplementation() == null || nopWall);
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
}
