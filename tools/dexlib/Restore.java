import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.writer.pool.DexPool;

/**
 * Restore: merge method bodies for shell-extracted stubs from every source
 * that carries them (SKILL §7 restore stage).
 *
 * A packer's method extraction/VMP freezes app methods as `native + no
 * code_item` (or otherwise implementation-less): the body lived in the
 * shell's runtime hook. A dump/reference/earlier-stage DEX that carries the
 * same class+signature WITH a body donates it. Sources are tried in order
 * (the pipeline invokes Restore once per source); the first source carrying
 * a body wins — methods that already have an implementation are never
 * touched, and abstract declarations are never given bodies.
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

        // index the source: class -> sig -> method carrying a body
        Map<String, Map<String, Method>> srcIdx = new HashMap<>();
        for (ClassDef c : src.getClasses()) {
            for (Method m : c.getMethods()) {
                if (m.getImplementation() != null) {
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
                boolean fillable = m.getImplementation() == null
                        && (m.getAccessFlags() & ACC_ABSTRACT) == 0;
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
                            + " (body merged from source)");
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
