//! 集成测试共享构造器（合成 APK / 最小 DEX）——零样本纪律：全部自造，永不引真实样本。

use std::io::Write;

/// uleb128 编码（builder 侧）
pub fn uleb_bytes(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

pub fn str_data(s: &str) -> Vec<u8> {
    let mut d = uleb_bytes(s.len() as u32);
    d.extend_from_slice(s.as_bytes());
    d.push(0);
    d
}

/// 固定 seed 的 xorshift64* 伪随机（测试可复现）
pub fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
        })
        .collect()
}

/// 最小合法 DEX：一个类、两个方法（一个 ACC_NATIVE stub、一个普通）。
/// 全部表结构真实（header/string_ids/type_ids/proto_ids/method_ids/class_defs/class_data）。
pub fn build_minimal_dex() -> Vec<u8> {
    let strings = [
        "Lcom/example/NativeProbe;",
        "Landroid/content/Context;",
        "V",
        "VL",
        "nativeFoo",
        "plainFoo",
        "Source.java",
    ];
    let mut sdata = Vec::new();
    let mut offs = Vec::new();
    for s in strings {
        offs.push((112 + sdata.len()) as u32);
        sdata.extend_from_slice(&str_data(s));
    }
    let string_ids_off = 112 + sdata.len();
    let type_ids_off = string_ids_off + 4 * strings.len();
    let proto_ids_off = type_ids_off + 3 * 4;
    let type_list_off = proto_ids_off + 12;
    let method_ids_off = type_list_off + 8;
    let class_defs_off = method_ids_off + 2 * 12;
    let class_data_off = class_defs_off + 32;

    let mut out = vec![0u8; 112];
    out[0..8].copy_from_slice(b"dex\n035\0");
    macro_rules! put {
        ($off:expr, $v:expr) => {
            out[$off..$off + 4].copy_from_slice(&$v.to_le_bytes())
        };
    }
    put!(0x20, 0u32); // file_size，末尾修正
    put!(0x24, 112u32);
    put!(0x28, 0x12345678u32);
    put!(0x38, strings.len() as u32);
    put!(0x3c, string_ids_off as u32);
    put!(0x40, 3u32);
    put!(0x44, type_ids_off as u32);
    put!(0x48, 1u32);
    put!(0x4c, proto_ids_off as u32);
    put!(0x58, 2u32);
    put!(0x5c, method_ids_off as u32);
    put!(0x60, 1u32);
    put!(0x64, class_defs_off as u32);

    out.extend_from_slice(&sdata);
    for o in offs {
        out.extend_from_slice(&o.to_le_bytes());
    }
    for i in [0u32, 1, 2] {
        out.extend_from_slice(&i.to_le_bytes());
    }
    // proto: shorty_idx=3, return_type_idx=2(V), parameters_off=type_list
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(type_list_off as u32).to_le_bytes());
    // type_list: size=1 → [Context(1)]
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    // method_ids: nativeFoo(class 0,proto 0,name 4) / plainFoo(class 0,proto 0,name 5)
    for (_, _, n) in [(0u32, 0u32, 4u32), (0, 0, 5)] {
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
    }
    // class_def: class_idx 0, access 0, super none, interfaces 0, source 6, annot 0, class_data_off, static 0
    for v in [0u32, 0, 0xFFFF_FFFF, 0, 6, 0, class_data_off as u32, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // class_data: 0/0/2/0，nativeFoo(diff 0, ACC_NATIVE 0x100, code 0)，plainFoo(diff 1, 0x1, 0)
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(2));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(0x100));
    out.extend_from_slice(&uleb_bytes(0));
    out.extend_from_slice(&uleb_bytes(1));
    out.extend_from_slice(&uleb_bytes(1));
    out.extend_from_slice(&uleb_bytes(0));

    let n = out.len() as u32;
    out[0x20..0x24].copy_from_slice(&n.to_le_bytes());
    out
}

/// 最小合法 arm64 ELF64（带 .dynsym 导出表）——符号定位段的可信 fixture。
/// symbols: [(name, st_value, st_size)]；null 段首条目由规范要求自动生成。
pub fn build_minimal_elf(symbols: &[(&str, u64, u64)]) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // ELF64
    out[5] = 1; // LE
    out[6] = 1; // EV_CURRENT
    out[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = EXEC
    out[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine = AArch64
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
    out[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx

    // .dynsym（null 条目 + 各符号；Elf64_Sym = 24B）
    let mut dynsym = vec![0u8; 24];
    let mut dynstr = vec![0u8];
    let mut name_offs = Vec::new();
    for (name, _, _) in symbols {
        name_offs.push(dynstr.len());
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }
    for (i, (_, value, size)) in symbols.iter().enumerate() {
        dynsym.extend_from_slice(&(name_offs[i] as u32).to_le_bytes());
        dynsym.push(0x12); // st_info: GLOBAL|FUNC
        dynsym.push(0); // st_other
        dynsym.extend_from_slice(&1u16.to_le_bytes()); // st_shndx = 1（已定义）
        dynsym.extend_from_slice(&value.to_le_bytes());
        dynsym.extend_from_slice(&size.to_le_bytes());
    }

    // .shstrtab
    let mut shstr = vec![0u8];
    let n1 = shstr.len();
    shstr.extend_from_slice(b".dynsym\0");
    let n2 = shstr.len();
    shstr.extend_from_slice(b".dynstr\0");
    let n3 = shstr.len();
    shstr.extend_from_slice(b".shstrtab\0");

    // 数据区布局
    let dynsym_off = out.len();
    out.extend_from_slice(&dynsym);
    let dynstr_off = out.len();
    out.extend_from_slice(&dynstr);
    let shstr_off = out.len();
    out.extend_from_slice(&shstr);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let shoff = out.len();

    // 段头：[0] NULL + [1] .dynsym + [2] .dynstr + [3] .shstrtab（Elf64_Shdr = 64B）
    out.extend_from_slice(&[0u8; 64]);
    let mut h = |name: usize, ty: u32, off: usize, size: usize, link: u32, entsize: u64, buf: &mut Vec<u8>| {
        buf.extend_from_slice(&(name as u32).to_le_bytes());
        buf.extend_from_slice(&ty.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        buf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        buf.extend_from_slice(&(off as u64).to_le_bytes());
        buf.extend_from_slice(&(size as u64).to_le_bytes());
        buf.extend_from_slice(&link.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        buf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
        buf.extend_from_slice(&entsize.to_le_bytes());
    };
    h(n1, 11, dynsym_off, dynsym.len(), 2, 24, &mut out); // .dynsym → link 指向 .dynstr
    h(n2, 3, dynstr_off, dynstr.len(), 0, 0, &mut out);
    h(n3, 3, shstr_off, shstr.len(), 0, 0, &mut out);

    out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff 回填
    out
}

/// 完整合成 APK：manifest + 真 DEX（1 native stub）+ 高/低熵 asset + **带 dynsym 的 so** + res 条目。
pub fn build_synthetic_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff]).unwrap();

    w.start_file("classes.dex", opts).unwrap();
    w.write_all(&build_minimal_dex()).unwrap();

    w.start_file("assets/payload.bin", opts).unwrap();
    w.write_all(&prng_bytes(42, 4096)).unwrap();

    w.start_file("assets/readme.txt", opts).unwrap();
    let low = (0..4096).map(|i| if i % 2 == 0 { b'a' } else { b'b' }).collect::<Vec<u8>>();
    w.write_all(&low).unwrap();

    // so：真导出表——目标符号 + 一个干扰符号（防误命中的查表检验）
    w.start_file("lib/arm64-v8a/libtest.so", opts).unwrap();
    let elf = build_minimal_elf(&[
        ("Java_com_example_NativeProbe_nativeFoo", 0x1204, 64),
        ("_JNI_OnLoad", 0x1300, 32),
    ]);
    w.write_all(&elf).unwrap();

    w.start_file("res/layout/main.xml", opts).unwrap();
    w.write_all(b"<layout/>").unwrap();

    w.finish().unwrap();
}
