//! 集成测试共享构造器（合成 APK / 最小 DEX）——零样本纪律：全部自造，永不引真实样本。
//! 各测试目标按需 include，未用到的构造器属正常（fixture 惯例）。
#![allow(dead_code)]

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
    let method_ids_off = type_list_off + 6; // type_list = size u32 + 1×u16 条目（spec）
    let class_defs_off = method_ids_off + 2 * 8; // method_id_item = 8 字节（spec）
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
    // type_list: size=1 → [Context(1)]，条目 u16（spec）
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    // method_ids: method_id_item = u16 class_idx / u16 proto_idx / u32 name_idx（spec，8 字节）
    // nativeFoo(class 0, proto 0, name 4) / plainFoo(class 0, proto 0, name 5)
    for (_, _, n) in [(0u32, 0u32, 4u32), (0, 0, 5)] {
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
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

/// 最小合法 arm64 ELF64（带 .dynsym + PT_LOAD）——符号定位与切片段的可信 fixture。
/// 布局：header(64) + phdr(56) + pad→0x1000 + 数据区[0x1000,0x1400) + dynsym/dynstr/shstr + 段头。
/// PT_LOAD: p_offset=0x1000, p_vaddr=0 → 符号 st_value 是 VA（0x204 → 文件偏移 0x1204，非平凡映射）。
/// symbols: [(name, st_value=VA, st_size)]；数据区 = prng_bytes(7, 0x400)。
pub fn build_minimal_elf(symbols: &[(&str, u64, u64)]) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // ELF64
    out[5] = 1; // LE
    out[6] = 1; // EV_CURRENT
    out[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = DYN（so 常态）
    out[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine = AArch64
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    out[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    out[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
    out[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx

    // PT_LOAD（Elf64_Phdr = 56B）：p_type=1, p_flags=5(R|X), p_offset=0x1000, p_vaddr=0,
    // p_paddr=0, p_filesz=0x400, p_memsz=0x400, p_align=0x1000
    let mut ph = Vec::new();
    ph.extend_from_slice(&1u32.to_le_bytes());
    ph.extend_from_slice(&5u32.to_le_bytes());
    ph.extend_from_slice(&0x1000u64.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes());
    ph.extend_from_slice(&0x400u64.to_le_bytes());
    ph.extend_from_slice(&0x400u64.to_le_bytes());
    ph.extend_from_slice(&0x1000u64.to_le_bytes());
    out.extend_from_slice(&ph);

    // padding 到 0x1000（确定性 PRNG）
    let pad = 0x1000 - out.len();
    out.extend_from_slice(&prng_bytes(5, pad));
    // 数据区 [0x1000, 0x1400)：切片内容来源
    out.extend_from_slice(&prng_bytes(7, 0x400));

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

    // 数据区之后的表布局
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

/// ELF 数据区内容（切片期望值的计算来源）：prng_bytes(7, 0x400)
pub const ELF_DATA_SEED: u64 = 7;
pub const ELF_DATA_LEN: usize = 0x400;

/// 最小 arm64 ELF64 + .init_array 段（解密例程候选定位的 fixture）。
/// 与 build_minimal_elf 同骨架；数据区后追加 init_array 数据段与段表项。
/// symbols: [(name, st_value=VA, st_size)]；init_entries: init_array 条目（内容为 VA）。
pub fn build_minimal_elf_v2(symbols: &[(&str, u64, u64)], init_entries: &[u64]) -> Vec<u8> {
    // 与 v1 同骨架 + init_array（独立构造，避免 v1 签名改动）
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&3u16.to_le_bytes());
    out[18..20].copy_from_slice(&183u16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[54..56].copy_from_slice(&56u16.to_le_bytes());
    out[56..58].copy_from_slice(&1u16.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum = 5
    out[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx = 3

    // PT_LOAD
    let mut ph = Vec::new();
    ph.extend_from_slice(&1u32.to_le_bytes());
    ph.extend_from_slice(&5u32.to_le_bytes());
    ph.extend_from_slice(&0x1000u64.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes());
    ph.extend_from_slice(&0x400u64.to_le_bytes());
    ph.extend_from_slice(&0x400u64.to_le_bytes());
    ph.extend_from_slice(&0x1000u64.to_le_bytes());
    out.extend_from_slice(&ph);

    let pad = 0x1000 - out.len();
    out.extend_from_slice(&prng_bytes(5, pad));
    out.extend_from_slice(&prng_bytes(7, 0x400)); // 数据区 [0x1000,0x1400)

    // .init_array 数据段（数据区之后）
    let init_off = out.len();
    for v in init_entries {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let init_size = init_entries.len() * 8;

    // .dynsym + .dynstr
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
        dynsym.push(0x12);
        dynsym.push(0);
        dynsym.extend_from_slice(&1u16.to_le_bytes());
        dynsym.extend_from_slice(&value.to_le_bytes());
        dynsym.extend_from_slice(&size.to_le_bytes());
    }

    let mut shstr = vec![0u8];
    let n1 = shstr.len();
    shstr.extend_from_slice(b".dynsym\0");
    let n2 = shstr.len();
    shstr.extend_from_slice(b".dynstr\0");
    let n3 = shstr.len();
    shstr.extend_from_slice(b".shstrtab\0");
    let n4 = shstr.len();
    shstr.extend_from_slice(b".init_array\0");

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

    let mut h = |name: usize, ty: u32, off: usize, size: usize, link: u32, entsize: u64, buf: &mut Vec<u8>| {
        buf.extend_from_slice(&(name as u32).to_le_bytes());
        buf.extend_from_slice(&ty.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&(off as u64).to_le_bytes());
        buf.extend_from_slice(&(size as u64).to_le_bytes());
        buf.extend_from_slice(&link.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&entsize.to_le_bytes());
    };
    out.extend_from_slice(&[0u8; 64]); // NULL 段
    h(n1, 11, dynsym_off, dynsym.len(), 2, 24, &mut out);
    h(n2, 3, dynstr_off, dynstr.len(), 0, 0, &mut out);
    h(n3, 3, shstr_off, shstr.len(), 0, 0, &mut out);
    h(n4, 14, init_off, init_size, 0, 8, &mut out); // SHT_INIT_ARRAY

    out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    out
}

/// 壳形态合成 APK（修正案 #1/#2 的 fixture）：业务 stub DEX + 壳 so 藏 assets。
/// assets/libshell_a64.so：带 stub 符号 + JNI_OnLoad，尾部追加明文 DEX（机械扫描命中）
/// assets/libshell_plain.so：无 DEX（零命中负事实卡点）
pub fn build_shell_style_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff]).unwrap();

    w.start_file("classes.dex", opts).unwrap();
    w.write_all(&build_minimal_dex()).unwrap();

    // 壳 so（arm64，符号齐备）+ 尾部明文 DEX
    let mut shell = build_minimal_elf_v2(
        &[
            ("Java_com_example_NativeProbe_nativeFoo", 0x204, 64),
            ("JNI_OnLoad", 0x300, 32),
        ],
        &[0x200],
    );
    shell.extend_from_slice(&build_minimal_dex()); // 明文嵌入（扫描应命中尾部）
    w.start_file("assets/libshell_a64.so", opts).unwrap();
    w.write_all(&shell).unwrap();

    // 零命中壳 so
    w.start_file("assets/libshell_plain.so", opts).unwrap();
    w.write_all(&build_minimal_elf_v2(&[("_x", 0x10, 8)], &[])).unwrap();

    w.start_file("assets/payload.bin", opts).unwrap();
    w.write_all(&prng_bytes(42, 4096)).unwrap();

    w.finish().unwrap();
}

/// PT_DYNAMIC 壳形态 ELF64（修正案 #3 fixture）：section headers 剥除（e_shnum=0），
/// 只有 program headers——动态路径必须独立可解析。PT_LOAD identity 映射
///（p_offset == p_vaddr == 0x1000）→ DT_ 值即文件偏移；符号 st_value 即文件偏移。
/// 布局：header(64) + phdr(PT_LOAD+PT_DYNAMIC) + pad→0x1000 + 数据区 0x400
/// + init_array + dynsym + dynstr + DT_HASH + .dynamic。
pub fn build_minimal_elf_v3(symbols: &[(&str, u64, u64)], init_entries: &[u64]) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&3u16.to_le_bytes()); // DYN
    out[18..20].copy_from_slice(&183u16.to_le_bytes()); // AArch64
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    out[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2
    out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0（壳剥除形态）
    out[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx = 0

    let ph_base = out.len();
    out.extend_from_slice(&[0u8; 112]); // 两个 phdr 占位
    while out.len() < 0x1000 {
        out.push(0);
    }
    out.extend_from_slice(&prng_bytes(7, 0x400)); // 数据区 [0x1000, 0x1400)

    // init_array（DT_INIT_ARRAY 指向；内容是 VA 条目）
    let init_off = out.len() as u64;
    for v in init_entries {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let init_sz = (init_entries.len() * 8) as u64;

    // dynsym（null 条目 + 符号）+ dynstr
    let sym_off = out.len() as u64;
    let mut dynsym = vec![0u8; 24];
    let mut dynstr = vec![0u8];
    let mut name_offs = Vec::new();
    for (n, _, _) in symbols {
        name_offs.push(dynstr.len());
        dynstr.extend_from_slice(n.as_bytes());
        dynstr.push(0);
    }
    for (i, (_, v, s)) in symbols.iter().enumerate() {
        dynsym.extend_from_slice(&(name_offs[i] as u32).to_le_bytes());
        dynsym.push(0x12); // GLOBAL|FUNC
        dynsym.push(0);
        dynsym.extend_from_slice(&1u16.to_le_bytes());
        dynsym.extend_from_slice(&v.to_le_bytes());
        dynsym.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&dynsym);
    let str_off = out.len() as u64;
    let str_sz = dynstr.len() as u64;
    out.extend_from_slice(&dynstr);

    // DT_HASH（System V）：nbucket=1, nchain=n+1, buckets=[1], chain（内容任意——解析器只读 nchain）
    let hash_off = out.len() as u64;
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&((symbols.len() as u32) + 1).to_le_bytes()); // nchain
    out.extend_from_slice(&1u32.to_le_bytes());
    for _ in 0..(symbols.len() + 1) {
        out.extend_from_slice(&0x8000_0001u32.to_le_bytes());
    }

    // .dynamic
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let dyn_off = out.len() as u64;
    for (t, v) in [
        (0x19u64, init_off), // DT_INIT_ARRAY（identity：VA == off）
        (0x1b, init_sz),      // DT_INIT_ARRAYSZ
        (4, hash_off),        // DT_HASH
        (6, sym_off),         // DT_SYMTAB
        (5, str_off),         // DT_STRTAB
        (10, str_sz),         // DT_STRSZ
        (11, 24),             // DT_SYMENT
    ] {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&0u64.to_le_bytes()); // DT_NULL tag
    out.extend_from_slice(&0u64.to_le_bytes()); // value
    let dyn_sz = (out.len() as u64) - dyn_off;

    // 回填 phdr：[0] PT_LOAD（identity），[1] PT_DYNAMIC
    let put_ph = |out: &mut Vec<u8>, i: usize, ty: u32, off: u64, vaddr: u64, filesz: u64| {
        let b = ph_base + i * 56;
        out[b..b + 4].copy_from_slice(&ty.to_le_bytes());
        out[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
        out[b + 16..b + 24].copy_from_slice(&vaddr.to_le_bytes());
        out[b + 32..b + 40].copy_from_slice(&filesz.to_le_bytes());
        out[b + 40..b + 48].copy_from_slice(&filesz.to_le_bytes());
    };
    let filesz = (out.len() as u64) - 0x1000;
    put_ph(&mut out, 0, 1, 0x1000, 0x1000, filesz);
    put_ph(&mut out, 1, 2, dyn_off, dyn_off, dyn_sz);
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

    // so：真导出表——目标符号（VA 0x204）+ 一个干扰符号（防误命中的查表检验）
    w.start_file("lib/arm64-v8a/libtest.so", opts).unwrap();
    let elf = build_minimal_elf(&[
        ("Java_com_example_NativeProbe_nativeFoo", 0x204, 64),
        ("_JNI_OnLoad", 0x300, 32),
    ]);
    w.write_all(&elf).unwrap();

    w.start_file("res/layout/main.xml", opts).unwrap();
    w.write_all(b"<layout/>").unwrap();

    w.finish().unwrap();
}

/// 一代壳形态的合成 APK（encrypted-payload 卡点的竖切 fixture）：
/// 好 classes.dex（stub 卡点）+ 坏 classes2.dex（payload 卡点）+ 高熵 asset
/// + 带 JNI_OnLoad 与 .init_array 的 so（解密例程候选定位）。
pub fn build_encrypted_apk(path: &std::path::Path) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    w.start_file("AndroidManifest.xml", opts).unwrap();
    w.write_all(&[0x03, 0x00, 0x08, 0x00, 0xff, 0xff]).unwrap();

    w.start_file("classes.dex", opts).unwrap();
    w.write_all(&build_minimal_dex()).unwrap();

    // "整体加密-单段型"的机械形态：声称是 DEX 但字节不是（seed 99 的伪随机字节）
    w.start_file("classes2.dex", opts).unwrap();
    w.write_all(&prng_bytes(99, 4096)).unwrap();

    w.start_file("assets/payload.bin", opts).unwrap();
    w.write_all(&prng_bytes(42, 4096)).unwrap();

    // so：stub 符号 + JNI_OnLoad（候选定位命中）+ .init_array 两条目
    w.start_file("lib/arm64-v8a/libtest.so", opts).unwrap();
    let elf = build_minimal_elf_v2(
        &[
            ("Java_com_example_NativeProbe_nativeFoo", 0x204, 64),
            ("JNI_OnLoad", 0x300, 32),
        ],
        &[0x200, 0x210],
    );
    w.write_all(&elf).unwrap();

    w.finish().unwrap();
}
