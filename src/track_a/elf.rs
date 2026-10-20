//! ELF64（arm64）导出符号解析——机械表遍历，零语义。
//! 目标：.dynsym × .dynstr → 已定义符号（st_shndx ≠ 0）的 name / st_value / st_size。
//! 敌意输入防线与 dex.rs 同款：所有 size/offset 字段先对照数据长度校验。

#[derive(Debug, Clone, PartialEq)]
pub struct ExportedSymbol {
    pub name: String,
    pub st_value: u64,
    pub st_size: u64,
}

/// VA → 文件偏移映射（PT_LOAD：p_offset/p_vaddr/p_filesz）。
/// 无 PT_LOAD 且 va 落在文件内：退化直用（合成 so 的形态；真 so 恒有 PT_LOAD）。
pub fn va_to_file_offset(data: &[u8], va: u64) -> Result<u64, String> {
    let phoff = u64_at(data, 0x20)?;
    let phentsize = u16_at(data, 0x36)? as usize;
    let phnum = u16_at(data, 0x38)? as usize;
    if phnum == 0 || phentsize < 56 {
        // 退化：无 program header 的合成形态，va < len 时直用
        return if (va as usize) < data.len() {
            Ok(va)
        } else {
            Err(format!("elf: va 0x{va:x} out of file (no PT_LOAD)"))
        };
    }
    check(data, phoff, phnum as u64 * phentsize as u64, "program headers")?;
    for i in 0..phnum {
        let base = phoff as usize + i * phentsize;
        if u32_at(data, base)? != 1 {
            continue; // 非 PT_LOAD
        }
        let p_offset = u64_at(data, base + 8)?;
        let p_vaddr = u64_at(data, base + 16)?;
        let p_filesz = u64_at(data, base + 32)?;
        if va >= p_vaddr && va < p_vaddr + p_filesz {
            return Ok(va - p_vaddr + p_offset);
        }
    }
    Err(format!("elf: va 0x{va:x} not in any PT_LOAD"))
}

const SHT_DYNSYM: u32 = 11;

fn u16_at(d: &[u8], o: usize) -> Result<u16, String> {
    let b = d.get(o..o + 2).ok_or("elf: u16 out of bounds")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, String> {
    let b = d.get(o..o + 4).ok_or("elf: u32 out of bounds")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], o: usize) -> Result<u64, String> {
    let b = d.get(o..o + 8).ok_or("elf: u64 out of bounds")?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn check(d: &[u8], off: u64, size: u64, what: &str) -> Result<(), String> {
    let end = (off as usize)
        .checked_add(size as usize)
        .ok_or_else(|| format!("elf: {what} overflow"))?;
    if end > d.len() {
        return Err(format!("elf: {what} out of bounds {off}+{size}>{}", d.len()));
    }
    Ok(())
}

/// 解析 ELF64 导出符号表（修正案 #3：全部 ELF64 架构——符号表是格式事实，无架构语义；
/// 实战修正：arm64-only 限制曾使同包的 x86_64 壳 so 情报全部丢失）。
/// ELF32 不支持（Err——调用方按空表处理，事实如实）。
/// 双路径：PT_DYNAMIC（运行时视角，壳剥 section header 依然可见）优先；
/// 无 PT_DYNAMIC（静态/合成 fixture）→ section header 路径（SHT_DYNSYM）。
pub fn exported_symbols(data: &[u8]) -> Result<Vec<ExportedSymbol>, String> {
    if !data.starts_with(b"\x7fELF") {
        return Err("elf: not an ELF (magic)".into());
    }
    if data.get(4) != Some(&2) {
        return Err("elf: not ELF64".into());
    }
    if let Some(v) = dynamic_dynsym(data)? {
        return Ok(v); // 运行时视角优先
    }
    let shoff = u64_at(data, 0x28)?;
    let shentsize = u16_at(data, 0x3a)?;
    let shnum = u16_at(data, 0x3c)?;
    let _shstrndx = u16_at(data, 0x3e)?;
    let shentsize = shentsize as usize;
    let shnum = shnum as usize;

    check(data, shoff, shnum as u64 * shentsize as u64, "section headers")?;

    // section header 读取器
    let sh = |i: usize| -> Result<[u64; 6], String> {
        let base = shoff as usize + i * shentsize;
        Ok([
            u32_at(data, base)? as u64,          // sh_name
            u32_at(data, base + 4)? as u64,      // sh_type
            u64_at(data, base + 0x18)?,          // sh_offset
            u64_at(data, base + 0x20)?,          // sh_size
            u32_at(data, base + 0x28)? as u64,   // sh_link
            u64_at(data, base + 0x38)?,          // sh_entsize
        ])
    };

    // shstrtab 仅为段名服务；dynsym 按 sh_type（SHT_DYNSYM）+ sh_link 定位，无需段名

    // 找 .dynsym（类型 SHT_DYNSYM 优先，按规范 link 指向 .dynstr）
    let mut dynsym: Option<[u64; 6]> = None;
    for i in 0..shnum {
        let h = sh(i)?;
        if h[1] == SHT_DYNSYM as u64 {
            dynsym = Some(h);
            break;
        }
    }
    let Some(dynsym) = dynsym else {
        return Ok(Vec::new()); // 无 dynsym：空导出表（合法事实）
    };

    // .dynstr = dynsym.sh_link 指向的段
    let dynstr_hdr = sh(dynsym[4] as usize).map_err(|e| format!("elf: dynstr link: {e}"))?;
    check(data, dynsym[2], dynsym[3], "dynsym")?;
    check(data, dynstr_hdr[2], dynstr_hdr[3], "dynstr")?;
    let dynstr = &data[dynstr_hdr[2] as usize..(dynstr_hdr[2] + dynstr_hdr[3]) as usize];

    let str_at = |off: u64| -> String {
        let start = off as usize;
        let end = dynstr[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(start);
        String::from_utf8_lossy(&dynstr[start..end]).into_owned()
    };

    // 条目遍历（Elf64_Sym = 24 字节；st_shndx @ +6，st_value @ +8，st_size @ +16）
    let entsize = if dynsym[5] == 0 { 24 } else { dynsym[5] as usize };
    if entsize < 24 {
        return Err("elf: dynsym entsize < 24".into());
    }
    let count = (dynsym[3] as usize) / entsize;
    let mut out = Vec::with_capacity(count.min(1 << 16)); // 敌意 size 上限：预分配受控
    for i in 0..count {
        let base = dynsym[2] as usize + i * entsize;
        if base + 24 > data.len() {
            return Err("elf: dynsym entry out of bounds".into());
        }
        let st_name = u32_at(data, base)? as u64;
        let st_shndx = u16_at(data, base + 6)?;
        if st_shndx == 0 {
            continue; // SHN_UNDEF：导入符号，非本 so 定义
        }
        out.push(ExportedSymbol {
            name: str_at(st_name),
            st_value: u64_at(data, base + 8)?,
            st_size: u64_at(data, base + 16)?,
        });
    }
    Ok(out)
}

// ─── PT_DYNAMIC 运行时视角（修正案 #3）───
// 壳可剥 section header，剥不掉动态段——系统 linker 加载 so 只读 program headers，
// 故 DT_SYMTAB/DT_STRTAB/DT_INIT_ARRAY 永远在 PT_DYNAMIC 里（运行时事实，机械可读）。

const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_SYMENT: u64 = 11;
const DT_INIT_ARRAY: u64 = 0x19;
const DT_INIT_ARRAYSZ: u64 = 0x1b;
const DT_GNU_HASH: u64 = 0x6ffffef5;

/// PT_DYNAMIC 的 (p_offset, p_filesz)；无 → None。
fn pt_dynamic(data: &[u8]) -> Result<Option<(u64, u64)>, String> {
    let phoff = u64_at(data, 0x20)?;
    let phentsize = u16_at(data, 0x36)? as usize;
    let phnum = u16_at(data, 0x38)? as usize;
    if phnum == 0 || phentsize < 56 {
        return Ok(None);
    }
    check(data, phoff, phnum as u64 * phentsize as u64, "program headers")?;
    for i in 0..phnum {
        let base = phoff as usize + i * phentsize;
        if u32_at(data, base)? == 2 {
            // PT_DYNAMIC：p_offset @+8, p_filesz @+32
            return Ok(Some((u64_at(data, base + 8)?, u64_at(data, base + 32)?)));
        }
    }
    Ok(None)
}

/// PT_DYNAMIC 标签表（到 DT_NULL 止）。
fn dynamic_tags(data: &[u8]) -> Result<Option<Vec<(u64, u64)>>, String> {
    let Some((off, sz)) = pt_dynamic(data)? else {
        return Ok(None);
    };
    check(data, off, sz, "PT_DYNAMIC")?;
    let n = sz as usize / 16;
    let mut tags = Vec::with_capacity(n);
    for i in 0..n {
        let t = u64_at(data, off as usize + i * 16)?;
        let v = u64_at(data, off as usize + i * 16 + 8)?;
        if t == 0 {
            break; // DT_NULL
        }
        tags.push((t, v));
    }
    Ok(Some(tags))
}

/// 动态符号条目数（机械推导）：DT_HASH 的 nchain 直读；否则 DT_GNU_HASH 推导。
fn dyn_symcount(tags: &[(u64, u64)], data: &[u8]) -> Result<Option<u64>, String> {
    if let Some(&(_, hv)) = tags.iter().find(|(t, _)| *t == DT_HASH) {
        let hoff = va_to_file_offset(data, hv)?;
        check(data, hoff, 8, "DT_HASH header")?;
        return Ok(Some(u32_at(data, hoff as usize + 4)? as u64)); // nchain
    }
    if let Some(&(_, gv)) = tags.iter().find(|(t, _)| *t == DT_GNU_HASH) {
        let gh = va_to_file_offset(data, gv)? as usize;
        let nbuckets = u32_at(data, gh)? as usize;
        let symoffset = u32_at(data, gh + 4)? as usize;
        let bloom_size = u32_at(data, gh + 8)? as usize;
        let buckets = gh + 16 + bloom_size * 8;
        check(data, buckets as u64, nbuckets as u64 * 4, "gnu_hash buckets")?;
        let mut max_idx = 0usize;
        for i in 0..nbuckets {
            let v = u32_at(data, buckets + i * 4)? as usize;
            if v > max_idx {
                max_idx = v;
            }
        }
        if max_idx == 0 {
            return Ok(Some(0));
        }
        let chain = buckets + nbuckets * 4;
        let mut i = max_idx;
        loop {
            if i >= (1 << 20) {
                return Ok(None); // 敌意链：放弃推导，回退 section 路径
            }
            check(data, chain as u64 + (i - symoffset) as u64 * 4, 4, "gnu_hash chain")?;
            if u32_at(data, chain + (i - symoffset) * 4)? & 1 == 1 {
                break;
            }
            i += 1;
        }
        return Ok(Some(i as u64 + 1));
    }
    Ok(None)
}

/// PT_DYNAMIC 路径的动态符号表（运行时视角——修正案 #3）。
/// 无 PT_DYNAMIC / 缺关键标签 → None（调用方回退 section header 路径）。
pub fn dynamic_dynsym(data: &[u8]) -> Result<Option<Vec<ExportedSymbol>>, String> {
    let Some(tags) = dynamic_tags(data)? else {
        return Ok(None);
    };
    let Some(&(_, sv)) = tags.iter().find(|(t, _)| *t == DT_SYMTAB) else {
        return Ok(None);
    };
    let Some(&(_, tv)) = tags.iter().find(|(t, _)| *t == DT_STRTAB) else {
        return Ok(None);
    };
    let Some(n) = dyn_symcount(&tags, data)? else {
        return Ok(None);
    };
    let syment = tags.iter().find(|(t, _)| *t == DT_SYMENT).map(|&(_, v)| v as usize).unwrap_or(24);
    if syment < 24 {
        return Ok(None);
    }
    let symtab = va_to_file_offset(data, sv)?;
    let strtab = va_to_file_offset(data, tv)?;
    check(data, symtab, n * syment as u64, "DT_SYMTAB")?;
    // DT_STRSZ(0xa) 在则校验 strtab 边界；缺席时名字读取以文件尾兜底 + 越界跳过
    if let Some(&(_, sz)) = tags.iter().find(|(t, _)| *t == 10) {
        check(data, strtab, sz, "DT_STRTAB")?;
    }
    let mut out = Vec::with_capacity((n as usize).min(1 << 16));
    let base_str = strtab as usize;
    for i in 0..n as usize {
        let base = symtab as usize + i * syment;
        if base + 24 > data.len() {
            return Err("elf: DT_SYMTAB entry out of bounds".into());
        }
        let st_name = u32_at(data, base)? as usize;
        let st_shndx = u16_at(data, base + 6)?;
        if st_shndx == 0 {
            continue; // SHN_UNDEF
        }
        let start = base_str + st_name;
        if start >= data.len() {
            continue; // 敌意名偏移：跳过（事实层不炸）
        }
        let end = data[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(data.len());
        out.push(ExportedSymbol {
            name: String::from_utf8_lossy(&data[start..end]).into_owned(),
            st_value: u64_at(data, base + 8)?,
            st_size: u64_at(data, base + 16)?,
        });
    }
    Ok(Some(out))
}

/// PT_DYNAMIC 路径的 init_array（linker 真正执行的初始化器清单——修正案 #3）。
pub fn dynamic_init_array(data: &[u8]) -> Result<Option<InitArrayInfo>, String> {
    let Some(tags) = dynamic_tags(data)? else {
        return Ok(None);
    };
    let (Some(&(_, iva)), Some(&(_, isz))) = (
        tags.iter().find(|(t, _)| *t == DT_INIT_ARRAY),
        tags.iter().find(|(t, _)| *t == DT_INIT_ARRAYSZ),
    ) else {
        return Ok(None);
    };
    let off = va_to_file_offset(data, iva)?;
    check(data, off, isz, "DT_INIT_ARRAY")?;
    Ok(Some(InitArrayInfo {
        file_offset: off,
        size: isz,
        entry_count: isz / 8,
    }))
}

// ─── .init_array 解析（解密例程候选定位的机械来源；只报位置与条目数，零语义）───

/// e_machine → Android ABI 名（格式事实映射，非猜测）。
/// ELF32/64 的 e_machine 同在 0x12。未知机器 → None。
pub fn machine_abi(data: &[u8]) -> Option<String> {
    if !data.starts_with(b"\x7fELF") {
        return None;
    }
    let m = u16_at(data, 0x12).ok()?;
    Some(match m {
        183 => "arm64-v8a",  // EM_AARCH64
        40 => "armeabi-v7a", // EM_ARM
        62 => "x86_64",      // EM_X86_64
        3 => "x86",           // EM_386
        _ => return None,
    }
    .to_string())
}

/// .init_array 段的格式事实（不含条目内容——指针指向的函数体无边界，不切片不猜测）。
#[derive(Debug, Clone, PartialEq)]
pub struct InitArrayInfo {
    pub file_offset: u64,
    pub size: u64,
    /// size / 8（Elf64_Addr 条目数）
    pub entry_count: u64,
}

/// 按段名找 .init_array。无此段 → None（事实，不是错误）。ELF64 全架构（格式事实）。
/// 修正案 #3 双路径：DT_INIT_ARRAY（linker 真正执行的清单）优先，section 名路径后备。
pub fn init_array(data: &[u8]) -> Result<Option<InitArrayInfo>, String> {
    if !data.starts_with(b"\x7fELF") || data.get(4) != Some(&2) {
        return Ok(None);
    }
    if let Some(x) = dynamic_init_array(data)? {
        return Ok(Some(x)); // 运行时视角优先
    }
    let shoff = u64_at(data, 0x28)?;
    let shentsize = u16_at(data, 0x3a)? as usize;
    let shnum = u16_at(data, 0x3c)? as usize;
    let shstrndx = u16_at(data, 0x3e)? as usize;
    if shnum == 0 || shentsize < 64 || shstrndx >= shnum {
        return Ok(None); // 表残缺：无事实可报，空手退出
    }
    check(data, shoff, shnum as u64 * shentsize as u64, "section headers")?;

    let str_hdr = shoff as usize + shstrndx * shentsize;
    let str_off = u64_at(data, str_hdr + 0x18)?;
    let str_size = u64_at(data, str_hdr + 0x20)?;
    check(data, str_off, str_size, "shstrtab")?;
    let shstrtab = &data[str_off as usize..(str_off + str_size) as usize];

    let name_at = |off: u64| -> bool {
        let s = off as usize;
        if s >= shstrtab.len() {
            return false;
        }
        let end = shstrtab[s..].iter().position(|&b| b == 0).map(|p| s + p).unwrap_or(s);
        &shstrtab[s..end] == b".init_array"
    };

    for i in 0..shnum {
        let base = shoff as usize + i * shentsize;
        let sh_name = u32_at(data, base)? as u64;
        if name_at(sh_name) {
            let off = u64_at(data, base + 0x18)?;
            let size = u64_at(data, base + 0x20)?;
            check(data, off, size, "init_array")?;
            return Ok(Some(InitArrayInfo {
                file_offset: off,
                size,
                entry_count: size / 8,
            }));
        }
    }
    Ok(None)
}
