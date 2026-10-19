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

const EM_AARCH64: u16 = 183;
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

/// 解析 ELF64 导出符号表。arm64（EM_AARCH64）；其他架构返回空表（事实如实，不猜）。
pub fn exported_symbols(data: &[u8]) -> Result<Vec<ExportedSymbol>, String> {
    if !data.starts_with(b"\x7fELF") {
        return Err("elf: not an ELF (magic)".into());
    }
    if data.get(4) != Some(&2) {
        return Err("elf: not ELF64".into());
    }
    let machine = u16_at(data, 0x12)?;
    if machine != EM_AARCH64 {
        return Ok(Vec::new()); // 非 arm64：空表（事实，不是错误）
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

// ─── .init_array 解析（解密例程候选定位的机械来源；只报位置与条目数，零语义）───

/// .init_array 段的格式事实（不含条目内容——指针指向的函数体无边界，不切片不猜测）。
#[derive(Debug, Clone, PartialEq)]
pub struct InitArrayInfo {
    pub file_offset: u64,
    pub size: u64,
    /// size / 8（Elf64_Addr 条目数）
    pub entry_count: u64,
}

/// 按段名找 .init_array（需要 shstrtab）。非 arm64 或无此段 → None（事实，不是错误）。
pub fn init_array(data: &[u8]) -> Result<Option<InitArrayInfo>, String> {
    if !data.starts_with(b"\x7fELF") || data.get(4) != Some(&2) {
        return Ok(None);
    }
    if u16_at(data, 0x12)? != EM_AARCH64 {
        return Ok(None);
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
