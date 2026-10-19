//! ELF64（arm64）导出符号解析——机械表遍历，零语义。
//! 目标：.dynsym × .dynstr → 已定义符号（st_shndx ≠ 0）的 name / st_value / st_size。
//! 敌意输入防线与 dex.rs 同款：所有 size/offset 字段先对照数据长度校验。

#[derive(Debug, Clone, PartialEq)]
pub struct ExportedSymbol {
    pub name: String,
    pub st_value: u64,
    pub st_size: u64,
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

    // 条目遍历（Elf64_Sym = 24 字节；st_shndx @ +16，st_value @ +8，st_size @ +20）
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
