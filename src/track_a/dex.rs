//! DEX 结构解析——机械表遍历，零语义。
//! 只提取格式事实：header / string / type / proto / method / class_def / class_data，
//! 以及 access_flags 的 ACC_NATIVE 位（方法体不在 DEX 内的结构事实）。

/// uleb128 解码（DEX 标准）。
fn uleb(data: &[u8], off: &mut usize) -> Result<u32, String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let b = *data.get(*off).ok_or("uleb out of bounds")?;
        *off += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 28 {
            return Err("uleb overflow".into());
        }
    }
}

fn u32_at(data: &[u8], off: usize) -> Result<u32, String> {
    let b = data.get(off..off + 4).ok_or("u32 out of bounds")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// DEX 方法清点结果（格式事实）。
#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub class: String,
    pub name: String,
    pub descriptor: String,
    pub access_flags: u32,
    pub is_native: bool,
}

pub const ACC_NATIVE: u32 = 0x100;

struct Dex<'a> {
    data: &'a [u8],
}

impl<'a> Dex<'a> {
    fn u32(&self, off: usize) -> Result<u32, String> {
        u32_at(self.data, off)
    }

    /// MUTF-8 字符串（uleb 长度前缀 + \0 结尾；类名方法名以 ASCII 为主，lossy 足够 v0.1）
    fn string(&self, off: usize) -> Result<String, String> {
        let mut p = off;
        let _utf16_len = uleb(self.data, &mut p)?;
        let start = p;
        while *self.data.get(p).ok_or("string no terminator")? != 0 {
            p += 1;
        }
        Ok(String::from_utf8_lossy(&self.data[start..p]).into_owned())
    }

    fn string_by_idx(&self, idx: u32, string_ids_off: usize) -> Result<String, String> {
        let off = self.u32(string_ids_off + (idx as usize) * 4)? as usize;
        self.string(off)
    }

    fn type_descriptor(&self, idx: u32, string_ids_off: usize, type_ids_off: usize) -> Result<String, String> {
        let sidx = self.u32(type_ids_off + (idx as usize) * 4)?;
        self.string_by_idx(sidx, string_ids_off)
    }

    /// proto → "(p1p2)ret" 形式 descriptor
    fn proto_descriptor(&self, idx: u32, string_ids_off: usize, type_ids_off: usize, proto_ids_off: usize) -> Result<String, String> {
        let base = proto_ids_off + (idx as usize) * 12;
        let return_idx = self.u32(base + 4)?;
        let params_off = self.u32(base + 8)?;
        let mut params = String::new();
        params.push('(');
        if params_off > 0 {
            let n = self.u32(params_off as usize)? as usize;
            for i in 0..n {
                let tidx = self.u32(params_off as usize + 4 + i * 4)?;
                params.push_str(&self.type_descriptor(tidx, string_ids_off, type_ids_off)?);
            }
        }
        params.push(')');
        params.push_str(&self.type_descriptor(return_idx, string_ids_off, type_ids_off)?);
        Ok(params)
    }
}

/// 敌意输入防线：表范围校验——任何 size 字段先对照数据长度，再谈分配。
fn check_table(data: &[u8], off: u32, size: u32, item_size: usize, what: &str) -> Result<(), String> {
    let off = off as usize;
    let bytes = size
        .checked_mul(item_size as u32)
        .ok_or_else(|| format!("{what} size overflow"))?;
    let end = off.checked_add(bytes as usize).ok_or_else(|| format!("{what} offset overflow"))?;
    if end > data.len() {
        return Err(format!("{what} out of bounds: {off}+{bytes} > {}", data.len()));
    }
    Ok(())
}

/// 解析 DEX，返回全部方法（含非 native——供后续段清点，native 由 debt 阶段过滤）。
pub fn parse(data: &[u8]) -> Result<Vec<MethodInfo>, String> {
    if !data.starts_with(b"dex\n") || data.get(7) != Some(&0) {
        return Err("not a DEX (magic mismatch)".into());
    }
    let dex = Dex { data };
    let string_ids_size = dex.u32(0x38)?;
    let string_ids_off = dex.u32(0x3c)?;
    let type_ids_size = dex.u32(0x40)?;
    let type_ids_off = dex.u32(0x44)?;
    let proto_ids_size = dex.u32(0x48)?;
    let proto_ids_off = dex.u32(0x4c)?;
    let method_ids_size = dex.u32(0x58)?;
    let method_ids_off = dex.u32(0x5c)?;
    let class_defs_size = dex.u32(0x60)?;
    let class_defs_off = dex.u32(0x64)?;

    check_table(data, string_ids_off, string_ids_size, 4, "string_ids")?;
    check_table(data, type_ids_off, type_ids_size, 4, "type_ids")?;
    check_table(data, proto_ids_off, proto_ids_size, 12, "proto_ids")?;
    check_table(data, method_ids_off, method_ids_size, 12, "method_ids")?;
    check_table(data, class_defs_off, class_defs_size, 32, "class_defs")?;

    let string_ids_off = string_ids_off as usize;
    let type_ids_off = type_ids_off as usize;
    let proto_ids_off = proto_ids_off as usize;
    let class_defs_off = class_defs_off as usize;
    let method_ids_off = method_ids_off as usize;

    // method_ids 全量解引用（class / name / descriptor）
    let method_ids_off = method_ids_off as usize;
    let mut methods: Vec<(String, String, String)> = Vec::with_capacity(method_ids_size as usize);
    for i in 0..method_ids_size as usize {
        let base = method_ids_off + i * 12;
        let class_idx = dex.u32(base)?;
        let proto_idx = dex.u32(base + 4)?;
        let name_idx = dex.u32(base + 8)?;
        let class = dex.type_descriptor(class_idx, string_ids_off, type_ids_off)?;
        let name = dex.string_by_idx(name_idx, string_ids_off)?;
        let descriptor = dex.proto_descriptor(proto_idx, string_ids_off, type_ids_off, proto_ids_off)?;
        methods.push((class, name, descriptor));
    }

    // class_defs → class_data → 方法访问标志
    let mut out = Vec::new();
    for c in 0..class_defs_size as usize {
        let base = class_defs_off + c * 32;
        let class_data_off = dex.u32(base + 24)? as usize;
        if class_data_off == 0 {
            continue;
        }
        let mut p = class_data_off;
        let static_fields = uleb(data, &mut p)?;
        let instance_fields = uleb(data, &mut p)?;
        let direct_methods = uleb(data, &mut p)?;
        let virtual_methods = uleb(data, &mut p)?;
        for _ in 0..(static_fields + instance_fields) {
            uleb(data, &mut p)?; // field_idx_diff
            uleb(data, &mut p)?; // access_flags
        }
        let total = direct_methods + virtual_methods;
        let mut idx: u32 = 0;
        for _ in 0..total {
            let diff = uleb(data, &mut p)?;
            let access = uleb(data, &mut p)?;
            let _code_off = uleb(data, &mut p)?;
            idx += diff;
            if let Some((class, name, descriptor)) = methods.get(idx as usize).cloned() {
                out.push(MethodInfo {
                    class,
                    name,
                    descriptor,
                    access_flags: access,
                    is_native: access & ACC_NATIVE != 0,
                });
            }
        }
    }
    Ok(out)
}
