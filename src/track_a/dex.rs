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

fn u16_at(data: &[u8], off: usize) -> Result<u16, String> {
    let b = data.get(off..off + 2).ok_or("u16 out of bounds")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
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

    /// proto → "(p1p2)ret" 形式 descriptor。
    /// type_list 条目按 spec 为 u16（实战修正：合成 fixture 单参数未暴露的读法错误）。
    fn proto_descriptor(&self, idx: u32, string_ids_off: usize, type_ids_off: usize, proto_ids_off: usize) -> Result<String, String> {
        let base = proto_ids_off + (idx as usize) * 12;
        let return_idx = self.u32(base + 4)?;
        let params_off = self.u32(base + 8)?;
        let mut params = String::new();
        params.push('(');
        if params_off > 0 {
            let n = self.u32(params_off as usize)? as usize;
            for i in 0..n {
                let tidx = u16_at(self.data, params_off as usize + 4 + i * 2)?;
                params.push_str(&self.type_descriptor(tidx as u32, string_ids_off, type_ids_off)?);
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
    check_table(data, method_ids_off, method_ids_size, 8, "method_ids")?;
    check_table(data, class_defs_off, class_defs_size, 32, "class_defs")?;

    let string_ids_off = string_ids_off as usize;
    let type_ids_off = type_ids_off as usize;
    let proto_ids_off = proto_ids_off as usize;
    let class_defs_off = class_defs_off as usize;
    let method_ids_off = method_ids_off as usize;

    // method_ids 全量解引用（class / name / descriptor）。
    // method_id_item 按 spec：u16 class_idx / u16 proto_idx / u32 name_idx = 8 字节
    // （实战修正：原按 12 字节 u32 读，与真实 DEX 错位即越界——合成 fixture 同错咬合未暴露）
    let mut methods: Vec<(String, String, String)> = Vec::with_capacity(method_ids_size as usize);
    for i in 0..method_ids_size as usize {
        let base = method_ids_off + i * 8;
        let class_idx = u16_at(data, base)? as u32;
        let proto_idx = u16_at(data, base + 2)? as u32;
        let name_idx = dex.u32(base + 4)?;
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
        let total = [direct_methods, virtual_methods];
        for count in total {
            // method_idx_diff 每表归零（spec：direct/virtual 两表各自首项为绝对
            // 索引）——跨表累加会把 virtual 表整体误归到 direct 末项之后。
            let mut idx: u32 = 0;
            for _ in 0..count {
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
    }
    Ok(out)
}


/// 测试与修复管线共用的合成 fixture（零样本纪律）：单类 LC;，direct 表一项
/// = static native "zap"（method_ids 索引 1，名字排序在 virtual 之后），
/// virtual 表一项 = native "onCreate"（索引 0——virtual 表首项为绝对索引，
/// 两表各自归零是 spec 事实；跨表累加会把 onCreate 误归为 zap 的第二次出现）。
#[cfg(test)]
pub(crate) fn hollow_dex_fixture() -> Vec<u8> {
    fn uleb_bytes(mut v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }
    let strings = ["LC;", "V", "onCreate", "zap"];
    let mut data = vec![0u8; 0x70];
    data[0..8].copy_from_slice(b"dex\n035\0");
    data[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes()); // header_size
    data[0x28..0x2c].copy_from_slice(&0x12345678u32.to_le_bytes()); // endian_tag

    let string_ids_off = 0x70usize;
    let type_ids_off = string_ids_off + strings.len() * 4; // 0x80
    let proto_ids_off = type_ids_off + 2 * 4; // 0x88
    let method_ids_off = proto_ids_off + 12; // 0x94
    let class_defs_off = method_ids_off + 2 * 8; // 0xa4
    let class_data_off = class_defs_off + 32; // 0xc4

    // class_data：0 字段；direct=1(zap, native|static)，virtual=1(onCreate, native)
    let mut class_data = Vec::new();
    for v in [0u32, 0, 1, 1] {
        class_data.extend(uleb_bytes(v));
    }
    class_data.extend(uleb_bytes(1)); // direct: method_idx_diff=1 → zap
    class_data.extend(uleb_bytes(0x108)); // public|static|native
    class_data.extend(uleb_bytes(0)); // code_off=0（空心桩）
    class_data.extend(uleb_bytes(0)); // virtual: 绝对索引 0 → onCreate（归零判别点）
    class_data.extend(uleb_bytes(0x101)); // public|native
    class_data.extend(uleb_bytes(0));

    let mut str_offs = Vec::new();
    let mut cursor = class_data_off + class_data.len();
    for s in strings {
        str_offs.push(cursor as u32);
        cursor += uleb_bytes(s.chars().count() as u32).len() + s.len() + 1;
    }
    data.resize(cursor, 0);

    data[0x38..0x3c].copy_from_slice(&(strings.len() as u32).to_le_bytes());
    data[0x3c..0x40].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
    data[0x40..0x44].copy_from_slice(&2u32.to_le_bytes());
    data[0x44..0x48].copy_from_slice(&(type_ids_off as u32).to_le_bytes());
    data[0x48..0x4c].copy_from_slice(&1u32.to_le_bytes());
    data[0x4c..0x50].copy_from_slice(&(proto_ids_off as u32).to_le_bytes());
    data[0x58..0x5c].copy_from_slice(&2u32.to_le_bytes());
    data[0x5c..0x60].copy_from_slice(&(method_ids_off as u32).to_le_bytes());
    data[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
    data[0x64..0x68].copy_from_slice(&(class_defs_off as u32).to_le_bytes());

    for (i, off) in str_offs.iter().enumerate() {
        data[string_ids_off + i * 4..string_ids_off + i * 4 + 4].copy_from_slice(&off.to_le_bytes());
    }
    // type_ids：type0 → "LC;"，type1 → "V"
    data[type_ids_off..type_ids_off + 4].copy_from_slice(&0u32.to_le_bytes());
    data[type_ids_off + 4..type_ids_off + 8].copy_from_slice(&1u32.to_le_bytes());
    // proto0：shorty "V"，return type1(V)，无参数
    data[proto_ids_off..proto_ids_off + 4].copy_from_slice(&1u32.to_le_bytes());
    data[proto_ids_off + 4..proto_ids_off + 8].copy_from_slice(&1u32.to_le_bytes());
    // method_ids：onCreate(name 2)、zap(name 3)，均 class0/proto0
    for (i, name_idx) in [2u32, 3].iter().enumerate() {
        let b = method_ids_off + i * 8;
        data[b..b + 2].copy_from_slice(&0u16.to_le_bytes());
        data[b + 2..b + 4].copy_from_slice(&0u16.to_le_bytes());
        data[b + 4..b + 8].copy_from_slice(&name_idx.to_le_bytes());
    }
    // class_def：class_idx 0，class_data_off 在 +24
    data[class_defs_off + 24..class_defs_off + 28]
        .copy_from_slice(&(class_data_off as u32).to_le_bytes());
    // class_data 与字符串数据
    data[class_data_off..class_data_off + class_data.len()].copy_from_slice(&class_data);
    for (s, off) in strings.iter().zip(str_offs.iter()) {
        let mut p = *off as usize;
        let l = uleb_bytes(s.chars().count() as u32);
        data[p..p + l.len()].copy_from_slice(&l);
        p += l.len();
        data[p..p + s.len()].copy_from_slice(s.as_bytes());
    }
    let size = data.len() as u32;
    data[0x20..0x24].copy_from_slice(&size.to_le_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_idx_diff_resets_per_list() {
        // 判别 fixture：direct 表独占索引 1（zap），virtual 表首项 diff=0。
        // 跨表累加的旧读法：virtual 首项解析为 1+0=1 → onCreate 丢失、zap 重复。
        let ms = parse(&hollow_dex_fixture()).expect("fixture parses");
        let names: Vec<&str> = ms.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["zap", "onCreate"], "per-list reset: {names:?}");
        assert!(ms.iter().all(|m| m.is_native));
        let onc = ms.iter().find(|m| m.name == "onCreate").unwrap();
        assert_eq!(onc.class, "LC;");
        assert_eq!(onc.descriptor, "()V");
    }
}
