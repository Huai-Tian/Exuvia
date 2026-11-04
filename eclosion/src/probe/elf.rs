// ELF64 动态符号解析:从磁盘上的 libart.so 读出 .dynsym 全量符号
// (经 PT_DYNAMIC + DT_GNU_HASH/DT_HASH 遍历,不依赖 section header——
// 设备上的库可能被剥 section)。
use crate::{emit, jh, jn, js};

pub struct DynSym { pub name: String, pub value: u64, pub size: u64 }

fn r16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn r32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn r64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

pub struct Elf {
    pub data: Vec<u8>,
    pub load_bias_file: u64, // 最小 PT_LOAD p_vaddr(算装载 slide 用)
    pub dynsym_off: u64,
    pub dynstr_off: u64,
    pub nsyms: u64,
}

pub fn load(path: &str) -> Result<Elf, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return Err(format!("{path}: not ELF64"));
    }
    let phoff = r64(&data, 32) as usize;
    let phnum = r16(&data, 56) as usize;
    let phentsize = r16(&data, 54) as usize;
    let mut dyn_off = 0u64;
    let mut load_bias_file = u64::MAX;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = r32(&data, ph);
        if p_type == 2 { // PT_DYNAMIC
            dyn_off = r64(&data, ph + 8);
        } else if p_type == 1 { // PT_LOAD
            let v = r64(&data, ph + 16);
            load_bias_file = load_bias_file.min(v);
        }
    }
    if dyn_off == 0 || load_bias_file == u64::MAX {
        return Err("missing PT_DYNAMIC/PT_LOAD".into());
    }
    // 扫 dynamic 段拿 DT_SYMTAB/DT_STRTAB/DT_GNU_HASH/DT_HASH
    let (mut symtab, mut strtab, mut gnu_hash, mut hash) = (0u64, 0u64, 0u64, 0u64);
    let mut off = dyn_off as usize;
    loop {
        let tag = r64(&data, off) as i64;
        let val = r64(&data, off + 8);
        if tag == 0 { break; }
        match tag {
            6 => symtab = val,
            5 => strtab = val,
            0x6ffffef5 => gnu_hash = val,
            4 => hash = val,
            _ => {}
        }
        off += 16;
    }
    // vaddr -> file offset:按 PT_LOAD 逐个换算
    let v2o = |v: u64| -> Result<u64, String> {
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            if r32(&data, ph) == 1 {
                let (fo, va, fs) = (r64(&data, ph + 8), r64(&data, ph + 16), r64(&data, ph + 32));
                if va <= v && v < va + fs { return Ok(fo + (v - va)); }
            }
        }
        Err(format!("vaddr 0x{v:x} not in any LOAD"))
    };
    // 符号总数:优先 DT_HASH 的 nchain;只有 gnu_hash 时按 bucket/chain 推上界
    let nsyms: u64 = if hash != 0 {
        let ho = v2o(hash)? as usize;
        let nchain = r32(&data, ho + 4);
        nchain as u64
    } else if gnu_hash != 0 {
        let go = v2o(gnu_hash)? as usize;
        let nbuckets = r32(&data, go) as usize;
        let symoffset = r32(&data, go + 4);
        let bloom_size = r32(&data, go + 8) as usize;
        let buckets_off = go + 16 + bloom_size * 8;
        let mut maxb = 0u32;
        for i in 0..nbuckets { maxb = maxb.max(r32(&data, buckets_off + i * 4)); }
        let mut n = maxb;
        if maxb >= symoffset {
            let chains_off = buckets_off + nbuckets * 4;
            loop {
                let h = r32(&data, chains_off + ((n - symoffset) as usize) * 4);
                n += 1;
                if h & 1 == 1 { break; }
                if n > 1_000_000 { return Err("gnu_hash chain runaway".into()); }
            }
        }
        n as u64
    } else {
        return Err("no DT_HASH/DT_GNU_HASH".into());
    };
    let dynsym_off = v2o(symtab)?;
    let dynstr_off = v2o(strtab)?;
    Ok(Elf { data, load_bias_file, dynsym_off, dynstr_off, nsyms })
}

impl Elf {
    pub fn syms(&self) -> Vec<DynSym> {
        let mut out = Vec::new();
        for i in 0..self.nsyms as usize {
            let so = self.dynsym_off as usize + i * 24;
            if so + 24 > self.data.len() { break; }
            let name_off = r32(&self.data, so) as usize;
            let no = self.dynstr_off as usize + name_off;
            if no >= self.data.len() { continue; }
            let end = self.data[no..].iter().position(|&c| c == 0).unwrap_or(64);
            let name = String::from_utf8_lossy(&self.data[no..no + end]).to_string();
            out.push(DynSym { name, value: r64(&self.data, so + 8), size: r64(&self.data, so + 16) });
        }
        out
    }
}

// 探针#11 前半个问题:libart.so 里有哪些可用抓手符号
pub fn probe_symbols(path: &str) {
    match load(path) {
        Err(e) => emit(&[("k", js("elf_error")), ("path", js(path)), ("err", js(&e))]),
        Ok(elf) => {
            let syms = elf.syms();
            emit(&[("k", js("elf")), ("path", js(path)),
                   ("dynsym_count", jn(syms.len())),
                   ("load_bias_file", jh(elf.load_bias_file))]);
            // Runtime 抓手候选:凡名字含 Runtime 的都报上来,带回来分析
            for s in syms.iter().filter(|s| s.name.contains("Runtime")) {
                emit(&[("k", js("sym_candidate")), ("name", js(&s.name)),
                       ("value", jh(s.value)), ("size", jn(s.size))]);
            }
            // DexFile 注册相关符号(佐证"注册必经此处"的教义)
            for s in syms.iter().filter(|s| s.name.contains("DexFile")
                && (s.name.contains("Open") || s.name.contains("Register"))) {
                emit(&[("k", js("sym_dexreg")), ("name", js(&s.name)), ("value", jh(s.value))]);
            }
            let has_instance = syms.iter().any(|s| s.name == "_ZN3art7Runtime9instance_E");
            emit(&[("k", js("sym_runtime_instance")), ("present", jn(has_instance as u8))]);
        }
    }
}
