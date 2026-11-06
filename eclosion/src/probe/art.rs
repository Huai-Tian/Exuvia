// 探针#11/#12:libart.so 符号定位 Runtime 单例 → 结构自发现走读 → DexFile 三重自证。
// 零注入:全程 process_vm_readv / /proc/pid/mem 只读;前后回读 TracerPid 证零附着。
use super::elf;
use super::memio::{cross_check, find_pid_by_pkg, read_maps, tracer_pid, Reader};
use crate::{emit, jh, jn, js};
use std::collections::{HashMap, HashSet, VecDeque};

const SCAN_SPAN: u64 = 0x1000;       // 常规节点扫 4KB
const ROOT_SPAN: u64 = 0x4000;       // Runtime 是大对象(class_linker_ 等字段可越过 2KB),首层扫 16KB
const MAX_NODES: usize = 20000;      // 走读节点上限(防爆)
const MAX_DEPTH: u8 = 6;             // Runtime→ClassLinker→容器→节点→DexFile 链至少 4 层
const ROUND_BUDGET_SECS: u64 = 180;  // 单轮时间预算,超时响亮相告

pub fn run(pkg: &str) {
    // 1. 按包名定位(裁定#22:进程名==包名)
    let pids = find_pid_by_pkg(pkg);
    if pids.is_empty() {
        emit(&[("k", js("art_error")), ("detail", js("package not running")), ("pkg", js(pkg))]);
        return;
    }
    let pid = pids[0];
    emit(&[("k", js("art_target")), ("pid", jn(pid)), ("pkg", js(pkg)), ("n_pids", jn(pids.len()))]);
    let tracer0 = tracer_pid(pid);

    // 2. maps 里找 libart.so,算 slide
    let maps = read_maps(pid);
    let art_ent = maps.iter().find(|m| m.path.ends_with("/libart.so")).cloned();
    let Some(art_ent) = art_ent else {
        emit(&[("k", js("art_error")), ("detail", js("libart.so not mapped"))]);
        return;
    };
    let elf_path = &art_ent.path;
    let elf = match elf::load(elf_path) {
        Ok(e) => e,
        Err(e) => { emit(&[("k", js("art_error")), ("detail", js(&format!("elf parse: {e}")))]); return; }
    };
    let slide = art_ent.start - elf.load_bias_file;
    emit(&[("k", js("art_lib")), ("path", js(elf_path)),
           ("map_base", jh(art_ent.start)), ("slide", jh(slide))]);

    // 磁盘符号面(#11 前半:有哪些抓手)
    elf::probe_symbols(elf_path);

    // 3. Runtime 单例
    let r = Reader::new(pid);
    let syms = elf.syms();
    let inst = syms.iter().find(|s| s.name == "_ZN3art7Runtime9instance_E");
    let runtime_ptr = match inst {
        Some(s) => {
            let slot = slide + s.value;
            let p = r.u64_at(slot).unwrap_or(0);
            emit(&[("k", js("art_runtime")), ("via", js("symbol:instance_")),
                   ("slot", jh(slot)), ("runtime", jh(p))]);
            p
        }
        None => {
            // 抓手缺席 = 大声报告 + 退而求其次:扫 libart 数据段找 Runtime 样结构
            emit(&[("k", js("art_runtime_missing")),
                   ("detail", js("symbol _ZN3art7Runtime9instance_E absent; falling back to data scan"))]);
            data_scan_for_runtime(&r, &maps, slide)
        }
    };
    if runtime_ptr == 0 || !r.is_readable(runtime_ptr) {
        emit(&[("k", js("art_error")), ("detail", js("runtime pointer unreadable")), ("runtime", jh(runtime_ptr))]);
        return;
    }

    // 4. 结构自发现走读 + DexFile 三重自证
    let mut confirmed_all: Vec<(u64, u64, String)> = Vec::new(); // (obj, begin, chain)
    for round in 0..3 {
        let found = walk_round(&r, &maps, runtime_ptr, round, pkg);
        let set: HashSet<u64> = found.iter().map(|&(b, _)| b).collect();
        emit(&[("k", js("dex_round")), ("round", jn(round)), ("count", jn(found.len()))]);
        if round == 0 {
            confirmed_all = found.iter().map(|&(b, o)| (o, b, String::new())).collect();
        } else {
            let prev: HashSet<u64> = confirmed_all.iter().map(|&(_, b, _)| b).collect();
            let inter: HashSet<u64> = prev.intersection(&set).cloned().collect();
            emit(&[("k", js("dex_stable")), ("round", jn(round)),
                   ("stable", jn(inter.len())), ("prev", jn(prev.len())), ("now", jn(set.len()))]);
        }
        if round < 2 { std::thread::sleep(std::time::Duration::from_secs(2)); }
    }

    // 5. 载荷直扫:不依赖任何结构模型,直接在全部可读映射里找 "dex\n" 魔数。
    //    与 Runtime 走读互为独立证据;壳把 dex 藏进匿名映射时这条是兜底主力。
    let maps2 = read_maps(pid);
    let payloads = scan_dex_payloads(&r, &maps2);

    // 6. 载荷身份识别 + 反查归属 + 链猎
    let walk_begins: HashSet<u64> = confirmed_all.iter().map(|&(_, b, _)| b).collect();
    let mut hunt_targets: Vec<u64> = Vec::new();
    for (begin, fsize, path, perm) in &payloads {
        identify_dex(&r, *begin, path, perm);
        if walk_begins.contains(begin) { continue; }
        let objs = hunt_dexfile_objects(&r, &maps2, *begin, *fsize, path, perm, pkg);
        hunt_targets.extend(objs);
    }
    hunt_targets.sort_unstable();
    hunt_targets.dedup();
    if !hunt_targets.is_empty() {
        chain_hunt(&r, &maps2, runtime_ptr, &hunt_targets);
    }

    // 7. 双通道互证 + 零痕迹回证
    let mut samples: Vec<u64> = confirmed_all.iter().take(3).map(|&(_, b, _)| b).collect();
    if samples.is_empty() {
        samples = payloads.iter().take(3).map(|&(b, _, _, _)| b).collect();
    }
    if !samples.is_empty() { cross_check(&r, &samples); }
    let tracer1 = tracer_pid(pid);
    emit(&[("k", js("zero_trace")),
           ("tracer_before", jn(tracer0)), ("tracer_after", jn(tracer1)),
           ("clean", jn((tracer0 == 0 && tracer1 == 0) as u8))]);
}

// 一轮走读:从 Runtime 广度优先,找 DexFile 对象(begin_ 指向 dex 魔数者)
// 返回 (begin_, dexfile_obj_addr) 列表
//
// 剪枝纪律(2026-11-06 真机教训:旧规则"目标首 u64 必须还是可读指针"把
// std::list 节点、Mutex 首字段等合法中间结构全部冤杀,三轮只扫到 16 节点):
// - dex 魔数检查对任何可读指针都做(无论目标映射权限)
// - 入队只要求目标落在可写映射(堆/arena/bss)——结构体字段语义剪枝
// - 去重在入队时完成;每轮有墙钟预算,超时响亮报告
fn walk_round(r: &Reader, maps: &[super::memio::MapEnt], runtime: u64, round: u32, pkg: &str)
    -> Vec<(u64, u64)>
{
    let readable = |a: u64| maps.iter().any(|m| m.start <= a && a < m.end && m.perm.contains('r'));
    let writable = |a: u64| maps.iter().any(|m| m.start <= a && a < m.end && m.perm.starts_with("rw"));
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, String, u8)> = VecDeque::new();
    visited.insert(runtime);
    queue.push_back((runtime, "R".to_string(), 0));
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut nodes = 0usize;
    let mut reads = 0usize;
    let mut direct_refs = 0usize;
    let t0 = std::time::Instant::now();
    let mut overtime = false;

    while let Some((addr, chain, depth)) = queue.pop_front() {
        if nodes >= MAX_NODES { break; }
        if t0.elapsed().as_secs() > ROUND_BUDGET_SECS { overtime = true; break; }
        nodes += 1;
        let mut span = if depth == 0 { ROOT_SPAN } else { SCAN_SPAN };
        // 跨距收缩到所在映射末尾——否则贴边的节点整段读取失败被静默跳过
        if let Some(m) = maps.iter().find(|m| m.start <= addr && addr < m.end) {
            span = span.min(m.end - addr) & !7;
        }
        if span < 8 { continue; }
        let Some(buf) = r.read(addr, span as usize) else { continue };
        reads += 1;
        for off in (0..span as usize).step_by(8) {
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            if v < 0x10000 || !readable(v) { continue; }
            let ch = format!("{chain}+0x{off:x}");
            // 直判: v 本身就是 dex 载荷起点(容器槽位/结构字段直接存 begin_ 指针)。
            // 真机实测:DexFile 对象本身走读未必到得了,但存 begin_ 的槽位可能到得了。
            if direct_refs < 32 {
                if let Some(mg) = r.read(v, 4) {
                    reads += 1;
                    if &mg == b"dex\n" {
                        emit(&[("k", js("dex_ref_direct")), ("chain", js(&ch)),
                               ("begin", jh(v)), ("round", jn(round))]);
                        direct_refs += 1;
                        continue;
                    }
                }
            }
            // v 指向的对象可能是 DexFile——但不能假设 begin_ 在 obj+0:
            // 新版 DexFile 有虚析构,obj+0 是 vtable(指向 libart),begin_ 在 obj+8
            // (2026-11-06 真机教训:只看 obj+0,三轮 1398 节点零命中)。
            // 故扫对象前 0x40 字节,任一 u64 字段指向 "dex\n" 即候选,字段偏移实测上报。
            if let Some(obj) = r.read(v, 0x40) {
                reads += 1;
                let mut matched = false;
                for fo in (0..0x40usize).step_by(8) {
                    let fv = u64::from_le_bytes(obj[fo..fo + 8].try_into().unwrap());
                    if fv < 0x10000 || !readable(fv) { continue; }
                    if let Some(magic) = r.read(fv, 4) {
                        reads += 1;
                        if &magic == b"dex\n" {
                            if validate_dexfile(r, v, fv, fo as u64, &ch, pkg) {
                                out.push((fv, v));
                            }
                            matched = true;
                            break; // 一个对象只报一次
                        }
                    }
                }
                if matched { continue; } // DexFile 对象不再向里走
            }
            // 继续向里走:目标须是可写映射里的结构体(堆/arena/bss)
            if depth < MAX_DEPTH && writable(v) && !visited.contains(&v) {
                visited.insert(v);
                queue.push_back((v, ch, depth + 1));
            }
        }
    }
    emit(&[("k", js("walk_stats")), ("round", jn(round)), ("nodes", jn(nodes)),
           ("queue_left", jn(queue.len())), ("reads", jn(reads)),
           ("elapsed_ms", jn(t0.elapsed().as_millis() as u64)),
           ("overtime", jn(overtime as u8))]);
    out
}

// 三重自证:魔数(调用方已验) + size_==header.file_size + location 串含 .apk/包名
// begin_off 为 begin_ 字段在对象内的实测偏移(0=无虚表旧布局,8=带 vtable 新布局)
fn validate_dexfile(r: &Reader, obj: u64, begin_: u64, begin_off: u64, chain: &str, pkg: &str) -> bool {
    let Some(hdr) = r.read(begin_, 0x40) else { return false };
    let file_size = u32::from_le_bytes(hdr[0x20..0x24].try_into().unwrap());
    let checksum = u32::from_le_bytes(hdr[0x08..0x0c].try_into().unwrap());
    if file_size < 0x70 || file_size > 256 * 1024 * 1024 { return false; }

    // size_ 紧跟 begin_ 字段(begin_@begin_off,size_@begin_off+8)
    let size_off = begin_off + 8;
    let size_at = r.u64_at(obj + size_off).unwrap_or(0);
    let size_ok = size_at == file_size as u64;

    // location_:扫 obj+0x10..0x50 找可解析的 cxx string
    // (vtable 布局把 location_ 推到 0x18 之后,范围放宽)
    let mut location = String::new();
    let mut loc_off = 0u64;
    for lo in (0x10u64..0x50).step_by(8) {
        if let Some(s) = r.cxx_string_at(obj + lo) {
            if s.contains(".apk") || s.contains("dex") || s.contains(pkg) || s.contains("base.apk") {
                location = s;
                loc_off = lo;
                break;
            }
        }
    }
    // location_checksum_:扫 obj+0x08..0x60 找等于 header checksum 的 u32
    let mut csum_off = 0u64;
    if let Some(body) = r.read(obj, 0x60) {
        for co in (0x08usize..0x60).step_by(4) {
            if u32::from_le_bytes(body[co..co + 4].try_into().unwrap()) == checksum && checksum != 0 {
                csum_off = co as u64;
                break;
            }
        }
    }

    let confirmed = size_ok && !location.is_empty();
    emit(&[
        ("k", js(if confirmed { "dex_confirmed" } else { "dex_candidate" })),
        ("via", js("runtime_walk")),
        ("chain", js(chain)),
        ("obj", jh(obj)), ("begin", jh(begin_)), ("begin_off", jh(begin_off)),
        ("file_size", jn(file_size)),
        ("size_off", jh(size_off)), ("size_field_ok", jn(size_ok as u8)),
        ("location", js(&location)), ("location_off", jh(loc_off)),
        ("checksum", jh(checksum as u64)), ("checksum_field_off", jh(csum_off)),
        ("pkg_in_location", jn(location.contains(pkg) as u8)),
    ]);
    confirmed
}

const CHUNK: usize = 1 << 20;              // 直扫/反查的读块 1MB(带 8B 重叠)
const MAX_SCAN_BYTES: u64 = 1 << 30;       // 每条通道的扫描总量上限 1GB

// 逐字节找 "dex\n"(先锚 'd' 再比尾巴,够快)
fn find_magic(buf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i] == b'd' && &buf[i + 1..i + 4] == b"\x65\x78\x0a" { // "ex\n"
            out.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

// 载荷直扫:在目标全部可读映射里找 dex 魔数,头部校验后上报。
// 返回 (begin, file_size, map_path, map_perm) 去重列表。
fn scan_dex_payloads(r: &Reader, maps: &[super::memio::MapEnt]) -> Vec<(u64, u64, String, String)> {
    let t0 = std::time::Instant::now();
    let mut out: Vec<(u64, u64, String, String)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut scanned = 0u64;
    let mut hits_raw = 0usize;
    let mut skipped_big = 0usize;

    for m in maps.iter().filter(|m| m.perm.contains('r')) {
        let len = m.end - m.start;
        if len > 512 * 1024 * 1024 { skipped_big += 1; continue; } // 巨型堆跳过(dex 不会住里面)
        if scanned >= MAX_SCAN_BYTES { break; }
        let mut off = 0u64;
        while off < len {
            // 尾部整块读,中间块多带 8B 重叠防魔数跨界
            let want = if off + CHUNK as u64 >= len { len - off } else { CHUNK as u64 + 8 };
            let Some(buf) = r.read(m.start + off, want as usize) else { off += CHUNK as u64; continue };
            scanned += buf.len() as u64;
            for pos in find_magic(&buf) {
                let begin = m.start + off + pos as u64;
                if !seen.insert(begin) { continue; }
                hits_raw += 1;
                // 头部校验:版本串(035/037/038/039/040/041) + file_size 合理
                let Some(hdr) = r.read(begin, 0x40) else { continue };
                let ver = &hdr[4..7];
                let ver_ok = matches!(ver, b"035" | b"036" | b"037" | b"038" | b"039" | b"040" | b"041");
                let file_size = u32::from_le_bytes(hdr[0x20..0x24].try_into().unwrap());
                let size_ok = file_size >= 0x70 && file_size <= 256 * 1024 * 1024;
                if ver_ok && size_ok {
                    emit(&[("k", js("dex_region")),
                           ("begin", jh(begin)),
                           ("version", js(&format!("{}{}{}", hdr[4] as char, hdr[5] as char, hdr[6] as char))),
                           ("file_size", jn(file_size)),
                           ("within_map", jn((begin + file_size as u64 <= m.end) as u8)),
                           ("map_path", js(&m.path)), ("map_perm", js(&m.perm))]);
                    out.push((begin, file_size as u64, m.path.clone(), m.perm.clone()));
                }
            }
            if off + CHUNK as u64 >= len { break; }
            off += CHUNK as u64;
        }
    }
    emit(&[("k", js("dex_region_stats")), ("found", jn(out.len())), ("raw_hits", jn(hits_raw)),
           ("scanned_mb", jn(scanned >> 20)), ("skipped_big_maps", jn(skipped_big)),
           ("elapsed_ms", jn(t0.elapsed().as_millis() as u64))]);
    out
}

// 反查归属:全 rw 映射里找指向 begin_ 的八字节字段;命中地址 X 即某对象的一个字段,
// DexFile 对象 = X - begin_off(begin_off ∈ {0, 8} 两候选都验),size_/location 复核。
// begin_off=8 候选再做 vtable 判别:obj[0] 落在 libart 映射内则强烈倾向虚表布局。
// 返回所有"size_ 或 location 至少一项吻合"的候选对象地址(供链猎使用)。
fn hunt_dexfile_objects(r: &Reader, maps: &[super::memio::MapEnt], begin: u64, file_size: u64,
                        map_path: &str, map_perm: &str, pkg: &str) -> Vec<u64> {
    let art_ranges: Vec<(u64, u64)> = maps.iter()
        .filter(|m| m.path.ends_with("/libart.so"))
        .map(|m| (m.start, m.end)).collect();
    let mut found: HashSet<u64> = HashSet::new();
    let mut objs: Vec<u64> = Vec::new();
    let mut scanned = 0u64;
    let needle = begin.to_le_bytes();
    'outer: for m in maps.iter().filter(|m| m.perm.starts_with("rw")) {
        let len = m.end - m.start;
        if len > 512 * 1024 * 1024 { continue; }
        if scanned >= MAX_SCAN_BYTES { break; }
        let mut off = 0u64;
        while off < len {
            let want = if off + CHUNK as u64 >= len { len - off } else { CHUNK as u64 + 8 };
            let Some(buf) = r.read(m.start + off, want as usize) else { off += CHUNK as u64; continue };
            scanned += buf.len() as u64;
            let mut pos = 0usize;
            while pos + 8 <= buf.len() {
                if &buf[pos..pos + 8] == needle.as_slice() {
                    let x = m.start + off + pos as u64; // 字段地址
                    for begin_off in [0u64, 8] {
                        let obj = x - begin_off;
                        if !found.insert(obj) { continue; }
                        let size_at = r.u64_at(obj + begin_off + 8).unwrap_or(0);
                        let mut location = String::new();
                        let mut loc_off = 0u64;
                        for lo in (0x10u64..0x50).step_by(8) {
                            if let Some(s) = r.cxx_string_at(obj + lo) {
                                if s.contains(".apk") || s.contains("dex") || s.contains(pkg) || s.contains("base.apk") {
                                    location = s; loc_off = lo; break;
                                }
                            }
                        }
                        let size_ok = size_at == file_size;
                        if size_ok || !location.is_empty() {
                            // vtable 判别:begin_off=8 时 obj[0] 应指向 libart
                            let vtable_hint = if begin_off == 8 {
                                let p = r.u64_at(obj).unwrap_or(0);
                                art_ranges.iter().any(|&(a, b)| a <= p && p < b) as u8
                            } else { 0 };
                            emit(&[("k", js("dex_object")), ("via", js("reverse_ref")),
                                   ("obj", jh(obj)), ("begin", jh(begin)),
                                   ("begin_off", jh(begin_off)),
                                   ("vtable_hint", jn(vtable_hint)),
                                   ("field_addr", jh(x)), ("field_in_map", js(&m.path)),
                                   ("size_off", jh(begin_off + 8)), ("size_field_ok", jn(size_ok as u8)),
                                   ("location", js(&location)), ("location_off", jh(loc_off)),
                                   ("payload_map", js(map_path)), ("payload_perm", js(map_perm))]);
                            objs.push(obj);
                        }
                    }
                    if found.len() >= 64 { break 'outer; } // 防炸
                }
                pos += 8;
            }
            if off + CHUNK as u64 >= len { break; }
            off += CHUNK as u64;
        }
    }
    objs
}

// 载荷身份识别:解析 dex 头,取前 8 个 type 的类描述符——一眼区分壳桩与原始应用。
fn identify_dex(r: &Reader, begin: u64, map_path: &str, map_perm: &str) {
    let Some(hdr) = r.read(begin, 0x70) else { return };
    let string_ids_size = u32::from_le_bytes(hdr[0x38..0x3c].try_into().unwrap());
    let string_ids_off = u32::from_le_bytes(hdr[0x3c..0x40].try_into().unwrap()) as u64;
    let type_ids_size = u32::from_le_bytes(hdr[0x40..0x44].try_into().unwrap());
    let type_ids_off = u32::from_le_bytes(hdr[0x44..0x48].try_into().unwrap()) as u64;
    let mut classes: Vec<String> = Vec::new();
    let n = type_ids_size.min(8);
    for i in 0..n {
        let Some(di) = r.u32_at(begin + type_ids_off + i as u64 * 4) else { break };
        if di >= string_ids_size { continue; }
        let Some(soff) = r.u32_at(begin + string_ids_off + di as u64 * 4) else { continue };
        let Some(raw) = r.read(begin + soff as u64, 128) else { continue };
        // string_data: 前导 uleb128 的 utf16 长度,随后 NUL 结尾的 MUTF-8
        let mut p = 0usize;
        while p < raw.len() && raw[p] & 0x80 != 0 { p += 1; }
        p += 1;
        let end = raw[p..].iter().position(|&b| b == 0).map(|e| p + e).unwrap_or(raw.len());
        classes.push(String::from_utf8_lossy(&raw[p..end]).to_string());
    }
    emit(&[("k", js("dex_identify")), ("begin", jh(begin)),
           ("map_path", js(map_path)), ("map_perm", js(map_perm)),
           ("type_ids", jn(type_ids_size)), ("string_ids", jn(string_ids_size)),
           ("classes", js(&classes.join("|")))]);
}

// 链猎:带着目标对象清单从 Runtime 再走一遍 BFS,父指针全记录;
// 任何一个目标被某个节点的字段指到,就把完整偏移链回溯出来。
// 回答:结构路(Runtime→…→DexFile)在这台设备上到底通不通。
fn chain_hunt(r: &Reader, maps: &[super::memio::MapEnt], runtime: u64, targets: &[u64]) {
    let target_set: HashSet<u64> = targets.iter().cloned().collect();
    let mut hit: HashMap<u64, String> = HashMap::new();
    let mut parent: HashMap<u64, (u64, u64)> = HashMap::new(); // 子 → (父节点, 槽位偏移)
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, u8)> = VecDeque::new();
    visited.insert(runtime);
    queue.push_back((runtime, 0));
    let t0 = std::time::Instant::now();
    let mut nodes = 0usize;

    'outer: while let Some((addr, depth)) = queue.pop_front() {
        if nodes >= MAX_NODES || t0.elapsed().as_secs() > ROUND_BUDGET_SECS { break; }
        nodes += 1;
        let mut span = if depth == 0 { ROOT_SPAN } else { SCAN_SPAN };
        if let Some(m) = maps.iter().find(|m| m.start <= addr && addr < m.end) {
            span = span.min(m.end - addr) & !7;
        }
        if span < 8 { continue; }
        let Some(buf) = r.read(addr, span as usize) else { continue };
        for off in (0..span as usize).step_by(8) {
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            if v < 0x10000 { continue; }
            if target_set.contains(&v) && !hit.contains_key(&v) {
                // 回溯:addr → … → runtime
                let mut chain = format!("+0x{off:x}");
                let mut cur = addr;
                while let Some(&(p, o)) = parent.get(&cur) {
                    chain = format!("+0x{o:x}") + &chain;
                    cur = p;
                    if cur == runtime || chain.len() > 512 { break; }
                }
                let chain = format!("R{chain}");
                hit.insert(v, chain.clone());
                emit(&[("k", js("chain_hunt")), ("target", jh(v)),
                       ("found", jn(1u8)), ("chain", js(&chain))]);
                if hit.len() == target_set.len() { break 'outer; }
                continue;
            }
            let w = maps.iter().any(|m| m.start <= v && v < m.end && m.perm.starts_with("rw"));
            if depth < 10 && w && !visited.contains(&v) {
                visited.insert(v);
                parent.insert(v, (addr, off as u64));
                queue.push_back((v, depth + 1));
            }
        }
    }
    for t in targets {
        if !hit.contains_key(t) {
            emit(&[("k", js("chain_hunt")), ("target", jh(*t)), ("found", jn(0u8))]);
        }
    }
    emit(&[("k", js("chain_hunt_stats")), ("nodes", jn(nodes)),
           ("targets", jn(targets.len())), ("hit", jn(hit.len())),
           ("elapsed_ms", jn(t0.elapsed().as_millis() as u64))]);
}

// 抓手符号缺席时的退路:在 libart 数据段里找"像 Runtime 的结构"
// (前 0x200 内含 ≥3 个指向 libart 自身的指针)
fn data_scan_for_runtime(r: &Reader, maps: &[super::memio::MapEnt], slide: u64) -> u64 {
    for m in maps.iter().filter(|m| m.path.ends_with("/libart.so") && m.perm.starts_with("rw")) {
        let mut off = 0u64;
        while off < m.end - m.start {
            let a = m.start + off;
            if let Some(buf) = r.read(a, 0x1000) {
                for i in (0..0x1000).step_by(8) {
                    let v = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                    if v < 0x10000 { continue; }
                    if let Some(body) = r.read(v, 0x200) {
                        let hits = (0..0x200).step_by(8).filter(|&j| {
                            let p = u64::from_le_bytes(body[j..j + 8].try_into().unwrap());
                            p >= slide && p < slide + 0x4000000 // 指向 libart 内部
                        }).count();
                        if hits >= 3 {
                            emit(&[("k", js("art_runtime_candidate")), ("addr", jh(v)),
                                   ("lib_hits", jn(hits))]);
                            return v; // 第一个候选先顶上,其余由回报分析
                        }
                    }
                }
            }
            off += 0x1000;
        }
    }
    0
}
