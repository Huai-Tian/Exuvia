// 探针#11/#12:libart.so 符号定位 Runtime 单例 → 结构自发现走读 → DexFile 三重自证。
// 零注入:全程 process_vm_readv / /proc/pid/mem 只读;前后回读 TracerPid 证零附着。
use super::elf;
use super::memio::{cross_check, find_pid_by_pkg, read_maps, tracer_pid, Reader};
use crate::{emit, jh, jn, js};
use std::collections::{HashSet, VecDeque};

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

    // 5. 双通道互证 + 零痕迹回证
    let samples: Vec<u64> = confirmed_all.iter().take(3).map(|&(_, b, _)| b).collect();
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
    let t0 = std::time::Instant::now();
    let mut overtime = false;

    while let Some((addr, chain, depth)) = queue.pop_front() {
        if nodes >= MAX_NODES { break; }
        if t0.elapsed().as_secs() > ROUND_BUDGET_SECS { overtime = true; break; }
        nodes += 1;
        let span = if depth == 0 { ROOT_SPAN } else { SCAN_SPAN };
        let Some(buf) = r.read(addr, span as usize) else { continue };
        reads += 1;
        for off in (0..span as usize).step_by(8) {
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            if v < 0x10000 || !readable(v) { continue; }
            let ch = format!("{chain}+0x{off:x}");
            // 两级: v 指向的对象,其首个 u64(begin_)是否指向 "dex\n"
            if let Some(b8) = r.read(v, 8) {
                reads += 1;
                let begin_ = u64::from_le_bytes(b8.try_into().unwrap());
                if begin_ >= 0x10000 && readable(begin_) {
                    if let Some(magic) = r.read(begin_, 4) {
                        reads += 1;
                        if &magic == b"dex\n" {
                            if validate_dexfile(r, v, begin_, &ch, pkg) {
                                out.push((begin_, v));
                            }
                            continue; // DexFile 对象不再向里走
                            // (对象内部不再扫,但 begin_ 指向的 dex 本体也不入队:
                            //  它在文件映射里,writable 检查本来就进不去)
                        }
                    }
                }
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
fn validate_dexfile(r: &Reader, obj: u64, begin_: u64, chain: &str, pkg: &str) -> bool {
    let Some(hdr) = r.read(begin_, 0x40) else { return false };
    let file_size = u32::from_le_bytes(hdr[0x20..0x24].try_into().unwrap());
    let checksum = u32::from_le_bytes(hdr[0x08..0x0c].try_into().unwrap());
    if file_size < 0x70 || file_size > 256 * 1024 * 1024 { return false; }

    // size_ 应在 obj+0x08(DexFile 经典布局 begin_@0 size_@8)
    let size_at_8 = r.u64_at(obj + 8).unwrap_or(0);
    let size_ok = size_at_8 == file_size as u64;

    // location_:扫 obj+0x10..0x30 找可解析的 cxx string
    let mut location = String::new();
    let mut loc_off = 0u64;
    for lo in (0x10u64..0x30).step_by(8) {
        if let Some(s) = r.cxx_string_at(obj + lo) {
            if s.contains(".apk") || s.contains("dex") || s.contains(pkg) {
                location = s;
                loc_off = lo;
                break;
            }
        }
    }
    // location_checksum_:扫 obj+0x08..0x58 找等于 header checksum 的 u32
    let mut csum_off = 0u64;
    if let Some(body) = r.read(obj, 0x58) {
        for co in (0x08usize..0x58).step_by(4) {
            if u32::from_le_bytes(body[co..co + 4].try_into().unwrap()) == checksum && checksum != 0 {
                csum_off = co as u64;
                break;
            }
        }
    }

    let confirmed = size_ok && !location.is_empty();
    emit(&[
        ("k", js(if confirmed { "dex_confirmed" } else { "dex_candidate" })),
        ("chain", js(chain)),
        ("obj", jh(obj)), ("begin", jh(begin_)),
        ("file_size", jn(file_size)),
        ("size_field_ok", jn(size_ok as u8)),
        ("location", js(&location)), ("location_off", jh(loc_off)),
        ("checksum", jh(checksum as u64)), ("checksum_field_off", jh(csum_off)),
        ("pkg_in_location", jn(location.contains(pkg) as u8)),
    ]);
    confirmed
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
