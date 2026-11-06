// 采集引擎(工单驱动的纯执行管线,零内置策略):
//   定位(按包名/模拟 pid)→ 载荷直扫(工单 scan 参数)→ 连续判稳 → 驱动读挖取
//   → carve 校验 → sha256 去重 → 反查归属(旁证)→ tar.gz + manifest。
// 1.13.5 教义:载荷直扫 = 通用定位主通路(零偏移);结构走读 = 旁证,不在此路径。

use crate::channel::Channel;
use crate::probe::memio::{find_pid_by_pkg, MapEnt};
use crate::proto::*;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

const CHUNK: usize = 1 << 20;               // 1MB 块 + 8B 重叠(防魔数跨界)
const MAX_SCAN_BYTES: u64 = 1 << 30;        // 单轮扫描总量封顶 1GB
const SKIP_MAP_BYTES: u64 = 512 << 20;      // 巨型堆跳过(dex 不住里面)

/// 引擎上下文(设备事实与执行控制)
pub struct Ctx {
    /// 已安装应用搜索根(真机 /data/app;模拟 = 测试目录)
    pub apk_root: std::path::PathBuf,
    /// 模拟目标 pid(file 通道专用;真机 = None,按包名定位)
    pub pid_hint: Option<u32>,
    pub cancel: Arc<AtomicBool>,
}

pub type Ev<'a> = dyn FnMut(&str, serde_json::Value) + 'a;

/// 工单执行入口。成功 = (manifest, tar.gz 字节);失败 = (code, detail)。
pub fn execute(
    wo: &WorkOrder,
    wo_raw: &[u8],
    ch: &dyn Channel,
    ctx: &Ctx,
    ev: &mut Ev,
) -> Result<(Manifest, Vec<u8>), (String, String)> {
    let t0 = Instant::now();
    let mut errors: Vec<RunError> = Vec::new();
    let mut log: Vec<String> = Vec::new(); // runtime-log 工件(事件流水)
    let mut log_ev = |k: &str, v: serde_json::Value| {
        log.push(json!({"k": k, "v": v}).to_string());
        ev(k, v);
    };

    // ① 目标锚核对(不符 = 大声拒绝)
    let apk = find_installed_apk(&ctx.apk_root, &wo.target.package)
        .ok_or_else(|| ("apk-absent".to_string(), format!("{} 未在 {} 下找到", wo.target.package, ctx.apk_root.display())))?;
    let apk_bytes = std::fs::read(&apk).map_err(|e| ("apk-read".to_string(), e.to_string()))?;
    let apk_hash = crate::sha256_hex(&apk_bytes);
    if apk_hash != wo.target.apk_sha256 {
        return Err(("apk-mismatch".into(), format!("期望 {} 实测 {apk_hash}", wo.target.apk_sha256)));
    }
    log_ev("target_anchored", json!({"apk": apk.display().to_string(), "sha256": apk_hash}));

    // ② 定位目标进程(未运行则 am start 拉起——启动目标恒为采集器职责,工单 launch_activity 必填)
    let pid = match ctx.pid_hint {
        Some(p) => p,
        None => {
            let mut pids = find_pid_by_pkg(&wo.target.package);
            if pids.is_empty() {
                log_ev("target_launch", json!({"activity": wo.target.launch_activity}));
                let ok = std::process::Command::new("am")
                    .args(["start", "-n", &wo.target.launch_activity])
                    .status().map(|s| s.success()).unwrap_or(false);
                if !ok { return Err(("launch-failed".into(), wo.target.launch_activity.clone())); }
                let t_dead = Instant::now() + std::time::Duration::from_secs(15);
                while pids.is_empty() && Instant::now() < t_dead {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    pids = find_pid_by_pkg(&wo.target.package);
                }
            }
            *pids.first().ok_or_else(|| ("target-not-running".into(), wo.target.package.clone()))? as u32
        }
    };
    log_ev("target_pid", json!({"pid": pid}));

    // ③ 连续判稳的载荷直扫
    let poll = &wo.extraction.scan.poll;
    let deadline = t0 + std::time::Duration::from_secs(poll.window_s);
    let mut stable: Vec<(u64, u64, String, String)> = Vec::new();
    let mut stable_count = 0u64;
    let mut round = 0u64;
    loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            return Err(("cancelled".into(), "工单被撤销".into()));
        }
        if Instant::now() > deadline {
            return Err(("window-exceeded".into(), format!("window_s={} 耗尽", poll.window_s)));
        }
        round += 1;
        let maps = ch.maps(pid).map_err(|e| ("maps".into(), e))?;
        let hits = scan_payloads(ch, pid, &maps, &wo.extraction.scan, &mut *ev);
        if hits == stable && !hits.is_empty() {
            stable_count += 1;
        } else {
            stable = hits;
            stable_count = if stable.is_empty() { 0 } else { 1 };
        }
        ev("scan_round", json!({"round": round, "hits": stable.len(), "stable": stable_count}));
        if stable_count >= poll.stable_rounds && !stable.is_empty() { break; }
        std::thread::sleep(std::time::Duration::from_millis(poll.interval_ms));
    }
    ev("dex_stable", json!({"count": stable.len(), "rounds": round}));

    // ④ 挖取 + carve 校验 + sha256 去重
    let carve = &wo.extraction.scan.carve;
    let mut payloads: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut seen_hash: Vec<String> = Vec::new();
    for (begin, fsize, mpath, mperm) in &stable {
        if ctx.cancel.load(Ordering::Relaxed) {
            return Err(("cancelled".into(), "工单被撤销".into()));
        }
        let raw = ch.read(pid, *begin, *fsize as usize)
            .map_err(|e| ("read".into(), format!("0x{begin:x}: {e}")))?;
        if carve.verify_header {
            match dex_header(&raw) {
                Some((_, fs)) if fs as u64 == *fsize => {}
                _ => {
                    errors.push(RunError { code: "carve-reject".into(), detail: format!("0x{begin:x} 头校验失败,丢弃") });
                    continue;
                }
            }
        }
        let hash = crate::sha256_hex(&raw);
        if seen_hash.contains(&hash) { continue; }
        seen_hash.push(hash);
        // 载荷身份(事件证据;识别逻辑零策略——只读头部表)
        let id = dex_identify(&raw);
        ev("dex_identify", json!({"begin": format!("0x{begin:x}"), "map_path": mpath, "map_perm": mperm,
            "type_ids": id.0, "string_ids": id.1, "classes": id.2, "packages": id.3}));
        payloads.push((*begin, raw));
    }
    if payloads.is_empty() {
        return Err(("no-payload".into(), "稳定载荷为零".into()));
    }

    // ⑤ 反查归属(旁证:可写图里指向载荷的指针数;不进工件)
    let maps = ch.maps(pid).map_err(|e| ("maps".into(), e))?;
    let rw: Vec<&MapEnt> = maps.iter().filter(|m| m.perm.contains('w')).collect();
    for (begin, _) in &payloads {
        let mut refs = 0u32;
        for m in rw.iter().take(64) {
            let len = (m.end - m.start).min(64 << 20);
            if let Ok(buf) = ch.read(pid, m.start, len as usize) {
                refs += count_needle(&buf, *begin).min(32); // 每图计数封顶防刷
            }
        }
        ev("dex_object", json!({"begin": format!("0x{begin:x}"), "refs": refs}));
    }

    // ⑥ 工件打包(tar.gz 唯一形态;随机工件名,铁律 4)
    let mut artifacts: Vec<ArtifactEntry> = Vec::new();
    let mut tar_data: Vec<(String, Vec<u8>)> = Vec::new();
    if wo.deliverables.iter().any(|d| d == "dex") {
        for (begin, raw) in &payloads {
            let name = format!("classes_0x{begin:x}.dex");
            artifacts.push(ArtifactEntry { name: name.clone(), kind: "dex".into(), sha256: crate::sha256_hex(raw), size_bytes: raw.len() as u64 });
            tar_data.push((name, raw.clone()));
        }
    }
    if wo.deliverables.iter().any(|d| d == "runtime-log") {
        let data = log.join("\n").into_bytes();
        artifacts.push(ArtifactEntry { name: "runtime-log.jsonl".into(), kind: "runtime-log".into(), sha256: crate::sha256_hex(&data), size_bytes: data.len() as u64 });
        tar_data.push(("runtime-log.jsonl".into(), data));
    }
    if wo.deliverables.iter().any(|d| d == "maps") {
        let text: String = maps.iter().map(|m| format!("{:x}-{:x} {} {}", m.start, m.end, m.perm, m.path)).collect::<Vec<_>>().join("\n");
        let data = text.into_bytes();
        artifacts.push(ArtifactEntry { name: "maps.txt".into(), kind: "maps".into(), sha256: crate::sha256_hex(&data), size_bytes: data.len() as u64 });
        tar_data.push(("maps.txt".into(), data));
    }
    let archive = build_tar_gz(&tar_data).map_err(|e| ("archive".into(), e))?;

    // ⑦ manifest(全字段;driver 回读实际生效通道)
    let (dname, dver) = ch.driver_id();
    let manifest = Manifest {
        schema: "exuvia.manifest".into(),
        manifest_version: MANIFEST_VERSION,
        order_id: wo.order_id.clone(),
        workorder_sha256: crate::sha256_hex(wo_raw),
        collector: CollectorInfo { name: "exuvia-eclosion".into(), version: env!("CARGO_PKG_VERSION").into() },
        device: device_info(),
        stealth_tier_used: wo.stealth.tier.clone(),
        driver: if wo.stealth.driver.is_some() {
            Some(DriverStatus { name: dname, version: dver, handshake: true, channels_used: ch.channels() })
        } else { None },
        anchors_hit: vec![], // 载荷直扫路径不挂锚点(锚点 = 侦察提示,§10.1)
        env_gates: wo.env_gates.iter().map(|g| GateResult { gate: g.gate.clone(), passed: eval_gate(g) }).collect(),
        artifacts,
        errors,
        residuals_accepted: vec![
            "fs-artifacts", "transport", "in-process-agent", "proc-visibility",
            "kernel-hook-residual", "timing-window",
        ].into_iter().map(String::from).collect(),
    };
    ev("engine_done", json!({"elapsed_ms": t0.elapsed().as_millis() as u64, "payloads": payloads.len()}));
    Ok((manifest, archive))
}

/// 已安装应用定位:/data/app/<pkg>-*/base.apk 布局(apk_root 参数化,模拟可换)
fn find_installed_apk(root: &std::path::Path, pkg: &str) -> Option<std::path::PathBuf> {
    let rd = std::fs::read_dir(root).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == pkg || (name.starts_with(pkg) && name[pkg.len()..].starts_with('-')) {
            let p = e.path().join("base.apk");
            if p.exists() { return Some(p); }
        }
    }
    None
}

/// dex 头校验:魔数(工单给的版本白名单)在扫描层已核;此处核 file_size 自洽
fn dex_header(buf: &[u8]) -> Option<(String, u32)> {
    if buf.len() < 0x70 { return None; }
    if &buf[0..4] != b"dex\n" { return None; }
    let ver = String::from_utf8_lossy(&buf[4..7]).to_string();
    let file_size = u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap());
    // 自证下限:file_size 至少罩得住头部;上限由调用方按 carve.max_size/图界判
    if file_size < 0x70 { return None; }
    Some((ver, file_size))
}

/// 载荷身份直读(头部 string/type 表;返回 type_ids 数、string_ids 数、前 8 类型、包名前缀 top)
fn dex_identify(buf: &[u8]) -> (u32, u32, Vec<String>, Vec<String>) {
    let rd = |off: usize| -> Option<u32> { buf.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) };
    let (Some(string_ids_size), Some(string_ids_off), Some(type_ids_size), Some(type_ids_off)) =
        (rd(0x38), rd(0x3c), rd(0x40), rd(0x44)) else { return (0, 0, vec![], vec![]) };
    let string_at = |idx: u32| -> Option<String> {
        let soff = rd(string_ids_off as usize + idx as usize * 4)? as usize;
        let raw = buf.get(soff..(soff + 256).min(buf.len()))?;
        let mut p = 0usize;
        while p < raw.len() && raw[p] & 0x80 != 0 { p += 1; }
        p += 1;
        let end = raw[p..].iter().position(|&b| b == 0).map(|e| p + e).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[p..end]).to_string())
    };
    let mut classes = Vec::new();
    for i in 0..type_ids_size.min(8) {
        if let Some(di) = rd(type_ids_off as usize + i as usize * 4) {
            if di < string_ids_size {
                if let Some(s) = string_at(di) { classes.push(s); }
            }
        }
    }
    // 包名前缀统计:L-描述符含 "/" 的取前两段(验明壳桩 vs 原始应用)
    let mut freq: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for i in 0..string_ids_size.min(200_000) {
        if let Some(s) = string_at(i) {
            if s.starts_with('L') && s.contains('/') {
                let inner = &s[1..];
                let mut segs = inner.split('/');
                if let (Some(a), Some(b)) = (segs.next(), segs.next()) {
                    if !a.is_empty() && !b.is_empty() && a.len() < 64 && b.len() < 64 {
                        *freq.entry(format!("{a}.{b}")).or_default() += 1;
                    }
                }
            }
        }
    }
    let mut pkgs: Vec<(String, u32)> = freq.into_iter().collect();
    pkgs.sort_by(|a, b| b.1.cmp(&a.1));
    let pkgs: Vec<String> = pkgs.into_iter().take(5).map(|(k, v)| format!("{k}x{v}")).collect();
    (type_ids_size, string_ids_size, classes, pkgs)
}

/// 载荷直扫:工单 scan 参数驱动的魔数扫描 + 头部自证
fn scan_payloads(ch: &dyn Channel, pid: u32, maps: &[MapEnt], cfg: &WoScan, ev: &mut Ev)
    -> Vec<(u64, u64, String, String)>
{
    let magics: Vec<(String, Vec<u8>)> = cfg.magic.iter()
        .filter_map(|m| hex_decode(&m.hex).map(|h| (m.name.clone(), h)))
        .filter(|(_, h)| h.len() >= 8)
        .collect();
    if magics.is_empty() { ev("scan_error", json!({"detail": "magic 表为空或非法"})); return vec![]; }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut scanned = 0u64;
    for m in maps.iter() {
        // regions 过滤:perms 精确匹配(空串 = 所有可读图)/匿名/尺寸/排除表
        let perm_ok = if cfg.regions.perms.is_empty() { m.perm.contains('r') } else { m.perm == cfg.regions.perms };
        if !perm_ok { continue; }
        let anon = m.path.is_empty() || m.path.starts_with('[');
        if cfg.regions.anonymous_only && !anon { continue; }
        let len = m.end - m.start;
        if len < cfg.regions.min_size || len > cfg.regions.max_size { continue; }
        if cfg.regions.exclude.iter().any(|x| m.path.contains(x)) { continue; }
        if len > SKIP_MAP_BYTES || scanned >= MAX_SCAN_BYTES { continue; }
        let mut off = 0u64;
        while off < len {
            let want = if off + CHUNK as u64 >= len { len - off } else { CHUNK as u64 + 8 };
            let Ok(buf) = ch.read(pid, m.start + off, want as usize) else { off += CHUNK as u64; continue };
            scanned += buf.len() as u64;
            for (name, magic) in &magics {
                let mut pos = 0usize;
                while let Some(hit) = find_sub(&buf[pos..], magic) {
                    let begin = m.start + off + (pos + hit) as u64;
                    pos += hit + 4;
                    if !seen.insert(begin) { continue; }
                    // 自证:头 file_size 自洽 + 单体上限 + 图内完整(整头 0x70 读全)
                    let Ok(hdr) = ch.read(pid, begin, 0x70) else { continue };
                    let Some((_v, file_size)) = dex_header(&hdr) else { continue };
                    let fs = file_size as u64;
                    if fs > cfg.carve.max_size || begin + fs > m.end { continue; }
                    ev("dex_region", json!({"begin": format!("0x{begin:x}"), "magic": name,
                        "file_size": file_size, "map_path": m.path, "map_perm": m.perm}));
                    out.push((begin, fs, m.path.clone(), m.perm.clone()));
                }
            }
            if off + CHUNK as u64 >= len { break; }
            off += CHUNK as u64;
        }
    }
    out.sort();
    out
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn count_needle(hay: &[u8], needle: u64) -> u32 {
    let nb = needle.to_le_bytes();
    hay.windows(8).filter(|w| *w == nb).count() as u32
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn build_tar_gz(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut t = tar::Builder::new(enc);
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        t.append_data(&mut h, name, &data[..]).map_err(|e| e.to_string())?;
    }
    let enc = t.into_inner().map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}

fn prop(key: &str) -> String {
    std::fs::read_to_string("/system/build.prop").unwrap_or_default()
        .lines().find_map(|l| l.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
        .unwrap_or_default()
}

fn device_info() -> DeviceInfo {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let kernel = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy().to_string();
    let root = if std::path::Path::new("/data/adb/ksud").exists() { "ksu" }
        else if std::path::Path::new("/data/adb/magisk").exists() { "magisk" }
        else if unsafe { libc::getuid() } == 0 { "su" } else { "none" };
    DeviceInfo {
        abi: prop("ro.product.cpu.abi"),
        android_release: prop("ro.build.version.release"),
        kernel,
        root: root.into(),
    }
}

/// env-gate 预检:prop 类门现场读值比对;其他门类如实记未通过(记录用,不强制)
fn eval_gate(g: &WoEnvGate) -> bool {
    if g.gate.starts_with("ro.") { prop(&g.gate) == g.expected } else { false }
}
