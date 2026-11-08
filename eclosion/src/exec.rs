// exec 动词:本地直采(调试通道,无会话)——工单 → 闸门 → 引擎 → 工件直接落盘。
// 定位(2026-11-08 维护者裁定):采集功能的快速迭代回路先在设备本地闭环,
// 通信测试留到采集器功能收定后再跑——run 动词的 E2EE 生产面(铁律 5)不变,
// exec 是一次性调试动词,不构成传输线例外。
// 与 run 的差异:无反拨/无词表/无配对秘密;闸门同纪律(schema/版本/卫生/能力,
// 响亮拒绝);工件落点与主机端 collect 同构:manifest.json + artifacts.tar.gz
// + events.jsonl + 逐件解开(sha256 对账 manifest.artifacts,不符响亮失败)。
// Ctrl+C/SIGTERM = 引擎 cancel 旗(经引擎正常收尾,events.jsonl 不丢尾巴)。

use crate::channel::build_channel;
use crate::engine::{self, Ctx};
use crate::profile::{DriverProfile, Transport};
use crate::proto::*;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct ExecConfig {
    pub workorder: PathBuf,
    /// None = 编译期内置默认(同 run 动词)
    pub profile_path: Option<PathBuf>,
    /// 已安装应用搜索根(真机 /data/app;模拟 = 测试目录)
    pub apk_root: PathBuf,
    /// 工件落点目录
    pub out: PathBuf,
    pub harden: bool,
}

// ─── Ctrl+C/SIGTERM → cancel 旗(信号处理器不能捕获环境,经静态槽转交) ───

static CANCEL_SLOT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_cancel_signal(_sig: libc::c_int) {
    let p = CANCEL_SLOT.load(Ordering::Relaxed);
    if p != 0 {
        // 指针由 run() 保证存续到 cancel Arc drop 之前(卸载在 run 尾部执行)
        unsafe { (*(p as *const AtomicBool)).store(true, Ordering::Relaxed); }
    }
}

fn install_cancel(cancel: &Arc<AtomicBool>) {
    CANCEL_SLOT.store(Arc::as_ptr(cancel) as usize, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGINT, on_cancel_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_cancel_signal as libc::sighandler_t);
    }
}

fn uninstall_cancel() { CANCEL_SLOT.store(0, Ordering::Relaxed); }

/// 事件回流:stderr 实时打印(调试友好)+ events.jsonl 落盘(证据流水)
fn make_ev_sink(mut log: std::fs::File) -> impl FnMut(&str, serde_json::Value) {
    move |k: &str, v: serde_json::Value| {
        let line = json!({"k": k, "v": v}).to_string();
        eprintln!("[exec] 事件 {k}");
        writeln!(log, "{line}").ok();
    }
}

/// tar.gz 解开落盘 + 逐件 sha256 对账 manifest.artifacts(防裸工件;同主机端纪律)
fn unpack_verified(archive: &[u8], manifest: &Manifest, out: &Path) -> Result<Vec<(String, String, u64)>, String> {
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let mut extracted: Vec<(String, String, u64)> = Vec::new();
    for e in tar.entries().map_err(|e| format!("bad-archive: {e}"))? {
        let mut e = e.map_err(|e| format!("bad-archive: {e}"))?;
        let name = e.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        // 裸文件名硬校验(防 Zip-Slip;与主机端 collect 同款)
        if name.contains('/') || name.contains("..") {
            return Err(format!("bad-archive: 工件名 {name} 非裸文件名"));
        }
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut data).map_err(|e| e.to_string())?;
        let digest = crate::sha256_hex(&data);
        let expect = manifest.artifacts.iter().find(|a| a.name == name);
        match expect {
            Some(a) if a.sha256 == digest && a.size_bytes == data.len() as u64 => {}
            _ => return Err(format!("bad-artifact: {name} 与 manifest 对不上(sha256/尺寸)")),
        }
        std::fs::write(out.join(&name), &data).map_err(|e| format!("工件落盘失败: {e}"))?;
        extracted.push((name, digest, data.len() as u64));
    }
    if extracted.len() != manifest.artifacts.len() {
        return Err(format!(
            "bad-artifact: manifest 登记 {} 件,包内 {} 件",
            manifest.artifacts.len(),
            extracted.len()
        ));
    }
    Ok(extracted)
}

/// 本地直采一次。成功 = JSON 摘要(stdout);失败 = Err(code: detail)(events.jsonl 已尽在 out)
pub fn run(cfg: &ExecConfig) -> Result<serde_json::Value, String> {
    let t0 = Instant::now();
    if cfg.harden { crate::daemon::harden_process(); }

    // ① profile + 通道 + 握手(与 run 同纪律;握手失败 = 响亮拒绝,不静默降级)
    let profile = match &cfg.profile_path {
        Some(p) => DriverProfile::load(p)?,
        None => DriverProfile::builtin_default(),
    };
    let ch = build_channel(&profile)?;
    ch.handshake().map_err(|e| format!("驱动握手失败(不静默降级——响亮拒绝运行): {e}"))?;
    let pid_hint = match &profile.transport {
        Transport::File { pid, .. } => Some(*pid),
        _ => None,
    };

    // ② 工单解析 + 闸门(schema/版本/卫生/能力——同 daemon 纪律,响亮拒绝)
    let text = std::fs::read_to_string(&cfg.workorder)
        .map_err(|e| format!("工单不可读 {}: {e}", cfg.workorder.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("bad-workorder: 工单非 JSON: {e}"))?;
    let wo: WorkOrder = serde_json::from_value(value.clone())
        .map_err(|e| format!("bad-workorder: 对照 §10.1 v4: {e}"))?;
    crate::daemon::wo_gate_check(&wo, &ch.channels())
        .map_err(|(code, detail, hint)| format!("{code}: {detail} (hint: {hint})"))?;
    // 工单锚 = 解析 Value 的 to_vec(与守护侧算法逐位对齐,manifest 回显)
    let wo_raw = serde_json::to_vec(&value).map_err(|e| e.to_string())?;

    // ③ 输出目录 + 事件流水
    std::fs::create_dir_all(&cfg.out).map_err(|e| format!("输出目录不可建 {}: {e}", cfg.out.display()))?;
    let log = std::fs::File::create(cfg.out.join("events.jsonl"))
        .map_err(|e| format!("events.jsonl 创建失败: {e}"))?;

    // ④ 引擎全链(定位/诱导启动/直扫/判稳/carve/去重/打包)
    let cancel = Arc::new(AtomicBool::new(false));
    install_cancel(&cancel);
    let ctx = Ctx { apk_root: cfg.apk_root.clone(), pid_hint, cancel: cancel.clone() };
    let mut ev = make_ev_sink(log);
    let result = engine::execute(&wo, &wo_raw, &*ch, &ctx, &mut ev);
    uninstall_cancel();
    let (manifest, archive) = result.map_err(|(code, detail)| format!("{code}: {detail}"))?;

    // ⑤ 落盘:tar.gz 原包 + manifest + 逐件解开对账
    std::fs::write(cfg.out.join("artifacts.tar.gz"), &archive)
        .map_err(|e| format!("工件归档落盘失败: {e}"))?;
    let extracted = unpack_verified(&archive, &manifest, &cfg.out)?;
    std::fs::write(cfg.out.join("manifest.json"), serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?)
        .map_err(|e| format!("manifest 落盘失败: {e}"))?;

    let arts: Vec<serde_json::Value> = extracted.iter()
        .map(|(n, h, b)| json!({"name": n, "sha256": h, "size_bytes": b}))
        .collect();
    Ok(json!({
        "status": "ok",
        "order_id": manifest.order_id,
        "collector": { "name": "exuvia-eclosion", "version": env!("CARGO_PKG_VERSION") },
        "driver": manifest.driver.as_ref()
            .map(|d| json!({"name": d.name, "version": d.version, "handshake": d.handshake, "channels_used": d.channels_used})),
        "artifacts": arts,
        "errors": manifest.errors,
        "out": cfg.out.display().to_string(),
        "elapsed_ms": t0.elapsed().as_millis() as u64,
    }))
}
