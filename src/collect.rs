//! collect --run：采集会话主机端（SKILL.md §10.4 控制面词表的消费端）。
//! 监听 → 等羽化守护反向拨号 → 派单（workorder v4）→ 事件流水 → done(manifest)
//! → 文件族收讫 → 字节级验货（manifest.artifacts 全对账）。输出恒 JSON（CLI 就是 API）。
//!
//! 配对秘密只经环境变量 EXUVIA_SECRET 出示（argv 会进 /proc cmdline，不走）。
//! 工单锚纪律：派单 body 用文件原文解析出的 Value（不按结构体重排），
//! workorder_sha256 锚 = 该 Value 序列化字节的 sha256——与守护侧算法逐位对齐。

use crate::protocol::{CollectorManifest, SessionEnvelope, SessionKind, WorkOrder};
use crate::version;
use e2ee::{Event, Person, Receive};
use sha2::Digest as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct RunConfig {
    pub listen: String,
    pub workorder: PathBuf,
    pub out: Option<PathBuf>,
    /// 总窗口秒数；0 = 不限
    pub timeout_s: u64,
}

pub struct CollectSummary {
    pub order_id: String,
    pub artifacts: Vec<(String, String, u64)>,
    pub out_dir: PathBuf,
    pub elapsed_ms: u64,
    pub events: u32,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    format!("sha256:{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn encode(kind: SessionKind, seq: u64, order_id: Option<&str>, body: serde_json::Value) -> Result<String, String> {
    let env = SessionEnvelope {
        schema: "exuvia.session".into(),
        session_version: version::SESSION_VERSION,
        kind,
        seq,
        order_id: order_id.map(|s| s.to_string()),
        body,
    };
    let s = serde_json::to_string(&env).map_err(|e| e.to_string())?;
    if s.len() > 64 * 1024 {
        return Err(format!("会话帧 {}B 超 64KB 上限", s.len()));
    }
    Ok(s)
}

/// 读工单 + 主机侧闸门（与守护侧同纪律：任一不符 = 响亮拒绝，不静默执行）
fn load_workorder(path: &Path) -> Result<(serde_json::Value, WorkOrder, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("工单不可读 {}: {e}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("bad-workorder: 工单非 JSON: {e}"))?;
    let wo: WorkOrder = serde_json::from_value(value.clone())
        .map_err(|e| format!("bad-workorder: 对照 §10.1 v4: {e}"))?;
    if wo.schema != "exuvia.workorder" {
        return Err(format!("bad-schema: 工单 $schema={} 非 exuvia.workorder", wo.schema));
    }
    if wo.workorder_version != version::WORKORDER_VERSION {
        return Err(format!(
            "bad-version: 工单 workorder_version={} 主机支持={}",
            wo.workorder_version,
            version::WORKORDER_VERSION
        ));
    }
    if wo.hygiene.hygiene_version != version::HYGIENE_VERSION {
        return Err(format!(
            "bad-hygiene: 工单 hygiene_version={} 主机对齐={}",
            wo.hygiene.hygiene_version,
            version::HYGIENE_VERSION
        ));
    }
    let anchor = sha256_hex(&serde_json::to_vec(&value).map_err(|e| e.to_string())?);
    Ok((value, wo, anchor))
}

pub fn run(cfg: &RunConfig) -> Result<CollectSummary, String> {
    let (wo_value, wo, wo_anchor) = load_workorder(&cfg.workorder)?;
    let order_id = wo.order_id.clone();
    let out_dir = cfg
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("collect-{order_id}")));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("输出目录不可建 {}: {e}", out_dir.display()))?;
    let secret = std::env::var("EXUVIA_SECRET")
        .map_err(|_| "配对秘密缺席：经环境变量 EXUVIA_SECRET 出示（argv 会进 /proc cmdline，不走）".to_string())?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(session(cfg, wo_value, wo_anchor, order_id, out_dir, &secret))
}

async fn session(
    cfg: &RunConfig,
    wo_value: serde_json::Value,
    wo_anchor: String,
    order_id: String,
    out_dir: PathBuf,
    secret: &str,
) -> Result<CollectSummary, String> {
    let t0 = Instant::now();
    let inner = session_inner(cfg, wo_value, wo_anchor, order_id, out_dir, secret);
    if cfg.timeout_s > 0 {
        match tokio::time::timeout(Duration::from_secs(cfg.timeout_s), inner).await {
            Ok(r) => r,
            Err(_) => Err(format!("timeout: 总窗口 {}s 耗尽", cfg.timeout_s)),
        }
    } else {
        inner.await
    }
}

async fn session_inner(
    cfg: &RunConfig,
    wo_value: serde_json::Value,
    wo_anchor: String,
    order_id: String,
    out_dir: PathBuf,
    secret: &str,
) -> Result<CollectSummary, String> {
    let t0 = Instant::now();
    let (me, mut ev) = Person::born("exuvia", &cfg.listen)
        .await
        .map_err(|e| format!("会话内核诞生失败: {e}"))?;
    me.expect_secret_stable(secret.as_bytes()).await;
    eprintln!("[collect] 监听 {}，等守护反拨", me.listen_addr().await);

    // 事件流水原样落盘（会话证据；一行一帧）
    let log_path = out_dir.join("events.jsonl");
    let mut log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    use std::io::Write as _;

    // 等 Met（守护是发起方；本端作为收端自动聚焦）
    loop {
        tokio::select! {
            Some(e) = ev.recv() => if matches!(e, Event::Met { .. }) { break },
            _ = tokio::signal::ctrl_c() => return Err("cancelled: 配对前主机撤了".into()),
        }
    }
    me.set_receive(Receive::Always).await.map_err(|e| e.to_string())?;
    eprintln!("[collect] 已接线");

    // 派单
    let frame = encode(SessionKind::WorkorderAssign, 1, Some(&order_id), wo_value)?;
    me.speak(&frame).await.map_err(|e| e.to_string())?;
    eprintln!("[collect] 工单 {order_id} 已派（锚 {wo_anchor}）");

    let mut seq = 1u64;
    let mut events = 0u32;
    let mut manifest: Option<serde_json::Value> = None;
    let mut archive: Vec<u8> = Vec::new();
    let mut archive_done = false;
    let mut cancel_grace: Option<Instant> = None;

    loop {
        if let Some(t) = cancel_grace {
            if t.elapsed() > Duration::from_secs(3) {
                return Err("cancelled: 撤销帧已发，守护 3s 内未收官".into());
            }
        }
        tokio::select! {
            Some(e) = ev.recv() => match e {
                Event::Heard { text, .. } => {
                    writeln!(log, "{text}").ok();
                    events += 1;
                    let env: SessionEnvelope = serde_json::from_str(&text)
                        .map_err(|e| format!("bad-envelope: 守护帧非 §10.4 形态: {e}"))?;
                    if env.session_version != version::SESSION_VERSION {
                        return Err(format!("bad-version: 守护 session_version={} 主机={}", env.session_version, version::SESSION_VERSION));
                    }
                    match env.kind {
                        SessionKind::WorkorderAck => {
                            let accepted = env.body["accepted"].as_bool().unwrap_or(false);
                            if !accepted {
                                return Err(format!("守护响亮拒绝: {}", env.body));
                            }
                            eprintln!("[collect] ack accepted");
                        }
                        SessionKind::StatusReport => {
                            eprintln!("[collect] 守护状态 {}", env.body["state"].as_str().unwrap_or("?"));
                        }
                        SessionKind::Event | SessionKind::Progress => {
                            let k = env.body["event"].as_str().unwrap_or("?").to_string();
                            eprintln!("[collect] 事件 {k}");
                        }
                        SessionKind::Error => {
                            return Err(format!("守护报错: {}", env.body));
                        }
                        SessionKind::Done => {
                            let m: CollectorManifest = serde_json::from_value(env.body.clone())
                                .map_err(|e| format!("bad-manifest: 对照 §10.2 v2: {e}"))?;
                            if m.schema != "exuvia.manifest" || m.manifest_version != version::MANIFEST_VERSION {
                                return Err(format!("bad-version: manifest schema={} version={}", m.schema, m.manifest_version));
                            }
                            if m.order_id != order_id {
                                return Err(format!("bad-echo: manifest order_id={} ≠ 派单 {}", m.order_id, order_id));
                            }
                            if m.workorder_sha256 != wo_anchor {
                                return Err(format!("bad-anchor: 工单锚回显 {} ≠ {}", m.workorder_sha256, wo_anchor));
                            }
                            eprintln!("[collect] done（工件 {} 件）", m.artifacts.len());
                            manifest = Some(env.body.clone());
                        }
                        k => return Err(format!("bad-direction: 主机收到 {k:?}——词表方向硬性")),
                    }
                }
                Event::FileRequested { name, size, .. } => {
                    writeln!(log, "{{\"file_begin\":{name:?},\"size\":{size}}}").ok();
                    eprintln!("[collect] 来件 {name}（{size}B）");
                }
                Event::FileChunk { data, .. } => archive.extend_from_slice(&data),
                Event::FileComplete { total, .. } => {
                    if archive.len() as u64 != total {
                        return Err(format!("bad-transfer: 收 {}B ≠ 申报 {total}B", archive.len()));
                    }
                    eprintln!("[collect] 工件收讫 {}B", archive.len());
                    archive_done = true;
                }
                Event::FileDeclined { reason, .. } => {
                    writeln!(log, "{{\"file_declined\":{reason:?}}}").ok();
                }
                Event::Left { .. } => {
                    if cancel_grace.is_some() {
                        return Err("cancelled: 撤销帧已发，守护离场".into());
                    }
                    return Err("线死：守护在收官前离场".into());
                }
                _ => {}
            },
            _ = tokio::signal::ctrl_c() => {
                if cancel_grace.is_none() {
                    seq += 1;
                    let f = encode(SessionKind::WorkorderCancel, seq, Some(&order_id), serde_json::json!({}))?;
                    me.speak(&f).await.ok();
                    eprintln!("[collect] 撤销帧已发（等守护收官，3s 宽限）");
                    cancel_grace = Some(Instant::now());
                }
            },
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        if manifest.is_some() && archive_done {
            break;
        }
    }

    // ── 验货：tar.gz 解开逐件对账 manifest.artifacts ──
    let manifest = manifest.unwrap();
    let m: CollectorManifest = serde_json::from_value(manifest.clone()).map_err(|e| e.to_string())?;
    let archive_path = out_dir.join("artifacts.tar.gz");
    std::fs::write(&archive_path, &archive).map_err(|e| format!("工件落盘失败: {e}"))?;
    let gz = flate2::read::GzDecoder::new(&archive[..]);
    let mut tar = tar::Archive::new(gz);
    let mut extracted: Vec<(String, String, u64)> = Vec::new();
    let mut entries = Vec::new();
    {
        let mut tmp = Vec::new();
        for e in tar.entries().map_err(|e| format!("bad-archive: tar 解开失败: {e}"))? {
            let mut e = e.map_err(|e| format!("bad-archive: {e}"))?;
            let name = e.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
            // 防 Zip-Slip：工件名必须是裸文件名
            if name.contains('/') || name.contains("..") {
                return Err(format!("bad-archive: 工件名 {name} 非裸文件名"));
            }
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut data).map_err(|e| e.to_string())?;
            tmp.push((name, data));
        }
        entries = tmp;
    }
    for (name, data) in entries {
        let digest = sha256_hex(&data);
        let expect = m.artifacts.iter().find(|a| a.name == name);
        match expect {
            Some(a) if a.sha256 == digest && a.size_bytes == data.len() as u64 => {}
            _ => return Err(format!("bad-artifact: {name} 与 manifest 对不上（sha256/尺寸）")),
        }
        std::fs::write(out_dir.join(&name), &data).map_err(|e| format!("工件落盘失败: {e}"))?;
        extracted.push((name, digest, data.len() as u64));
    }
    if extracted.len() != m.artifacts.len() {
        return Err(format!(
            "bad-artifact: manifest 登记 {} 件，包内 {} 件",
            m.artifacts.len(),
            extracted.len()
        ));
    }
    std::fs::write(out_dir.join("manifest.json"), serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?)
        .map_err(|e| format!("manifest 落盘失败: {e}"))?;
    eprintln!("[collect] 验货通过，工件 {} 件落 {}", extracted.len(), out_dir.display());

    Ok(CollectSummary {
        order_id,
        artifacts: extracted,
        out_dir,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        events,
    })
}
