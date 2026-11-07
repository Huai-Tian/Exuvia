// 守护进程:三动词 run/stop/status(用户手动启停,铁律 5)。
// run = 硬化 → profile 加载 + 能力核对 + 握手 → 反向拨号主机 → 会话环:
//   assign → 闸门(版本/卫生/能力)→ ack → 引擎(阻塞线程,事件 mpsc 回流)
//   → done(manifest)+ tar.gz 文件族回传;cancel 随时生效;status.query 即答。
// 断线 = 线死事件 → 重拨;作业死线 = 工单 window_s;无保活帧(裁定 27)。
// 配对秘密只经环境变量 ECLOSION_SECRET 出示——argv 会进 /proc cmdline,不走。

use crate::channel::{build_channel, Channel};
use crate::engine::{self, Ctx};
use crate::profile::{DriverProfile, Transport};
use crate::proto::*;
use crate::session::{self, SessionTx};
use e2ee::{Event, Person};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct DaemonConfig {
    /// 状态根(设备 /data/local/tmp;桌面测试可换)
    pub state_root: PathBuf,
    /// 已安装应用搜索根(真机 /data/app;模拟 = 测试目录)
    pub apk_root: PathBuf,
    /// 驱动 profile;None = 编译期内置默认
    pub profile_path: Option<PathBuf>,
    /// 主机地址(反向拨号目标,设备零监听口)
    pub host: String,
    /// 进程硬化(测试可关)
    pub harden: bool,
}

/// 在跑工单:取消旗 + 事件回流 + 引擎 join
struct Running {
    order_id: String,
    cancel: Arc<AtomicBool>,
    events: tokio::sync::mpsc::UnboundedReceiver<(String, serde_json::Value)>,
    join: tokio::task::JoinHandle<Result<(Manifest, Vec<u8>), (String, String)>>,
}

/// 会话环内引擎侧的两种步进
enum Step {
    Event(Option<(String, serde_json::Value)>),
    Finished(Result<Result<(Manifest, Vec<u8>), (String, String)>, tokio::task::JoinError>),
}

struct State {
    dir: PathBuf,
    file: PathBuf,
}

impl State {
    fn create(root: &Path, profile: &DriverProfile) -> Result<State, String> {
        let dir = root.join(crate::rand_name("eclosion-"));
        std::fs::create_dir_all(&dir).map_err(|e| format!("状态目录创建失败: {e}"))?;
        let st = State { file: dir.join("state.json"), dir };
        st.write(&json!({
            "state": "boot",
            "profile": profile.name,
            "profile_version": profile.version,
        }))?;
        Ok(st)
    }
    fn write(&self, v: &serde_json::Value) -> Result<(), String> {
        let mut v = v.clone();
        v["pid"] = json!(std::process::id());
        std::fs::write(&self.file, serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
            .map_err(|e| format!("状态写入失败: {e}"))
    }
    fn cleanup(self) { std::fs::remove_dir_all(&self.dir).ok(); }
}

/// 进程硬化(照抄 e2ee CLI 职责;库不碰进程策略,宿主自理——立项书 §6)
pub fn harden_process() {
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &lim);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    if let Ok(text) = std::fs::read_to_string("/proc/swaps") {
        if text.lines().skip(1).any(|l| l.split_whitespace().nth(1) == Some("partition")) {
            eprintln!("[harden] 警告:swap 分区在场(秘密可能落盘)");
        }
    }
}

fn jittered_delay() -> std::time::Duration {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).unwrap_or_default();
    std::time::Duration::from_millis(1000 + (u16::from_le_bytes(b) % 1000) as u64)
}

pub async fn run(cfg: DaemonConfig) -> Result<(), String> {
    if cfg.harden { harden_process(); }
    let profile = match &cfg.profile_path {
        Some(p) => DriverProfile::load(p)?,
        None => DriverProfile::builtin_default(),
    };
    let channel: Arc<dyn Channel> = Arc::from(build_channel(&profile)?);
    channel.handshake().map_err(|e| format!("驱动握手失败(不静默降级——响亮拒绝运行): {e}"))?;
    let pid_hint = match &profile.transport {
        Transport::File { pid, .. } => Some(*pid),
        _ => None,
    };
    let secret = std::env::var("ECLOSION_SECRET")
        .map_err(|_| "配对秘密缺席:经环境变量 ECLOSION_SECRET 出示(argv 会进 /proc cmdline,不走)".to_string())?;

    let state = State::create(&cfg.state_root, &profile)?;
    eprintln!("[eclosion] 状态目录 {}", state.dir.display());
    let r = run_loop(&cfg, channel, pid_hint, &secret, &state).await;
    state.cleanup();
    r
}

async fn run_loop(cfg: &DaemonConfig, ch: Arc<dyn Channel>, pid_hint: Option<u32>, secret: &str, state: &State) -> Result<(), String> {
    let (me, mut ev) = Person::born("exuvia-eclosion", "127.0.0.1:0").await
        .map_err(|e| format!("会话内核诞生失败: {e}"))?;
    let mut tx = SessionTx::default();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;

    loop {
        state.write(&json!({"state": "dialing", "host": cfg.host}))?;
        match me.dial_secret(&cfg.host, Some(secret.as_bytes())).await {
            Ok(line) => eprintln!("[eclosion] 已接线 line={line}"),
            Err(e) => {
                eprintln!("[eclosion] 拨号失败({e}),稍后重拨");
                tokio::select! {
                    _ = tokio::time::sleep(jittered_delay()) => continue,
                    _ = sigterm.recv() => return Ok(()),
                }
            }
        }
        match wait_met(&mut ev, &mut sigterm).await {
            None => return Ok(()),          // 停止信号
            Some(false) => continue,        // 线死于配对前,重拨
            Some(true) => {}
        }
        state.write(&json!({"state": "idle", "host": cfg.host}))?;
        speak(&me, &mut tx, SessionKind::StatusReport, None, json!({"state": "idle"})).await?;

        // ── 会话环 ──
        let mut running: Option<Running> = None;
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    if let Some(r) = &running { r.cancel.store(true, Ordering::Relaxed); }
                    return Ok(());
                }
                Some(e) = ev.recv() => match e {
                    Event::Heard { text, .. } => {
                        handle_frame(cfg, &ch, pid_hint, &me, &mut tx, state, &text, &mut running).await?;
                    }
                    Event::Left { .. } => {
                        eprintln!("[eclosion] 线死,重拨");
                        if let Some(r) = &running { r.cancel.store(true, Ordering::Relaxed); }
                        break;
                    }
                    _ => {}
                },
                // 引擎侧两路归一(单 &mut 借用):事件 → event 信封;收官 → done/error + 文件族
                step = async {
                    match &mut running {
                        Some(r) => tokio::select! {
                            e = r.events.recv() => Step::Event(e),
                            j = &mut r.join => Step::Finished(j),
                        },
                        None => std::future::pending().await,
                    }
                } => match step {
                    Step::Event(Some((k, v))) => {
                        let oid = running.as_ref().map(|r| r.order_id.clone());
                        speak(&me, &mut tx, SessionKind::Event, oid, json!({"event": k, "fields": v})).await?;
                    }
                    Step::Event(None) => {} // 事件通道已关,等收官
                    Step::Finished(res) => {
                        let oid = running.as_ref().map(|r| r.order_id.clone()).unwrap_or_default();
                        let mut r = running.take().expect("Finished 时 running 必在");
                        // 收官前先排干事件尾巴:引擎线程终结时 join 与 events 同就绪,
                        // tokio::select! 随机择枝——join 胜出即收官会把队列残余事件
                        // 随通道丢弃(主机 events.jsonl 缺尾 = 证据缺尾,非测试抖动)。
                        // 发送端已随线程终结关闭,recv 排干即 None,不会悬住。
                        while let Some((k, v)) = r.events.recv().await {
                            speak(&me, &mut tx, SessionKind::Event, Some(oid.clone()), json!({"event": k, "fields": v})).await?;
                        }
                        match res {
                            Ok(Ok((manifest, archive))) => {
                                let body = serde_json::to_value(&manifest).map_err(|e| e.to_string())?;
                                speak(&me, &mut tx, SessionKind::Done, Some(oid.clone()), body).await?;
                                match send_archive(&me, &mut ev, &archive).await {
                                    Ok(stashed) => {
                                        // 传输间隙暂存的会话帧补处理(到达序保持)
                                        for text in stashed {
                                            handle_frame(cfg, &ch, pid_hint, &me, &mut tx, state, &text, &mut running).await?;
                                        }
                                    }
                                    Err(e) => {
                                        speak(&me, &mut tx, SessionKind::Error, Some(oid), json!({"code": "ship", "detail": e, "hint": "工件未收讫,工单可幂等重发"})).await?;
                                    }
                                }
                            }
                            Ok(Err((code, detail))) => {
                                speak(&me, &mut tx, SessionKind::Error, Some(oid), json!({"code": code, "detail": detail, "hint": "见 event 流水"})).await?;
                            }
                            Err(e) => {
                                speak(&me, &mut tx, SessionKind::Error, Some(oid), json!({"code": "engine-panic", "detail": e.to_string(), "hint": "采集线程异常终结"})).await?;
                            }
                        }
                        state.write(&json!({"state": "idle", "host": cfg.host}))?;
                    }
                }
            }
        }
    }
}

/// 等 Met;Some(true)=配对成功,Some(false)=线死,None=停止信号
async fn wait_met(ev: &mut e2ee::Events, sigterm: &mut tokio::signal::unix::Signal) -> Option<bool> {
    loop {
        tokio::select! {
            _ = sigterm.recv() => return None,
            Some(e) = ev.recv() => match e {
                Event::Met { .. } => return Some(true),
                Event::Left { .. } => return Some(false),
                _ => {}
            },
        }
    }
}

async fn speak(me: &Person, tx: &mut SessionTx, kind: SessionKind, order_id: Option<String>, body: serde_json::Value) -> Result<(), String> {
    let frame = tx.encode(kind, order_id, body)?;
    me.speak(&frame).await.map_err(|e| format!("speak 失败: {e}"))
}

async fn ack(me: &Person, tx: &mut SessionTx, order_id: String, accepted: bool, code: &str, detail: String, hint: &str) -> Result<(), String> {
    speak(me, tx, SessionKind::WorkorderAck, Some(order_id), json!({
        "accepted": accepted, "code": code, "detail": detail, "hint": hint,
    })).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame(
    cfg: &DaemonConfig,
    ch: &Arc<dyn Channel>,
    pid_hint: Option<u32>,
    me: &Person,
    tx: &mut SessionTx,
    state: &State,
    text: &str,
    running: &mut Option<Running>,
) -> Result<(), String> {
    let env = match session::decode(text) {
        Ok(e) => e,
        Err(e) => {
            return speak(me, tx, SessionKind::Error, None, json!({"code": "bad-envelope", "detail": e, "hint": "信封须为 §10.4 形态"})).await;
        }
    };
    match env.kind {
        SessionKind::WorkorderAssign => {
            let wo_raw = serde_json::to_vec(&env.body).map_err(|e| e.to_string())?;
            let wo: WorkOrder = match serde_json::from_slice(&wo_raw) {
                Ok(w) => w,
                Err(e) => {
                    return speak(me, tx, SessionKind::Error, env.order_id, json!({"code": "bad-workorder", "detail": e.to_string(), "hint": "对照 §10.1 v4"})).await;
                }
            };
            let order_id = wo.order_id.clone();
            if running.is_some() {
                return ack(me, tx, order_id, false, "busy", "有工单在跑".into(), "先 cancel 或等 done").await;
            }
            // 闸门:schema / 版本 / 卫生对齐 / 驱动能力——任一不符 = 响亮拒绝(不静默执行)
            if wo.schema != "exuvia.workorder" {
                return ack(me, tx, order_id, false, "bad-schema", wo.schema.clone(), "literal exuvia.workorder").await;
            }
            if wo.workorder_version != WORKORDER_VERSION {
                return ack(me, tx, order_id, false, "bad-version", format!("{}", wo.workorder_version), &format!("本端 = {WORKORDER_VERSION}")).await;
            }
            if wo.hygiene.hygiene_version != HYGIENE_VERSION {
                return ack(me, tx, order_id, false, "hygiene-mismatch", format!("{}", wo.hygiene.hygiene_version), &format!("本端 = {HYGIENE_VERSION}")).await;
            }
            if let Some(drv) = &wo.stealth.driver {
                let have = ch.channels();
                let missing: Vec<&String> = drv.channels.iter().filter(|c| !have.contains(c)).collect();
                if !missing.is_empty() {
                    return ack(me, tx, order_id, false, "capability", format!("缺 {missing:?} 现有 {have:?}"), "profile 能力须覆盖工单要求").await;
                }
            }
            ack(me, tx, order_id.clone(), true, "ok", "能力核对通过".into(), "").await?;
            state.write(&json!({"state": format!("running:{order_id}")}))?;

            // 引擎进阻塞线程(会话环不被采集阻塞——cancel/status 随时可达)
            let cancel = Arc::new(AtomicBool::new(false));
            let (evtx, evrx) = tokio::sync::mpsc::unbounded_channel();
            let ch2 = ch.clone();
            let ctx = Ctx { apk_root: cfg.apk_root.clone(), pid_hint, cancel: cancel.clone() };
            let join = tokio::task::spawn_blocking(move || {
                let mut evcb = |k: &str, v: serde_json::Value| { evtx.send((k.to_string(), v)).ok(); };
                engine::execute(&wo, &wo_raw, &*ch2, &ctx, &mut evcb)
            });
            *running = Some(Running { order_id, cancel, events: evrx, join });
        }
        SessionKind::WorkorderCancel => {
            match (&env.order_id, &running) {
                (Some(oid), Some(r)) if *oid == r.order_id => {
                    r.cancel.store(true, Ordering::Relaxed);
                    state.write(&json!({"state": format!("cancelling:{oid}")}))?;
                    speak(me, tx, SessionKind::StatusReport, env.order_id, json!({"state": "cancelling"})).await?;
                }
                _ => {
                    speak(me, tx, SessionKind::StatusReport, env.order_id, json!({"state": "idle"})).await?;
                }
            }
        }
        SessionKind::StatusQuery => {
            let st = match &running { Some(r) => format!("running:{}", r.order_id), None => "idle".into() };
            speak(me, tx, SessionKind::StatusReport, env.order_id, json!({"state": st})).await?;
        }
        // 羽化→主机词反向到达 = 协议错误(方向硬性,§10.4)
        other => {
            speak(me, tx, SessionKind::Error, env.order_id, json!({"code": "bad-direction", "detail": format!("{other:?} 不该到达羽化"), "hint": "方向见 §10.4 词表"})).await?;
        }
    }
    Ok(())
}

/// tar.gz 经文件族流式回传(4.1.0:无大小上限;FileDelivered 收讫;拒绝/超时如实报错)
/// 传输等待期间到达的会话帧(Heard)不得吞——暂存返回,由调用方收官后补处理
/// (旧实现 `_ => {}` 丢弃:主机在收讫间隙派新单,帧被吃掉,守护永不应答)
async fn send_archive(me: &Person, ev: &mut e2ee::Events, data: &[u8]) -> Result<Vec<String>, String> {
    let mut stashed: Vec<String> = Vec::new();
    let name = format!("{}.tar.gz", crate::rand_name("artifacts-"));
    me.file_begin(&name, data.len() as u64).await.map_err(|e| format!("file_begin: {e}"))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::select! {
            Some(e) = ev.recv() => match e {
                Event::FileAccepted { .. } => break,
                Event::FileDeclined { reason, .. } => return Err(format!("对端拒收: {reason:?}")),
                Event::Left { .. } => return Err("线死于文件传输前".into()),
                Event::Heard { text, .. } => stashed.push(text),
                _ => {}
            },
            _ = tokio::time::sleep_until(deadline) => return Err("等对端接受超时".into()),
        }
    }
    for chunk in data.chunks(256 * 1024) {
        me.file_chunk(chunk).await.map_err(|e| format!("file_chunk: {e}"))?;
    }
    me.file_end().await.map_err(|e| format!("file_end: {e}"))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        tokio::select! {
            Some(e) = ev.recv() => match e {
                Event::FileDelivered { .. } => return Ok(stashed),
                Event::Left { .. } => return Err("线死于等收讫".into()),
                Event::Heard { text, .. } => stashed.push(text),
                _ => {}
            },
            _ = tokio::time::sleep_until(deadline) => return Err("等收讫回执超时".into()),
        }
    }
}

/// stop 动词:SIGTERM 关停,等进程退场
pub fn stop(state_root: &Path, dir: Option<&Path>) -> Result<String, String> {
    let st = find_state(state_root, dir)?;
    let pid = st["pid"].as_u64().ok_or("state.json 缺 pid")? as i32;
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let t0 = std::time::Instant::now();
    while t0.elapsed().as_secs() < 10 {
        if !pid_alive(pid) { return Ok(format!("守护进程 {pid} 已停")); }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!("守护进程 {pid} 未在 10s 内退出"))
}

/// 活性判定:kill(pid,0) 对僵尸也"成功",须另认 /proc 状态字 Z
fn pid_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 { return false; }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s.rsplit(')').next().map(|t| t.split_whitespace().next() == Some("Z")).unwrap_or(false),
        Err(_) => false,
    }
}

/// status 动词:读状态文件 + 活性检查,JSON 行输出
pub fn status(state_root: &Path, dir: Option<&Path>) -> Result<String, String> {
    let st = find_state(state_root, dir)?;
    let pid = st["pid"].as_u64().ok_or("state.json 缺 pid")? as i32;
    let alive = pid_alive(pid);
    let mut out = st.clone();
    out["alive"] = json!(alive);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

fn find_state(state_root: &Path, dir: Option<&Path>) -> Result<serde_json::Value, String> {
    let file = match dir {
        Some(d) => d.join("state.json"),
        None => {
            let mut found = None;
            for e in std::fs::read_dir(state_root).map_err(|e| format!("状态根不可读: {e}"))?.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("eclosion-") && e.path().join("state.json").exists() {
                    if found.is_some() { return Err("多个守护实例在场,用 --dir 指定".into()); }
                    found = Some(e.path().join("state.json"));
                }
            }
            found.ok_or("未发现守护实例(状态目录不在场)")?
        }
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("状态文件读取失败: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("状态文件解析失败: {e}"))
}
