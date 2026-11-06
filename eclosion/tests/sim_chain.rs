#![cfg(unix)] // 羽化是设备侧执行器——测试随库同门(Windows 桌面不编译)
// 模拟全链自走通(立项书 §8 出口:假驱动 profile + 假内存图,桌面零真机):
//   真子进程跑 run 动词(会话层 + 守护全在环内)↔ 测试扮主机
//   → workorder.assign → ack → event 流水 → done(manifest)→ tar.gz 文件族收讫
//   → 字节级验货(载荷 == 种植 dex)→ status/stop 动词走真实进程。
use e2ee::{Event, Person, Receive};
use serde_json::json;

const SECRET: &[u8] = b"sim-chain-pairing-secret";
const DEX_VA: u64 = 0x7000_0000_0000;

/// 最小结构合法 dex:头 0x70 + string_ids + type_ids + 字符串区
fn make_dex() -> Vec<u8> {
    let strings: [&[u8]; 3] = [b"I", b"Lcom/example/Bar;", b"Lcom/example/Foo;"];
    let mut out = vec![0u8; 0x88];
    let mut offs = Vec::new();
    for s in strings {
        offs.push(out.len() as u32);
        out.push(s.len() as u8); // uleb128(<128 单字节)
        out.extend_from_slice(s);
        out.push(0);
    }
    for (i, o) in offs.iter().enumerate() {
        out[0x70 + i * 4..0x74 + i * 4].copy_from_slice(&o.to_le_bytes());
    }
    for (i, si) in [0u32, 1, 2].iter().enumerate() { // 描述符序:"I" < "Lcom…Bar;" < "Lcom…Foo;"
        out[0x7c + i * 4..0x80 + i * 4].copy_from_slice(&si.to_le_bytes());
    }
    out[0..8].copy_from_slice(b"dex\n039\0");
    let fs = out.len() as u32;
    out[0x20..0x24].copy_from_slice(&fs.to_le_bytes());
    out[0x34..0x38].copy_from_slice(&0x70u32.to_le_bytes());
    out[0x38..0x3c].copy_from_slice(&3u32.to_le_bytes());
    out[0x3c..0x40].copy_from_slice(&0x70u32.to_le_bytes());
    out[0x40..0x44].copy_from_slice(&3u32.to_le_bytes());
    out[0x44..0x48].copy_from_slice(&0x7cu32.to_le_bytes());
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    format!("sha256:{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn envelope(kind: &str, seq: u64, order_id: Option<&str>, body: serde_json::Value) -> String {
    json!({
        "$schema": "exuvia.session",
        "session_version": 1,
        "kind": kind,
        "seq": seq,
        "order_id": order_id,
        "body": body,
    }).to_string()
}

fn make_workorder(apk_sha256: &str) -> serde_json::Value {
    json!({
        "$schema": "exuvia.workorder",
        "workorder_version": 4,
        "order_id": "wo-sim-001",
        "target": {
            "package": "com.sim.app",
            "apk_sha256": apk_sha256,
            "launch_activity": "com.sim.app/.Main"
        },
        "family": { "id": "unknown", "evidence": [] },
        "extraction": {
            "mode": "passive",
            "art_anchors": [],
            "seed_plan": null,
            "scan": {
                "regions": { "perms": "r--p", "anonymous_only": true, "min_size": 4096, "max_size": 67108864, "exclude": [] },
                "magic": [ { "name": "dex039", "hex": "6465780a30333900" } ],
                "poll": { "interval_ms": 50, "stable_rounds": 2, "window_s": 30 },
                "carve": { "verify_header": true, "max_size": 33554432 }
            }
        },
        "env_gates": [ { "gate": "ro.debuggable", "expected": "0", "evidence": "sim" } ],
        "stealth": { "tier": "L0", "driver": null },
        "hygiene": { "hygiene_version": 3, "random_artifacts": true, "one_shot": true },
        "deliverables": ["dex", "runtime-log", "maps"]
    })
}

async fn wait_event<F>(ev: &mut e2ee::Events, secs: u64, mut pred: F) -> Event
where F: FnMut(&Event) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        tokio::select! {
            Some(e) = ev.recv() => { if pred(&e) { return e; } }
            _ = tokio::time::sleep_until(deadline) => panic!("等事件超时"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sim_full_chain() {
    // ── 摆假现场:内存映像(dex + 反查针)+ maps + 假已装应用 + 模拟 profile ──
    let tmp = std::env::temp_dir().join(format!("eclosion-sim-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let dex = make_dex();
    let mut image = vec![0u8; 0x6000];
    image[..dex.len()].copy_from_slice(&dex);
    image[0x4000..0x4008].copy_from_slice(&DEX_VA.to_le_bytes()); // 反查归属针
    let image_p = tmp.join("image.bin");
    std::fs::write(&image_p, &image).unwrap();
    let maps_p = tmp.join("maps.txt");
    std::fs::write(&maps_p, format!(
        "{DEX_VA:012x}-{:012x} r--p 00000000 00:00 0          [anon:dalvik-DEX]\n{:012x}-{:012x} rw-p 00000000 00:00 0          [anon:dalvik-alloc]\n",
        DEX_VA + 0x4000, DEX_VA + 0x4000, DEX_VA + 0x6000)).unwrap();
    let apk_root = tmp.join("apps");
    std::fs::create_dir_all(apk_root.join("com.sim.app-1")).unwrap();
    let apk_bytes = b"sim-apk-bytes";
    std::fs::write(apk_root.join("com.sim.app-1/base.apk"), apk_bytes).unwrap();
    let profile_p = tmp.join("profile.json");
    std::fs::write(&profile_p, json!({
        "driver_profile_version": 1,
        "name": "sim-file", "version": "0",
        "transport": { "kind": "file", "image": image_p.display().to_string(), "maps": maps_p.display().to_string(), "pid": 424242 },
        "ops": { "read": { "cmd": 0, "layout": "read40_v1" }, "read_list": null, "write": null,
                 "hide_proc": null, "pid_of": null, "mod_base": null }
    }).to_string()).unwrap();

    // ── 主机侧 ──
    let (host, mut host_ev) = Person::born("host", "127.0.0.1:0").await.unwrap();
    host.expect_secret_stable(SECRET).await;
    // 收档策略按"聚焦线"设置——得等 Met 落地、线有了焦点再设。
    let haddr = host.listen_addr().await;

    // ── 守护:真子进程跑 run 动词 ──
    let bin = env!("CARGO_BIN_EXE_exuvia-eclosion");
    let child_log = std::fs::File::create(tmp.join("daemon.log")).unwrap();
    let child_log2 = child_log.try_clone().unwrap();
    let mut child = std::process::Command::new(bin)
        .args(["run", "--host", &haddr, "--profile", &profile_p.display().to_string(),
               "--state-root", &tmp.display().to_string(), "--apk-root", &apk_root.display().to_string(),
               "--no-harden"])
        .env("ECLOSION_SECRET", std::str::from_utf8(SECRET).unwrap())
        .stdout(child_log).stderr(child_log2)
        .spawn().expect("守护子进程拉起");

    // Met → idle 状态报告
    wait_event(&mut host_ev, 20, |e| matches!(e, Event::Met { .. })).await;
    host.set_receive(Receive::Always).await.unwrap();
    let e = wait_event(&mut host_ev, 10, |e| matches!(e, Event::Heard { text, .. } if text.contains("status.report"))).await;
    let Event::Heard { text, .. } = e else { unreachable!() };
    assert!(text.contains("\"idle\""), "首报 = idle: {text}");

    // status 动词(CLI 真实进程)
    let st = std::process::Command::new(bin).args(["status", "--state-root", &tmp.display().to_string()])
        .output().expect("status 动词");
    assert!(st.status.success(), "status: {}", String::from_utf8_lossy(&st.stderr));
    let st: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(st["alive"], json!(true), "守护活性: {st}");

    // ── 派单 ──
    let wo = make_workorder(&sha256_hex(apk_bytes));
    let wo_sha = sha256_hex(serde_json::to_string(&wo).unwrap().as_bytes());
    host.speak(&envelope("workorder.assign", 1, Some("wo-sim-001"), wo)).await.unwrap();

    // ack(accepted=true)
    let e = wait_event(&mut host_ev, 15, |e| matches!(e, Event::Heard { text, .. } if text.contains("workorder.ack"))).await;
    let Event::Heard { text, .. } = e else { unreachable!() };
    assert!(text.contains("\"accepted\":true"), "ack: {text}");

    // event 流水 + done(manifest)+ 文件族
    let mut saw_dex_region = false;
    let mut saw_identify = false;
    let mut manifest: Option<serde_json::Value> = None;
    let mut archive: Vec<u8> = Vec::new();
    let mut archive_done = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while !archive_done {
        tokio::select! {
            Some(e) = host_ev.recv() => match e {
                Event::Heard { text, .. } => {
                    eprintln!("[host] heard: {}", &text[..text.len().min(160)]);
                    if text.contains("\"dex_region\"") { saw_dex_region = true; }
                    if text.contains("\"dex_identify\"") {
                        assert!(text.contains("com.example"), "包名前缀挖到: {text}");
                        saw_identify = true;
                    }
                    if text.contains("\"done\"") {
                        let env: serde_json::Value = serde_json::from_str(&text).unwrap();
                        manifest = Some(env["body"].clone());
                    }
                }
                Event::FileChunk { data, .. } => archive.extend_from_slice(&data),
                Event::FileRequested { name, size, auto, .. } => eprintln!("[host] 来件 {name} {size}B auto={auto}"),
                Event::FileComplete { .. } => { eprintln!("[host] 收讫"); archive_done = true; }
                e => eprintln!("[host] 事件 {e:?}"),
            },
            _ = tokio::time::sleep_until(deadline) => panic!("全链超时"),
        }
    }
    let manifest = manifest.expect("done 到达");
    assert_eq!(manifest["$schema"], json!("exuvia.manifest"));
    assert_eq!(manifest["manifest_version"], json!(2));
    assert_eq!(manifest["order_id"], json!("wo-sim-001"));
    assert_eq!(manifest["workorder_sha256"], json!(wo_sha), "工单锚回显");
    assert_eq!(manifest["collector"]["name"], json!("exuvia-eclosion"));
    assert_eq!(manifest["collector"]["version"], json!("0.2.0"));

    // 验货:tar.gz 解开,载荷字节 == 种植 dex
    let gz = flate2::read::GzDecoder::new(&archive[..]);
    let mut tar = tar::Archive::new(gz);
    let mut found = false;
    let mut saw_log = false;
    let mut saw_maps = false;
    for e in tar.entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path().unwrap().to_string_lossy().to_string();
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut data).unwrap();
        if name == format!("classes_0x{DEX_VA:x}.dex") {
            assert_eq!(data, dex, "载荷字节级一致");
            assert_eq!(sha256_hex(&data), manifest["artifacts"][0]["sha256"].as_str().unwrap());
            found = true;
        }
        if name == "runtime-log.jsonl" { saw_log = true; }
        if name == "maps.txt" { saw_maps = true; }
    }
    assert!(found && saw_log && saw_maps, "dex/runtime-log/maps 三件齐");
    assert!(saw_dex_region && saw_identify, "事件流水含 dex_region/dex_identify");

    // 坏版本工单 = 响亮拒绝
    let mut bad = make_workorder(&sha256_hex(apk_bytes));
    bad["workorder_version"] = json!(99);
    bad["order_id"] = json!("wo-sim-bad");
    host.speak(&envelope("workorder.assign", 2, Some("wo-sim-bad"), bad)).await.unwrap();
    let e = wait_event(&mut host_ev, 10, |e| matches!(e, Event::Heard { text, .. } if text.contains("workorder.ack"))).await;
    let Event::Heard { text, .. } = e else { unreachable!() };
    assert!(text.contains("\"accepted\":false") && text.contains("bad-version"), "坏版本响亮拒绝: {text}");

    // status.query 应答 idle
    host.speak(&envelope("status.query", 3, None, json!({}))).await.unwrap();
    let e = wait_event(&mut host_ev, 10, |e| matches!(e, Event::Heard { text, .. } if text.contains("status.report"))).await;
    let Event::Heard { text, .. } = e else { unreachable!() };
    assert!(text.contains("\"idle\""), "完工后归 idle: {text}");

    // stop 动词(CLI 真实进程)→ 子进程退场 + 状态目录清理
    let so = std::process::Command::new(bin).args(["stop", "--state-root", &tmp.display().to_string()])
        .output().expect("stop 动词");
    assert!(so.status.success(), "stop: {}", String::from_utf8_lossy(&so.stderr));
    let code = child.wait().expect("子进程退出码");
    assert!(code.success(), "守护正常退场: {code:?}");
    assert!(!std::fs::read_dir(&tmp).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("eclosion-")),
        "状态目录已清理");
    std::fs::remove_dir_all(&tmp).ok();
    println!("SIM-CHAIN-PASS");
}
