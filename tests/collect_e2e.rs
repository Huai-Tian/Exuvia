// collect --run 主机端全链测试（桌面零真机）：
//   ① 剧本假守护（测试内 e2ee Person）↔ 真 `exuvia collect --run` 子进程
//   ② 坏版本工单在监听前响亮拒绝
//   ③ Ctrl+C → workorder.cancel 帧实发
//   ④ 皇冠：真羽化守护子进程 ↔ 真 collect 子进程（§10.4 双向互操作实证）
use e2ee::{Event, Person};
use serde_json::json;

const SECRET: &[u8] = b"collect-e2e-pairing-secret";
const DEX_VA: u64 = 0x7000_0000_0000;

fn make_dex() -> Vec<u8> {
    let strings: [&[u8]; 3] = [b"I", b"Lcom/example/Bar;", b"Lcom/example/Foo;"];
    let mut out = vec![0u8; 0x88];
    let mut offs = Vec::new();
    for s in strings {
        offs.push(out.len() as u32);
        out.push(s.len() as u8);
        out.extend_from_slice(s);
        out.push(0);
    }
    for (i, o) in offs.iter().enumerate() {
        out[0x70 + i * 4..0x74 + i * 4].copy_from_slice(&o.to_le_bytes());
    }
    for (i, si) in [0u32, 1, 2].iter().enumerate() {
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

fn make_workorder(order_id: &str, apk_sha256: &str) -> serde_json::Value {
    json!({
        "$schema": "exuvia.workorder",
        "workorder_version": 4,
        "order_id": order_id,
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// 搭假现场：内存映像 + maps + 假已装应用 + 模拟 profile；回各路径
#[cfg(unix)] // 仅互操作皇冠案消费（守护实体只跑 unix）
fn stage_fake_device(tmp: &std::path::Path) -> (Vec<u8>, std::path::PathBuf, String) {
    let dex = make_dex();
    let mut image = vec![0u8; 0x6000];
    image[..dex.len()].copy_from_slice(&dex);
    image[0x4000..0x4008].copy_from_slice(&DEX_VA.to_le_bytes());
    std::fs::write(tmp.join("image.bin"), &image).unwrap();
    std::fs::write(tmp.join("maps.txt"), format!(
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
        "transport": { "kind": "file", "image": tmp.join("image.bin").display().to_string(), "maps": tmp.join("maps.txt").display().to_string(), "pid": 424242 },
        "ops": { "read": { "cmd": 0, "layout": "read40_v1" }, "read_list": null, "write": null,
                 "hide_proc": null, "pid_of": null, "mod_base": null }
    }).to_string()).unwrap();
    (dex, profile_p, sha256_hex(apk_bytes))
}

/// 假守护剧本：接线 → idle → 收单 → ack → 事件 → done(manifest)→ 文件族
async fn fake_daemon(port: u16, dex: &[u8]) {
    let (me, mut ev) = Person::born("fake-daemon", "127.0.0.1:0").await.unwrap();
    for _ in 0..50 {
        if me.dial_secret(&format!("127.0.0.1:{port}"), Some(SECRET)).await.is_ok() { break; }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // 收单
    let text = loop {
        if let Some(Event::Heard { text, .. }) = ev.recv().await {
            if text.contains("workorder.assign") { break text; }
        }
    };
    let env: serde_json::Value = serde_json::from_str(&text).unwrap();
    let oid = env["order_id"].as_str().unwrap().to_string();
    let wo_anchor = sha256_hex(&serde_json::to_vec(&env["body"]).unwrap());
    me.speak(&envelope("workorder.ack", 1, Some(&oid), json!({"accepted": true}))).await.unwrap();
    me.speak(&envelope("event", 2, Some(&oid),
        json!({"event": "dex_region", "fields": {"begin": format!("0x{DEX_VA:x}")}}))).await.unwrap();

    // manifest + 工件包
    let log_bytes = b"{\"k\":\"dex_region\"}\n".to_vec();
    let maps_bytes = b"fake-maps\n".to_vec();
    let dex_name = format!("classes_0x{DEX_VA:x}.dex");
    let mut tar_b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()));
    for (n, d) in [(dex_name.as_str(), dex), ("runtime-log.jsonl", &log_bytes[..]), ("maps.txt", &maps_bytes[..])] {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar_b.append_data(&mut h, n, &d[..]).unwrap();
    }
    let gz = tar_b.into_inner().unwrap().finish().unwrap();
    let manifest = json!({
        "$schema": "exuvia.manifest",
        "manifest_version": 2,
        "order_id": oid,
        "workorder_sha256": wo_anchor,
        "collector": { "name": "fake-daemon", "version": "0" },
        "device": { "abi": "arm64-v8a", "android_release": "15", "kernel": "sim", "root": "none" },
        "stealth_tier_used": "L0",
        "driver": null,
        "anchors_hit": [],
        "env_gates": [ { "gate": "ro.debuggable", "passed": true } ],
        "artifacts": [
            { "name": dex_name, "kind": "dex", "sha256": sha256_hex(dex), "size_bytes": dex.len() },
            { "name": "runtime-log.jsonl", "kind": "runtime-log", "sha256": sha256_hex(&log_bytes), "size_bytes": log_bytes.len() },
            { "name": "maps.txt", "kind": "maps", "sha256": sha256_hex(&maps_bytes), "size_bytes": maps_bytes.len() }
        ],
        "errors": [],
        "residuals_accepted": []
    });
    me.speak(&envelope("done", 3, Some(&oid), manifest)).await.unwrap();
    me.file_begin("artifacts.tar.gz", gz.len() as u64).await.unwrap();
    // 等应允再喂块
    loop {
        if let Some(Event::FileAccepted { .. }) = ev.recv().await { break; }
    }
    me.file_chunk(&gz).await.unwrap();
    me.file_end().await.unwrap();
    // 等主机收讫回执,随后体面离场
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(Event::FileDelivered { .. }) = ev.recv().await { break; }
        }
    }).await;
}

#[test]
fn collect_full_chain_scripted_daemon() {
    let tmp = std::env::temp_dir().join(format!("collect-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let dex = make_dex();
    let wo = make_workorder("wo-e2e-001", &sha256_hex(b"sim-apk-bytes"));
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string_pretty(&wo).unwrap()).unwrap();
    let out = tmp.join("out");
    let port = free_port();

    let dex2 = dex.clone();
    let daemon = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(fake_daemon(port, &dex2));
    });
    let host = std::process::Command::new(env!("CARGO_BIN_EXE_exuvia"))
        .args(["collect", "--run", "--listen", &format!("127.0.0.1:{port}"),
               "--workorder", &wo_p.display().to_string(), "--out", &out.display().to_string()])
        .env("EXUVIA_SECRET", std::str::from_utf8(SECRET).unwrap())
        .output().expect("collect 子进程");
    daemon.join().unwrap();

    assert!(host.status.success(), "collect 退场: {}", String::from_utf8_lossy(&host.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&host.stdout).unwrap();
    assert_eq!(summary["status"], json!("ok"));
    assert_eq!(summary["order_id"], json!("wo-e2e-001"));
    assert_eq!(summary["artifacts"].as_array().unwrap().len(), 3);

    // 落点四件齐 + 载荷字节级一致
    let got = std::fs::read(out.join(format!("classes_0x{DEX_VA:x}.dex"))).unwrap();
    assert_eq!(got, dex, "载荷字节级一致");
    assert!(out.join("artifacts.tar.gz").exists());
    assert!(out.join("manifest.json").exists());
    let log = std::fs::read_to_string(out.join("events.jsonl")).unwrap();
    assert!(log.contains("dex_region") && log.contains("\"done\""), "事件流水在册");
    std::fs::remove_dir_all(&tmp).ok();
    println!("COLLECT-E2E-PASS");
}

#[test]
fn collect_rejects_bad_version_before_listen() {
    let tmp = std::env::temp_dir().join(format!("collect-bad-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut wo = make_workorder("wo-e2e-bad", &sha256_hex(b"x"));
    wo["workorder_version"] = json!(99);
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string(&wo).unwrap()).unwrap();
    let host = std::process::Command::new(env!("CARGO_BIN_EXE_exuvia"))
        .args(["collect", "--run", "--listen", &format!("127.0.0.1:{}", free_port()),
               "--workorder", &wo_p.display().to_string()])
        .env("EXUVIA_SECRET", "x")
        .output().unwrap();
    assert!(!host.status.success());
    assert!(String::from_utf8_lossy(&host.stderr).contains("bad-version"), "响亮拒绝: {}", String::from_utf8_lossy(&host.stderr));
    std::fs::remove_dir_all(&tmp).ok();
}

#[cfg(unix)] // 撤销信号走 SIGINT(libc);Windows 控制台风慕另行裁定
#[test]
fn collect_cancel_sends_cancel_frame() {
    let tmp = std::env::temp_dir().join(format!("collect-cancel-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let wo = make_workorder("wo-e2e-cancel", &sha256_hex(b"sim-apk-bytes"));
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string_pretty(&wo).unwrap()).unwrap();
    let port = free_port();

    // 假守护:ack 后装死,只看撤销帧到不到
    let daemon = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let (me, mut ev) = Person::born("fake-daemon", "127.0.0.1:0").await.unwrap();
            for _ in 0..50 {
                if me.dial_secret(&format!("127.0.0.1:{port}"), Some(SECRET)).await.is_ok() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let mut got_cancel = false;
            while let Some(e) = ev.recv().await {
                if let Event::Heard { text, .. } = e {
                    if text.contains("workorder.assign") {
                        let env: serde_json::Value = serde_json::from_str(&text).unwrap();
                        let oid = env["order_id"].as_str().unwrap().to_string();
                        me.speak(&envelope("workorder.ack", 1, Some(&oid), json!({"accepted": true}))).await.unwrap();
                    }
                    if text.contains("workorder.cancel") { got_cancel = true; break; }
                }
            }
            assert!(got_cancel, "撤销帧应到达守护");
        });
    });

    let child = std::process::Command::new(env!("CARGO_BIN_EXE_exuvia"))
        .args(["collect", "--run", "--listen", &format!("127.0.0.1:{port}"),
               "--workorder", &wo_p.display().to_string(), "--out", &tmp.join("out").display().to_string()])
        .env("EXUVIA_SECRET", std::str::from_utf8(SECRET).unwrap())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500)); // 等 ack 落定
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let out = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(!out.status.success(), "撤销应非零退场");
    assert!(String::from_utf8_lossy(&out.stderr).contains("cancelled"), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    std::fs::remove_dir_all(&tmp).ok();
}

/// 皇冠:真羽化守护 ↔ 真 collect —— §10.4 双向互操作实证
#[cfg(unix)] // 守护只跑 Android/Linux;Windows 桌面此案缺席(宿主两案照跑)
#[test]
fn collect_real_daemon_interop() {
    let exuvia_bin = env!("CARGO_BIN_EXE_exuvia");
    let eclosion_bin = std::path::Path::new(exuvia_bin).parent().unwrap().join("exuvia-eclosion");
    assert!(eclosion_bin.exists(), "先跑 cargo test --workspace（需守护二进制在场）");

    let tmp = std::env::temp_dir().join(format!("collect-interop-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let (dex, profile_p, apk_sha) = stage_fake_device(&tmp);
    let wo = make_workorder("wo-e2e-interop", &apk_sha);
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string_pretty(&wo).unwrap()).unwrap();
    let out = tmp.join("out");
    let port = free_port();
    let secret = std::str::from_utf8(SECRET).unwrap();

    // 守护子进程
    let mut daemon = std::process::Command::new(&eclosion_bin)
        .args(["run", "--host", &format!("127.0.0.1:{port}"), "--profile", &profile_p.display().to_string(),
               "--state-root", &tmp.display().to_string(), "--apk-root", &tmp.join("apps").display().to_string(),
               "--no-harden"])
        .env("ECLOSION_SECRET", secret)
        .stdout(std::fs::File::create(tmp.join("daemon.out")).unwrap())
        .stderr(std::fs::File::create(tmp.join("daemon.err")).unwrap())
        .spawn().expect("守护子进程拉起");
    std::thread::sleep(std::time::Duration::from_millis(500)); // 守护拨号前,主机先听

    let host = std::process::Command::new(exuvia_bin)
        .args(["collect", "--run", "--listen", &format!("127.0.0.1:{port}"),
               "--workorder", &wo_p.display().to_string(), "--out", &out.display().to_string()])
        .env("EXUVIA_SECRET", secret)
        .output().expect("collect 子进程");

    assert!(host.status.success(), "collect: {}\n守护err: {}",
        String::from_utf8_lossy(&host.stderr),
        std::fs::read_to_string(tmp.join("daemon.err")).unwrap_or_default());
    let summary: serde_json::Value = serde_json::from_slice(&host.stdout).unwrap();
    assert_eq!(summary["status"], json!("ok"));
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["collector"]["name"], json!("exuvia-eclosion"));
    assert_eq!(manifest["collector"]["version"], json!("0.2.0"));
    assert_eq!(manifest["order_id"], json!("wo-e2e-interop"));
    let got = std::fs::read(out.join(format!("classes_0x{DEX_VA:x}.dex"))).unwrap();
    assert_eq!(got, dex, "真守护挖出载荷,字节级一致");

    // 收尾:stop 动词送走守护
    let so = std::process::Command::new(&eclosion_bin)
        .args(["stop", "--state-root", &tmp.display().to_string()])
        .output().expect("stop 动词");
    assert!(so.status.success(), "stop: {}", String::from_utf8_lossy(&so.stderr));
    assert!(daemon.wait().unwrap().success(), "守护正常退场");
    std::fs::remove_dir_all(&tmp).ok();
    println!("COLLECT-INTEROP-PASS");
}
