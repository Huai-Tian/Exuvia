#![cfg(unix)] // 羽化是设备侧执行器——测试随库同门(Windows 桌面不编译)
// exec 动词本地直采链测试(调试通道,无会话):
//   工单 → 闸门 → 引擎(文件模拟通道)→ 工件落盘(逐件 sha256 对账)
//   坏版本工单在闸门响亮拒绝(非零退场,stderr 三件套)。
// 摆设同 sim_chain(两层 /data/app 布局 + 种植 dex + file profile);目录带测试名
// 前缀防同进程互踩(教训 #8:固定 /tmp 目录两轮并行互踩计数)。
use serde_json::json;

const DEX_VA: u64 = 0x7000_0000_0000;

/// 最小结构合法 dex(同 sim_chain/collect_e2e 摆设)
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

/// 摆假现场:内存映像 + maps + 两层 /data/app 布局 + file profile;回 (种植 dex, apk sha)
fn stage_fake_device(tmp: &std::path::Path) -> (Vec<u8>, String) {
    let dex = make_dex();
    let mut image = vec![0u8; 0x6000];
    image[..dex.len()].copy_from_slice(&dex);
    image[0x4000..0x4008].copy_from_slice(&DEX_VA.to_le_bytes()); // 反查归属针
    std::fs::write(tmp.join("image.bin"), &image).unwrap();
    std::fs::write(tmp.join("maps.txt"), format!(
        "{DEX_VA:012x}-{:012x} r--p 00000000 00:00 0          [anon:dalvik-DEX]\n{:012x}-{:012x} rw-p 00000000 00:00 0          [anon:dalvik-alloc]\n",
        DEX_VA + 0x4000, DEX_VA + 0x4000, DEX_VA + 0x6000)).unwrap();
    let apk_root = tmp.join("apps");
    std::fs::create_dir_all(apk_root.join("~~simRand==").join("com.sim.app-1")).unwrap();
    let apk_bytes = b"sim-apk-bytes";
    std::fs::write(apk_root.join("~~simRand==/com.sim.app-1/base.apk"), apk_bytes).unwrap();
    let profile_p = tmp.join("profile.json");
    std::fs::write(&profile_p, json!({
        "driver_profile_version": 1,
        "name": "sim-file", "version": "0",
        "transport": { "kind": "file", "image": tmp.join("image.bin").display().to_string(), "maps": tmp.join("maps.txt").display().to_string(), "pid": 424242 },
        "ops": { "read": { "cmd": 0, "layout": "read40_v1" }, "read_list": null, "write": null,
                 "hide_proc": null, "pid_of": null, "mod_base": null }
    }).to_string()).unwrap();
    (dex, sha256_hex(apk_bytes))
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("eclosion-exec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 本地直采全链:真子进程跑 exec 动词(词表/会话零参与)→ 工件四件齐 + 字节级一致
#[test]
fn exec_local_chain_happy_path() {
    let tmp = unique_dir("happy");
    let (dex, apk_sha) = stage_fake_device(&tmp);
    let wo = make_workorder("wo-exec-001", &apk_sha);
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string_pretty(&wo).unwrap()).unwrap();
    let out = tmp.join("out");

    let bin = env!("CARGO_BIN_EXE_exuvia-eclosion");
    let host = std::process::Command::new(bin)
        .args(["exec", "--workorder", &wo_p.display().to_string(),
               "--profile", &tmp.join("profile.json").display().to_string(),
               "--apk-root", &tmp.join("apps").display().to_string(),
               "--out", &out.display().to_string()])
        .output().expect("exec 子进程拉起");
    let stdout = String::from_utf8_lossy(&host.stdout);
    let stderr = String::from_utf8_lossy(&host.stderr);
    assert!(host.status.success(), "exec 退场失败\nstdout: {stdout}\nstderr: {stderr}");

    // stdout = JSON 摘要(CLI 就是 API)
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout 应为单 JSON: {e}\nstdout: {stdout}"));
    assert_eq!(summary["status"], json!("ok"));
    assert_eq!(summary["order_id"], json!("wo-exec-001"));
    assert_eq!(summary["collector"]["name"], json!("exuvia-eclosion"));
    assert_eq!(summary["collector"]["version"], json!("0.2.1"));

    // 落点四件齐(manifest/artifacts.tar.gz/events.jsonl/逐件解开)
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["$schema"], json!("exuvia.manifest"));
    assert_eq!(manifest["manifest_version"], json!(2));
    assert_eq!(manifest["order_id"], json!("wo-exec-001"));
    // 工单锚 = 解析 Value 的 to_vec 逐位对齐
    let wo_value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&wo_p).unwrap()).unwrap();
    assert_eq!(manifest["workorder_sha256"], json!(sha256_hex(&serde_json::to_vec(&wo_value).unwrap())));
    assert!(out.join("artifacts.tar.gz").exists(), "tar.gz 归档在");
    let log = std::fs::read_to_string(out.join("events.jsonl")).unwrap();
    assert!(log.contains("dex_region") && log.contains("dex_stable") && log.contains("dex_identify"),
        "事件流水含直扫/判稳/身份: {log}");

    // 解开工件字节级一致
    let got = std::fs::read(out.join(format!("classes_0x{DEX_VA:x}.dex"))).unwrap();
    assert_eq!(got, dex, "载荷字节级一致");
    assert!(out.join("runtime-log.jsonl").exists() && out.join("maps.txt").exists(), "runtime-log/maps 齐");
    std::fs::remove_dir_all(&tmp).ok();
    println!("EXEC-DIRECT-PASS");
}

/// 坏版本工单在闸门响亮拒绝(非零退场,stderr 含 bad-version 三件套)
#[test]
fn exec_rejects_bad_version() {
    let tmp = unique_dir("badver");
    let (_dex, apk_sha) = stage_fake_device(&tmp);
    let mut wo = make_workorder("wo-exec-bad", &apk_sha);
    wo["workorder_version"] = json!(99);
    let wo_p = tmp.join("wo.json");
    std::fs::write(&wo_p, serde_json::to_string_pretty(&wo).unwrap()).unwrap();

    let bin = env!("CARGO_BIN_EXE_exuvia-eclosion");
    let host = std::process::Command::new(bin)
        .args(["exec", "--workorder", &wo_p.display().to_string(),
               "--profile", &tmp.join("profile.json").display().to_string(),
               "--apk-root", &tmp.join("apps").display().to_string(),
               "--out", &tmp.join("out").display().to_string()])
        .output().expect("exec 子进程拉起");
    let stderr = String::from_utf8_lossy(&host.stderr);
    assert!(!host.status.success(), "坏版本应非零退场");
    assert!(stderr.contains("bad-version"), "响亮拒绝 bad-version: {stderr}");
    std::fs::remove_dir_all(&tmp).ok();
}
