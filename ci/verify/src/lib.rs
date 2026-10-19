//! ci-verify 核心（对账与登记逻辑；main.rs 是 CLI 壳）。
//! 内部开发工具，不进发行物；比对逻辑公开、样本私有。

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// APK 里全部可解析 DEX 的方法集（(class, name, descriptor)）与类集。
/// parse 失败的 dex 跳过（加固包里是常态）；原包 dex 坏 = 调用方报错。
pub fn apk_method_sets(apk: &Path) -> Result<(BTreeSet<(String, String, String)>, BTreeSet<String>), String> {
    let file = std::fs::File::open(apk).map_err(|e| format!("open {}: {e}", apk.display()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("zip parse {}: {e}", apk.display()))?;
    let mut methods = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| format!("zip entry {i}: {e}"))?;
        let name = entry.name().map_err(|e| format!("zip name {i}: {e}"))?.to_string();
        if !(name.starts_with("classes") && name.ends_with(".dex")) {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| format!("dex read {name}: {e}"))?;
        if let Ok(list) = exuvia::track_a::dex::parse(&bytes) {
            for m in list {
                classes.insert(m.class.clone());
                methods.insert((m.class, m.name, m.descriptor));
            }
        }
    }
    Ok((methods, classes))
}

/// handoff/workspace/*/recovered.dex 的方法集与类集（merge 闸门销账后的 L1 骨架）。
pub fn recovered_sets(handoff: &Path) -> Result<(BTreeSet<(String, String, String)>, BTreeSet<String>), String> {
    let mut methods = BTreeSet::new();
    let mut classes = BTreeSet::new();
    let ws = handoff.join("workspace");
    let entries = match std::fs::read_dir(&ws) {
        Ok(e) => e,
        Err(_) => return Ok((methods, classes)), // 无 workspace = 零恢复（诚实空集）
    };
    for e in entries.flatten() {
        let dex_path = e.path().join("recovered.dex");
        if let Ok(bytes) = std::fs::read(&dex_path) {
            if let Ok(list) = exuvia::track_a::dex::parse(&bytes) {
                for m in list {
                    classes.insert(m.class.clone());
                    methods.insert((m.class, m.name, m.descriptor));
                }
            }
        }
    }
    Ok((methods, classes))
}

fn coverage<T: Ord>(sub: &BTreeSet<T>, sup: &BTreeSet<T>) -> f64 {
    if sub.is_empty() {
        return 0.0;
    }
    // 0..1 比率，3 位小数（产物字节确定性：同输入同输出）
    ((sub.intersection(sup).count() as f64 / sub.len() as f64) * 1000.0).round() / 1000.0
}

/// 语料登记：<name>.orig.apk + <name>.packed.apk 对 → corpus.json。
/// 语料本体永远私有；清单只放 hash 与大小（获取指南的数据半边）。
pub fn register(dir: &Path) -> Result<String, String> {
    let mut entries = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|x| format!("read dir {}: {x}", dir.display()))?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".orig.apk") {
            let packed = dir.join(format!("{stem}.packed.apk"));
            let orig = dir.join(&name);
            if !packed.is_file() {
                return Err(format!("orig without packed: {name} (expect {}.packed.apk)", stem));
            }
            let so = sha256_file(&orig)?;
            let sp = sha256_file(&packed)?;
            let zo = std::fs::metadata(&orig).map_err(|x| format!("stat {name}: {x}"))?.len();
            let zp = std::fs::metadata(&packed).map_err(|x| format!("stat {}: {x}", packed.display()))?.len();
            entries.push(serde_json::json!({
                "name": stem,
                "orig": { "sha256": so, "size_bytes": zo },
                "packed": { "sha256": sp, "size_bytes": zp },
            }));
        }
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let manifest = serde_json::json!({ "entries": entries });
    std::fs::write(dir.join("corpus.json"), serde_json::to_vec_pretty(&manifest).unwrap())
        .map_err(|e| format!("write corpus.json: {e}"))?;
    Ok(serde_json::to_string_pretty(&manifest).unwrap())
}

/// 原包对账（内部开发指标）：原包 ground truth vs (可见 ∪ 已恢复)。
pub fn check(orig: &Path, packed: &Path, handoff: &Path) -> Result<String, String> {
    let (orig_methods, orig_classes) = apk_method_sets(orig)?;
    if orig_classes.is_empty() {
        return Err(format!("no parseable DEX in orig {} — corpus is broken", orig.display()));
    }
    let (vis_methods, vis_classes) = apk_method_sets(packed)?;
    let (rec_methods, rec_classes) = recovered_sets(handoff)?;

    let mut all_methods = vis_methods.clone();
    all_methods.extend(rec_methods.iter().cloned());
    let mut all_classes = vis_classes.clone();
    all_classes.extend(rec_classes.iter().cloned());

    let out = serde_json::json!({
        "orig": { "methods": orig_methods.len(), "classes": orig_classes.len() },
        "packed_visible": { "methods": vis_methods.len(), "classes": vis_classes.len() },
        "handoff_recovered": { "methods": rec_methods.len(), "classes": rec_classes.len() },
        "combined": { "methods": all_methods.len(), "classes": all_classes.len() },
        "class_coverage": coverage(&orig_classes, &all_classes),
        "method_coverage": coverage(&orig_methods, &all_methods),
    });
    Ok(serde_json::to_string_pretty(&out).unwrap())
}
