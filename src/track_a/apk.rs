//! APK 解包与清点——轨道 A 第一段。
//! 只做结构测量（zip 遍历、sha256、DEX magic 格式事实、asset 熵），零业务语义。

use crate::report::{
    ApkInfo, AssetEntry, DebtEntry, DebtFile, DebtStatus, DebtSummary, DexEntry, Fingerprint,
    Inventory, MethodRef, Report, SoEntry,
};
use crate::track_a::entropy::EntropyCounter;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

const BUF: usize = 64 * 1024;

/// 第一遍竖切：解包 + 清点 + 熵测量 + DEX 方法清点 → (REPORT, debt)。
/// 指纹判定不在此处——fence 未配置指纹字段，一切样本按未知族主线输出（matched=false）。
/// 加密 DEX（magic 不符）是敌意输入常态：不进 debt，仅以 magic_ok=false 留在清点事实里。
pub fn first_pass(apk_path: &Path) -> Result<(Report, DebtFile), String> {
    let file = File::open(apk_path).map_err(|e| format!("open apk: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("apk metadata: {e}"))?;
    let mut archive = ZipArchive::new(file).map_err(|e| format!("apk zip parse: {e}"))?;

    let apk_sha = {
        let mut f = File::open(apk_path).map_err(|e| format!("reopen apk: {e}"))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; BUF];
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("apk read: {e}"))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        format!("sha256:{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
    };

    let mut dex = Vec::new();
    let mut so = Vec::new();
    let mut assets = Vec::new();
    let mut manifest_present = false;
    let mut other: u64 = 0;
    let mut native_methods: Vec<crate::track_a::dex::MethodInfo> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| format!("zip entry {i}: {e}"))?;
        if entry.is_dir() {
            continue;
        }
        let name: String = entry
            .name()
            .map_err(|e| format!("zip name {i}: {e}"))?
            .to_string();
        let size = entry.size();

        // 分类清点（机械路径匹配，非语义）
        if name == "AndroidManifest.xml" {
            manifest_present = true;
            other += 1;
        } else if name.starts_with("classes") && name.ends_with(".dex") {
            // 完整读入（方法清点需要全量表结构）。
            // 不按声明 size 预分配——敌意 zip 的 size 字段可伪造，read_to_end 自行增长即安全。
            let mut bytes = Vec::new();
            let e: &mut dyn std::io::Read = entry.by_ref();
            e.read_to_end(&mut bytes).map_err(|x| format!("dex read {name}: {x}"))?;
            let magic_ok = bytes.starts_with(b"dex\n") && bytes.get(7) == Some(&0);
            let mut parse_ok = false;
            if magic_ok {
                // 表结构损坏 = 敌意输入常态：事实标注，不让单个 dex 失败拖垮整次剖析
                match crate::track_a::dex::parse(&bytes) {
                    Ok(methods) => {
                        native_methods.extend(methods.into_iter().filter(|m| m.is_native));
                        parse_ok = true;
                    }
                    Err(_) => {}
                }
            }
            dex.push(DexEntry { name, size_bytes: size, magic_ok, parse_ok });
        } else if let Some(rest) = name.strip_prefix("lib/") {
            let (abi, has_file) = match rest.split_once('/') {
                Some((a, _)) => (a.to_string(), true),
                None => (String::new(), false),
            };
            if has_file {
                so.push(SoEntry { name, abi, size_bytes: size });
            } else {
                other += 1;
            }
        } else if let Some(rest) = name.strip_prefix("assets/") {
            if rest.is_empty() {
                other += 1;
                continue;
            }
            // 流式读：熵计数器全程更新，不落内存
            let mut ent = EntropyCounter::new();
            let e: &mut dyn std::io::Read = entry.by_ref();
            let mut buf = vec![0u8; BUF];
            loop {
                let n = e.read(&mut buf).map_err(|x| format!("asset read {name}: {x}"))?;
                if n == 0 {
                    break;
                }
                ent.update(&buf[..n]);
            }
            assets.push(AssetEntry {
                name,
                size_bytes: size,
                entropy: ent.bits_per_byte(),
            });
        } else {
            other += 1;
        }
    }

    // native stubs → debt 条目（事实，无判断；debt_id 稳定排序保证产物字节确定性）
    let mut entries = Vec::with_capacity(native_methods.len());
    {
        let mut sorted = native_methods.clone();
        sorted.sort_by(|a, b| (&a.class, &a.name, &a.descriptor).cmp(&(&b.class, &b.name, &b.descriptor)));
        for (i, m) in sorted.iter().enumerate() {
            // descriptor "Lcom/example/Foo;" → FQCN "com.example.Foo"（机械变换）
            let fqcn = m
                .class
                .strip_prefix('L')
                .and_then(|s| s.strip_suffix(';'))
                .unwrap_or(&m.class)
                .replace('/', ".");
            entries.push(DebtEntry {
                debt_id: format!("debt-{:04}", i + 1),
                method: MethodRef { class: fqcn, name: m.name.clone(), descriptor: m.descriptor.clone() },
                status: DebtStatus::BlockedSolvable,
                facts: vec![
                    "native stub — body outside DEX (access_flags ACC_NATIVE)".to_string(),
                ],
                attempts: 0,
            });
        }
    }

    let total = entries.len() as u64;
    let debt_file = DebtFile {
        schema: "exuvia.debt".to_string(),
        handoff_version: crate::version::HANDOFF_VERSION,
        entries,
    };
    let summary = DebtSummary { total, blocked_solvable: total, out_of_scope: 0 };

    Ok((
        Report {
            schema: "exuvia.report".to_string(),
            handoff_version: crate::version::HANDOFF_VERSION,
            apk: ApkInfo { sha256: apk_sha, size_bytes: meta.len() },
            // 未知族主线：fence 无指纹配置时唯一诚实的输出
            fingerprint: Fingerprint { matched: false, family: None, confidence: None },
            inventory: Inventory { dex, so, assets, android_manifest_present: manifest_present, other_entries: other },
            debt: summary,
            unavailable: Vec::new(),
        },
        debt_file,
    ))
}
