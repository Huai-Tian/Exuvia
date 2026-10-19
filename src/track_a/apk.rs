//! APK 解包与清点——轨道 A 第一段。
//! 只做结构测量（zip 遍历、sha256、DEX magic 格式事实、asset 熵），零业务语义。
//! 卡点两类：method-native-stub（ACC_NATIVE）与 encrypted-payload（坏 DEX 机械事实）。

use crate::report::{
    ApkInfo, AssetEntry, DebtEntry, DebtFile, DebtKind, DebtStatus, DebtSummary, DexEntry,
    EvidenceGroup, Fingerprint, Inventory, MethodRef, Report, SliceBytes, SoEntry,
};
use crate::track_a::entropy::EntropyCounter;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

const BUF: usize = 64 * 1024;

/// encrypted-payload 卡点的头部切片上限（机械常量；总大小在 facts 里如实标注）
const PAYLOAD_HEAD: usize = 64 * 1024;

/// 第一遍竖切：解包 + 清点 + 熵测量 + DEX 方法清点 + 符号定位切片 → (REPORT, debt, evidence 组)。
/// 指纹判定不在此处——fence 未配置指纹字段，一切样本按未知族主线输出（matched=false）。
/// 加密 DEX（magic 不符/表损坏）自动成为 encrypted-payload 卡点（机械事实，无熵阈值）：
/// 解密工作由此进入外包循环；方法事实仍不收（敌意输入常态不因成卡点而改变）。
pub fn first_pass(apk_path: &Path) -> Result<(Report, DebtFile, Vec<EvidenceGroup>), String> {
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
    // (so 名, 字节, 导出符号)——bytes 供 debt 阶段切片；MB 级 so 内存可承受
    let mut so_cache: Vec<(String, Vec<u8>, Vec<crate::track_a::elf::ExportedSymbol>)> = Vec::new();
    // 坏 DEX 字节（encrypted-payload 卡点切片来源；同样在内存可承受范围）
    let mut bad_dex: Vec<(String, Vec<u8>, bool, bool)> = Vec::new(); // (name, bytes, magic_ok, parse_ok)
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
            if !magic_ok || !parse_ok {
                bad_dex.push((name.clone(), bytes, magic_ok, parse_ok));
            }
            dex.push(DexEntry { name, size_bytes: size, magic_ok, parse_ok });
        } else if let Some(rest) = name.strip_prefix("lib/") {
            let (abi, has_file) = match rest.split_once('/') {
                Some((a, _)) => (a.to_string(), true),
                None => (String::new(), false),
            };
            if has_file {
                // 读 so 字节 → 导出符号表（符号定位与切片的事实来源；敌意 ELF 由解析器范围校验兜底）
                let mut bytes = Vec::new();
                let e: &mut dyn std::io::Read = entry.by_ref();
                e.read_to_end(&mut bytes).map_err(|x| format!("so read {name}: {x}"))?;
                let syms = crate::track_a::elf::exported_symbols(&bytes).unwrap_or_default();
                so_cache.push((name.clone(), bytes, syms));
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

    // ── 卡点生成（事实，无判断；debt_id 稳定排序保证产物字节确定性）──
    // 编号规则：method-native-stub 在前（类名/方法名/描述符序），encrypted-payload 在后（文件名序）
    let mut entries: Vec<DebtEntry> = Vec::new();
    let mut groups: Vec<EvidenceGroup> = Vec::new();
    let mut next_id = 1usize;

    // 1) method-native-stub
    {
        let mut sorted = native_methods.clone();
        sorted.sort_by(|a, b| (&a.class, &a.name, &a.descriptor).cmp(&(&b.class, &b.name, &b.descriptor)));
        for m in sorted.iter() {
            // descriptor "Lcom/example/Foo;" → FQCN "com.example.Foo"（机械变换）
            let fqcn = m
                .class
                .strip_prefix('L')
                .and_then(|s| s.strip_suffix(';'))
                .unwrap_or(&m.class)
                .replace('/', ".");
            let debt_id = format!("debt-{next_id:04}");
            next_id += 1;
            // 符号定位（JNI 规范机械推导 → 全 so 导出表查表）：命中为事实，未命中也是事实
            let mut facts = vec![
                "native stub — body outside DEX (access_flags ACC_NATIVE)".to_string(),
            ];
            let cands = crate::track_a::jni::candidates(&fqcn, &m.name, &m.descriptor);
            let mut hits: Vec<String> = Vec::new();
            let mut slices: Vec<SliceBytes> = Vec::new();
            for (so_name, so_bytes, syms) in &so_cache {
                for sym in syms {
                    if sym.name == cands[0] || sym.name == cands[1] {
                        hits.push(format!(
                            "symbol {} → {} (dynsym, st_value=0x{:x}, st_size={})",
                            sym.name, so_name, sym.st_value, sym.st_size
                        ));
                        // 切片：VA → 文件偏移 → 方法体字节（越界 = 敌意/异常，事实标注不切片）
                        match crate::track_a::elf::va_to_file_offset(so_bytes, sym.st_value) {
                            Ok(off) if (off as usize) + (sym.st_size as usize) <= so_bytes.len() => {
                                let bytes =
                                    so_bytes[off as usize..off as usize + sym.st_size as usize].to_vec();
                                slices.push(SliceBytes {
                                    name: format!("{}--{}", so_name.replace('/', "-"), sym.name.replace('/', "-")),
                                    source: so_name.clone(),
                                    symbol: Some(sym.name.clone()),
                                    st_value: Some(sym.st_value),
                                    st_size: Some(sym.st_size),
                                    file_offset: off,
                                    bytes,
                                });
                            }
                            Ok(_) => hits.push(format!(
                                "slice {} out of so bounds (st_value=0x{:x}, st_size={}) — not sliced",
                                sym.name, sym.st_value, sym.st_size
                            )),
                            Err(e) => hits.push(format!("slice mapping failed for {}: {e}", sym.name)),
                        }
                    }
                }
            }
            if hits.is_empty() {
                facts.push(format!(
                    "symbol candidates [{}, {}] not found in any so export table (checked {} so)",
                    cands[0], cands[1], so_cache.len()
                ));
            } else {
                facts.extend(hits);
            }
            let evidence: Vec<String> = if slices.is_empty() {
                Vec::new()
            } else {
                vec![format!("evidence/{debt_id}/")]
            };
            entries.push(DebtEntry {
                debt_id: debt_id.clone(),
                kind: DebtKind::MethodNativeStub,
                method: Some(MethodRef { class: fqcn, name: m.name.clone(), descriptor: m.descriptor.clone() }),
                status: DebtStatus::BlockedSolvable,
                facts,
                evidence,
                attempts: 0,
            });
            if !slices.is_empty() {
                groups.push(EvidenceGroup { debt_id, slices });
            }
        }
    }

    // 2) encrypted-payload（坏 DEX：声称是 DEX 但字节不是——机械事实，无熵阈值）
    {
        let mut sorted = bad_dex.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, bytes, magic_ok, _parse_ok) in &sorted {
            let debt_id = format!("debt-{next_id:04}");
            next_id += 1;
            let mut facts = vec![if !*magic_ok {
                format!("claimed-DEX file {name} with non-DEX magic (encrypted or renamed payload — mechanical fact)")
            } else {
                format!("claimed-DEX file {name} with valid magic but broken tables (parse failed — mechanical fact)")
            }];
            // 邻近 asset 的原始熵清单（数据非判断：分档阈值属 fence，未挣得即不存在）
            for a in &assets {
                facts.push(format!(
                    "asset {}: {} bytes, entropy {} bits/byte",
                    a.name, a.size_bytes, a.entropy
                ));
            }
            let mut slices: Vec<SliceBytes> = vec![SliceBytes {
                name: name.replace('/', "-"),
                source: name.clone(),
                symbol: None,
                st_value: None,
                st_size: None,
                file_offset: 0,
                bytes: bytes.iter().copied().take(PAYLOAD_HEAD).collect(),
            }];
            facts.push(format!(
                "sliced first {} bytes of {name} (total {} bytes)",
                slices[0].bytes.len(),
                bytes.len()
            ));
            // 解密例程候选（机械定位器：JNI_OnLoad 精确查表 + .init_array 段事实；无语义断言）
            for (so_name, so_bytes, syms) in &so_cache {
                for sym in syms {
                    if sym.name == "JNI_OnLoad" {
                        facts.push(format!(
                            "decrypt-routine candidate JNI_OnLoad → {} (dynsym, st_value=0x{:x}, st_size={}) — mechanical locator",
                            so_name, sym.st_value, sym.st_size
                        ));
                        match crate::track_a::elf::va_to_file_offset(so_bytes, sym.st_value) {
                            Ok(off) if (off as usize) + (sym.st_size as usize) <= so_bytes.len() => {
                                slices.push(SliceBytes {
                                    name: format!("{}--JNI_OnLoad", so_name.replace('/', "-")),
                                    source: so_name.clone(),
                                    symbol: Some(sym.name.clone()),
                                    st_value: Some(sym.st_value),
                                    st_size: Some(sym.st_size),
                                    file_offset: off,
                                    bytes: so_bytes[off as usize..off as usize + sym.st_size as usize].to_vec(),
                                });
                            }
                            _ => facts.push(format!("JNI_OnLoad in {so_name} not sliced (out of bounds)")),
                        }
                    }
                }
                if let Some(ia) = crate::track_a::elf::init_array(so_bytes).unwrap_or(None) {
                    facts.push(format!(
                        "init_array: {} entries at file_offset 0x{:x} in {} — decrypt-routine candidates, mechanical locator (function bodies have no symbol bounds, not sliced)",
                        ia.entry_count, ia.file_offset, so_name
                    ));
                }
            }
            entries.push(DebtEntry {
                debt_id: debt_id.clone(),
                kind: DebtKind::EncryptedPayload,
                method: None,
                status: DebtStatus::BlockedSolvable,
                facts,
                evidence: vec![format!("evidence/{debt_id}/")],
                attempts: 0,
            });
            groups.push(EvidenceGroup { debt_id, slices });
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
        groups,
    ))
}
