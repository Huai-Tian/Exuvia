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

/// so 内明文 DEX 机械扫描（修正案 #2）：`dex\n` + magic[7]==\0 命中即提取。
/// 提取按 DEX header 的 file_size，越界截到 so 尾（截断如实返回，由调用方进 facts）。
/// 返回 (so 内偏移, 声明 file_size, 提取字节)。
fn scan_embedded_dex(so_bytes: &[u8]) -> Vec<(u64, u32, Vec<u8>)> {
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + 0x24 <= so_bytes.len() {
        if &so_bytes[i..i + 4] == b"dex\n" && so_bytes.get(i + 7) == Some(&0) {
            let fsize = u32::from_le_bytes([
                so_bytes[i + 0x20],
                so_bytes[i + 0x21],
                so_bytes[i + 0x22],
                so_bytes[i + 0x23],
            ]);
            let end = ((i as u64) + (fsize as u64)).min(so_bytes.len() as u64) as usize;
            hits.push((i as u64, fsize, so_bytes[i..end].to_vec()));
            i = end.max(i + 1); // 跳过已提取段继续扫
        } else {
            i += 1;
        }
    }
    hits
}

/// asset 熵清单事实（数据非判断：分档阈值属 fence，未挣得即不存在）。
fn asset_entropy_facts(assets: &[AssetEntry]) -> Vec<String> {
    assets
        .iter()
        .map(|a| format!("asset {}: {} bytes, entropy {} bits/byte", a.name, a.size_bytes, a.entropy))
        .collect()
}

/// 单个 so 的解密例程候选（机械定位器：JNI_OnLoad 精确查表 + .init_array 段事实）。
/// 返回 (facts, JNI_OnLoad 方法体切片——有边界才切，越界如实记 facts)。
fn onload_candidates(
    so_name: &str,
    so_bytes: &[u8],
    syms: &[crate::track_a::elf::ExportedSymbol],
) -> (Vec<String>, Vec<SliceBytes>) {
    let mut facts = Vec::new();
    let mut slices = Vec::new();
    // 导出符号清单（修正案 #3：壳 so 的真名——LLVM 混淆常剥不干净；机械列出，价值判断在下游）
    if !syms.is_empty() {
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        facts.push(format!(
            "{so_name} exports {} defined dynsym symbols: {}",
            syms.len(),
            names.join(", ")
        ));
    }
    for sym in syms {
        if sym.name == "JNI_OnLoad" {
            facts.push(format!(
                "decrypt-routine candidate JNI_OnLoad → {so_name} (dynsym, st_value=0x{:x}, st_size={}) — mechanical locator",
                sym.st_value, sym.st_size
            ));
            match crate::track_a::elf::va_to_file_offset(so_bytes, sym.st_value) {
                Ok(off) if (off as usize) + (sym.st_size as usize) <= so_bytes.len() => {
                    slices.push(SliceBytes {
                        name: format!("{}--JNI_OnLoad", so_name.replace('/', "-")),
                        source: so_name.to_string(),
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
            "init_array: {} entries at file_offset 0x{:x} in {so_name} — decrypt-routine candidates, mechanical locator (function bodies have no symbol bounds, not sliced)",
            ia.entry_count, ia.file_offset
        ));
    }
    (facts, slices)
}

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
    // parse 失败原因一并保留——事实不吞错，外部 LLM 诊断需要
    let mut bad_dex: Vec<(String, Vec<u8>, bool, Option<String>)> = Vec::new(); // (name, bytes, magic_ok, parse_err)
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
            let mut parse_err: Option<String> = None;
            if magic_ok {
                // 表结构损坏 = 敌意输入常态：事实标注（含失败原因），不让单个 dex 失败拖垮整次剖析
                match crate::track_a::dex::parse(&bytes) {
                    Ok(methods) => {
                        native_methods.extend(methods.into_iter().filter(|m| m.is_native));
                        parse_ok = true;
                    }
                    Err(e) => parse_err = Some(e),
                }
            }
            if !magic_ok || !parse_ok {
                bad_dex.push((name.clone(), bytes, magic_ok, parse_err.clone()));
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
            // 读全字节（熵计数 + ELF magic 检测双用；与 classes.dex 同等内存纪律）
            let mut bytes = Vec::new();
            let e: &mut dyn std::io::Read = entry.by_ref();
            e.read_to_end(&mut bytes).map_err(|x| format!("asset read {name}: {x}"))?;
            let mut ent = EntropyCounter::new();
            ent.update(&bytes);
            assets.push(AssetEntry {
                name: name.clone(),
                size_bytes: size,
                entropy: ent.bits_per_byte(),
            });
            // 修正案 #1：assets 下的 ELF（壳引擎藏匿形态——magic 纯格式事实）
            // 纳入 so 清点与符号查表；ABI 由 e_machine 映射（assets 无 ABI 目录）
            if bytes.starts_with(b"\x7fELF") {
                let syms = crate::track_a::elf::exported_symbols(&bytes).unwrap_or_default();
                let abi = crate::track_a::elf::machine_abi(&bytes).unwrap_or_default();
                so_cache.push((name.clone(), bytes, syms));
                so.push(SoEntry { name, abi, size_bytes: size });
            }
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

    // 2) encrypted-payload（来源三型，全机械事实：坏 DEX 文件 / so 内明文 DEX / assets ELF 零命中）
    {
        // 2a) 预扫全部 so 的明文 DEX（修正案 #2；与 so_cache 同序）
        let so_hits: Vec<Vec<(u64, u32, Vec<u8>)>> =
            so_cache.iter().map(|(_, b, _)| scan_embedded_dex(b)).collect();

        // 卡点候选：(排序键, 首条事实, 头切片+total, 额外切片, 自身 so)——统一排序后编号（产物字节确定性）
        let mut cands: Vec<(String, String, Option<(SliceBytes, u64)>, Vec<SliceBytes>, Option<String>)> = Vec::new();

        // 2b) 坏 DEX 文件（声称是 DEX 但字节不是 / 表损坏）——头切片 + 全部 so 的解密例程候选
        for (name, bytes, magic_ok, parse_err) in &bad_dex {
            let headline = if !*magic_ok {
                format!("claimed-DEX file {name} with non-DEX magic (encrypted or renamed payload — mechanical fact)")
            } else {
                format!(
                    "claimed-DEX file {name} with valid magic but broken tables (parse failed{} — mechanical fact)",
                    parse_err.as_deref().map(|e| format!(": {e}")).unwrap_or_default()
                )
            };
            let head = SliceBytes {
                name: name.replace('/', "-"),
                source: name.clone(),
                symbol: None,
                st_value: None,
                st_size: None,
                file_offset: 0,
                bytes: bytes.iter().copied().take(PAYLOAD_HEAD).collect(),
            };
            cands.push((name.clone(), headline, Some((head, bytes.len() as u64)), Vec::new(), None));
        }

        // 2c) so 内明文 DEX 命中（修正案 #2 正事实：机械扫描命中即提取，卡点即成果）
        for (i, (so_name, so_bytes, _)) in so_cache.iter().enumerate() {
            for (k, (off, fsize, dex_bytes)) in so_hits[i].iter().enumerate() {
                let headline = format!(
                    "plaintext DEX found in {so_name} at offset 0x{off:x} (declared file_size {fsize}, sliced {} bytes) — mechanical scan hit",
                    dex_bytes.len()
                );
                let slice = SliceBytes {
                    name: format!("{}--embedded-{k}", so_name.replace('/', "-")),
                    source: so_name.clone(),
                    symbol: None,
                    st_value: None,
                    st_size: None,
                    file_offset: *off,
                    bytes: dex_bytes.clone(),
                };
                cands.push((format!("{so_name}-{k}"), headline, None, vec![slice], Some(so_name.clone())));
            }
        }

        // 2d) assets ELF 零命中（壳引擎藏匿形态的负事实——"若藏有 payload 则已加密"由缺席机械暗示）
        for (i, (so_name, _, _)) in so_cache.iter().enumerate() {
            if so_name.starts_with("assets/") && so_hits[i].is_empty() {
                let headline = format!(
                    "assets ELF {so_name}: no plaintext DEX magic found in ELF scan (payload, if any, is encrypted/compressed — mechanical fact from absence)"
                );
                cands.push((so_name.clone(), headline, None, Vec::new(), Some(so_name.clone())));
            }
        }

        // 统一排序 + 编号 + facts 附加
        cands.sort_by(|a, b| a.0.cmp(&b.0));
        for (_key, headline, head, extra_slices, self_so) in cands {
            let debt_id = format!("debt-{next_id:04}");
            next_id += 1;
            let mut facts = vec![headline];
            facts.extend(asset_entropy_facts(&assets));
            if let Some((s, total)) = &head {
                facts.push(format!("sliced first {} bytes of {} (total {total} bytes)", s.bytes.len(), s.source));
            }
            let mut slices = Vec::new();
            if let Some((s, _)) = head {
                slices.push(s);
            }
            // 解密例程候选：坏 DEX 来源挂全部 so；so 命中/零命中卡点只挂自身 so（对象即该 so）
            match self_so.as_deref().and_then(|src| so_cache.iter().find(|(n, _, _)| n == src)) {
                Some((n, b, s)) => {
                    let (f, sl) = onload_candidates(n, b, s);
                    facts.extend(f);
                    slices.extend(sl);
                }
                None => {
                    for (n, b, s) in &so_cache {
                        let (f, sl) = onload_candidates(n, b, s);
                        facts.extend(f);
                        slices.extend(sl);
                    }
                }
            }
            slices.extend(extra_slices);
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
