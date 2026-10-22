//! 修复管线编排：doctor → clean → deweave → [repack] → [restore] → surgery
//!                     → zipalign → sign v2。
//!
//! 这是 repair_all.py 的 Rust 编排层——Python 工具链做重活，Rust 负责生命周期
//! 和 CLI 接口。每步的输出行被结构化收集到 RepairResult 中。

use std::path::{Path, PathBuf};
use super::embed;

/// 相对路径 → 绝对路径（Python 脚本在临时目录运行，需要绝对路径找到用户文件）。
fn abs(p: &Path) -> String {
    if p.is_absolute() {
        p.to_string_lossy().to_string()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(p)
            .to_string_lossy()
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct RepairArgs {
    /// 加固后的（壳）APK
    pub packed_apk: PathBuf,
    /// dump 出的 DEX 文件（可多个：与 repair_all.py 位置参数 nargs='+' 同义，
    /// 依次分诊后重打包为 classes.dex, classes2.dex…）
    pub dumped_dexes: Vec<PathBuf>,
    /// 输出 APK 路径
    pub out_apk: PathBuf,
    /// 参照 DEX（原包，仅内部测试用，可选）
    pub reference_dex: Option<PathBuf>,
    /// 额外 dump 来源（第三方 dump / 脱壳阶段产物，互补还原被抽取方法）
    pub extra_dumps: Vec<PathBuf>,
    /// 直挂成品 dex（原样追加为 classes2..N，不重序列化，可多个、保序）。
    /// 与 repair_all.py 的 --extra-dex 同义：脱壳阶段闸门产物等不可再序列化的
    /// 成品 dex 走这里——--dump 只作 restore 来源、永不进成品包，两条通道不可互换。
    pub extra_dex: Vec<PathBuf>,
    /// 源头通道：自动收集 ./handoff/workspace/*/recovered.dex（存在即已过四层
    /// 闸门）。无显式位置参数时最大者提升为主 dex，其余按 debt_id 序直挂。
    pub from_handoff: bool,
    /// 逃生门：检出空壳 native 桩仍原样发货（外科后首个生命周期调用必崩——
    /// 只用于分诊调试，生产路径永远让自动填体跑完）。
    pub allow_hollow: bool,
    /// 签名密钥 PEM（可选，默认生成测试密钥）
    pub key_pem: Option<PathBuf>,
    /// 证书 DER（可选）
    pub cert_der: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct RepairResult {
    /// doctor 阶段的修复列表
    pub doctor_fixes: Vec<String>,
    /// deweave 阶段恢复的织入数
    pub deweave_restored: usize,
    /// restore 阶段从 dump/reference 来源搬运的方法体数
    pub restore_count: usize,
    /// stubsafe 阶段合成的契约等价方法体数（无来源兜底）
    pub stubsafe_count: usize,
    /// 手术移除的 wrapper Application 类名
    pub surgery_removed: Option<String>,
    /// 移除的壳资产条目数
    pub shell_assets_removed: usize,
    /// 空壳填体记录（每条 "dex 路径: N 个 native 已填"——族 2 自动合成）
    pub hollow_filled: Vec<String>,
    /// 4 字节对齐的条目数
    pub entries_aligned: usize,
    /// 签名后的 APK 大小
    pub final_size: usize,
    /// 每步的日志输出
    pub logs: Vec<String>,
    /// 成功/失败
    pub success: bool,
    pub error: Option<String>,
}

/// 组装 repair_all.py 的完整参数表（独立函数：通道语义可被单测钉死）。
/// 三条 dex 通道各司其职，不可互换：
///   - 位置参数（doctor 产物，可多个）—— 分诊后重打包为 classes.dex, classes2…
///   - --dump（restore 来源，可多个）—— 只读、永不进成品
///   - --extra-dex（直挂，可多个）   —— 原样追加为 classesN+1..，不重序列化
fn repair_all_args(args: &RepairArgs, positionals: &[PathBuf], extras: &[PathBuf]) -> Vec<String> {
    let mut cmd_args: Vec<String> = vec![abs(&args.packed_apk)];
    for p in positionals {
        cmd_args.push(abs(p));
    }
    cmd_args.push("-o".to_string());
    cmd_args.push(abs(&args.out_apk));

    if let Some(ref reference) = args.reference_dex {
        cmd_args.push("--reference".to_string());
        cmd_args.push(abs(reference));
    }
    for dump in &args.extra_dumps {
        cmd_args.push("--dump".to_string());
        cmd_args.push(abs(dump));
    }
    for dex in extras {
        cmd_args.push("--extra-dex".to_string());
        cmd_args.push(abs(dex));
    }
    cmd_args
}

/// handoff 闸门产物收集：workspace/<debt_id>/recovered.dex（存在即已过四层
/// 闸门——语法/格式 → 对账 → 语义双锚 → 销账，gate.rs 落盘约定）。
/// 返回按 debt_id 字典序（确定性）。
fn collect_handoff_products(handoff_dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = match std::fs::read_dir(handoff_dir.join("workspace")) {
        Ok(rd) => rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect(),
        Err(_) => return Vec::new(),
    };
    dirs.sort();
    dirs.into_iter()
        .map(|d| d.join("recovered.dex"))
        .filter(|f| f.is_file())
        .collect()
}

fn file_sha256(p: &Path) -> Option<String> {
    use sha2::Digest as _;
    let data = std::fs::read(p).ok()?;
    Some(sha2::Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect())
}

/// 源头解析：显式位置参数 ∪ --from-handoff 收集 → (位置参数集, 直挂集)。
/// 规则：
/// - 收集集先对显式通道（位置参数 + 直挂）做 sha256 去重——同一闸门产物
///   显式给了又被收集到，不重复挂包；
/// - 有显式位置参数：收集集全部直挂（跟在显式 --extra-dex 之后）；
/// - 无显式位置参数：收集集中最大者提升为主 dex（受分诊），其余按
///   debt_id 序直挂——主 dex 承载应用体量、享受分诊（两战验证的行为），
///   卫星 dex 原样进包（闸门已验证字节，不再重序列化）；
/// - 位置参数集为空 = 结构化错误（repair_all 至少需要一个主 dex）。
fn resolve_ship_inputs(args: &RepairArgs) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    resolve_ship_inputs_at(args, Path::new("handoff"))
}

fn resolve_ship_inputs_at(args: &RepairArgs, handoff_dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let mut positionals = args.dumped_dexes.clone();
    let mut extras = args.extra_dex.clone();
    if args.from_handoff {
        let collected = collect_handoff_products(handoff_dir);
        if collected.is_empty() {
            return Err(format!("--from-handoff: {}/workspace/*/recovered.dex 无产物 —— 先跑脱壳循环（first_pass → goal → merge）", handoff_dir.display()));
        }
        let have: std::collections::HashSet<String> = positionals.iter()
            .chain(extras.iter())
            .filter_map(|p| file_sha256(p))
            .collect();
        let mut fresh: Vec<PathBuf> = collected.into_iter()
            .filter(|p| file_sha256(p).map(|h| !have.contains(&h)).unwrap_or(true))
            .collect();
        if positionals.is_empty() && !fresh.is_empty() {
            // 最大者提升为主 dex
            let main_idx = fresh.iter().enumerate()
                .max_by_key(|(_, p)| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
                .map(|(i, _)| i)
                .unwrap_or(0);
            positionals.push(fresh.remove(main_idx));
        }
        extras.extend(fresh);
    }
    if positionals.is_empty() {
        return Err("no input dex: 位置参数 <DUMPED_DEX> 或 --from-handoff 至少其一".into());
    }
    Ok((positionals, extras))
}

/// 提取「marker: <数字>」里的计数——marker 后跳空白、连续取数字。
/// 比 split(':') 健壮：输出行可能在数字后续接别的键值段
/// （repair_all.py 的 "shell assets removed: 4; shipped dexes: …" 同行多段格式）。
fn counter_after(l: &str, marker: &str) -> Option<usize> {
    let pos = l.find(marker)? + marker.len();
    let digits: String = l[pos..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<usize>().ok()
}

/// 框架模板方法名（tools/dexlib/StubSafe.java 的 LIFECYCLE 表逐字镜像——
/// 空壳触发集与契约兜底的判定集必须同源，两处漂移 = 口径分裂）。
/// native + 生命周期名 = 壳抽取铁证：模板方法契约要求 super 链，合法的
/// native 生命周期覆写不可能存在。
const LIFECYCLE: &[&str] = &[
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onRestart",
    "onDestroy", "onDestroyView", "onDetach", "onAttach", "onViewCreated",
    "onSaveInstanceState", "onRestoreInstanceState", "onNewIntent",
    "onBackPressed", "onActivityResult", "onRequestPermissionsResult",
    "onConfigurationChanged", "onLowMemory", "onTrimMemory",
    "onWindowFocusChanged", "onAttachedToWindow", "onDetachedFromWindow",
    "onCreateOptionsMenu", "onPrepareOptionsMenu", "onOptionsItemSelected",
    "onContextItemSelected", "onCreateContextMenu", "onCreatePanelView",
    "onCreatePanelMenu", "onPreparePanel", "onMenuOpened", "onPanelClosed",
    "onContextMenuClosed", "onMultiWindowModeChanged",
    "onPictureInPictureModeChanged", "onTopResumedActivityChanged",
    "attachBaseContext", "onStartCommand", "onBind", "onUnbind", "onRebind",
];

/// 单个发货 dex 的空壳诊断。
#[derive(Debug)]
struct HollowHit {
    path: PathBuf,
    /// 该 dex 全部 native 方法（填充集——翻译族整类翻译，只补生命周期名会
    /// 留下次崩点）；报告形态 "Lcls;->name(desc)"
    suspects: Vec<String>,
    /// 其中命中 LIFECYCLE 的子集（触发依据）
    lifecycle: Vec<String>,
}

/// 空壳检测（SKILL §7 完整性前提的机器执行）：发货通道每个 dex 过
/// dex::parse，native 方法名命中 LIFECYCLE 即触发。解析失败的 dex 不拦——
/// 病理分诊是 doctor 的职责面，这里只做触发判断。
fn detect_hollow(dex_paths: &[PathBuf]) -> Vec<HollowHit> {
    let mut hits = Vec::new();
    for p in dex_paths {
        let data = match std::fs::read(p) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let methods = match crate::track_a::dex::parse(&data) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let suspects: Vec<String> = methods
            .iter()
            .filter(|m| m.is_native)
            .map(|m| format!("{}->{}{}", m.class, m.name, m.descriptor))
            .collect();
        let lifecycle: Vec<String> = methods
            .iter()
            .filter(|m| m.is_native && LIFECYCLE.contains(&m.name.as_str()))
            .map(|m| format!("{}->{}{}", m.class, m.name, m.descriptor))
            .collect();
        if !lifecycle.is_empty() {
            hits.push(HollowHit { path: p.clone(), suspects, lifecycle });
        }
    }
    hits
}

/// 壳 .so 挑选（族 2 翻译体载体）：packed apk 内 assets/ 下、ELF64、
/// e_machine==183（AArch64——模拟执行臂是 aarch64）的 .so 取最大者。
/// lib/ 下的是 App 合法 JNI 库（repair.py 外科只剥 assets/），永不入选。
fn pick_shell_so(packed_apk: &Path, extract_dir: &Path) -> Result<Option<(String, PathBuf)>, String> {
    use std::io::Read as _;
    let f = std::fs::File::open(packed_apk)
        .map_err(|e| format!("open packed apk {}: {e}", packed_apk.display()))?;
    let mut zip = zip::ZipArchive::new(f)
        .map_err(|e| format!("packed apk zip: {e}"))?;
    let mut best: Option<(String, u64)> = None;
    for i in 0..zip.len() {
        let mut e = zip.by_index(i).map_err(|e2| format!("zip entry #{i}: {e2}"))?;
        let name = match e.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        if !(name.starts_with("assets/") && name.ends_with(".so")) {
            continue;
        }
        // ELF64 + AArch64：头 20B 足够判（magic / e_ident[EI_CLASS]=2 /
        // e_machine @18 LE == 183）
        let mut head = [0u8; 20];
        if e.read_exact(&mut head).is_err() {
            continue;
        }
        if &head[0..4] != b"\x7fELF" || head[4] != 2 {
            continue;
        }
        if u16::from_le_bytes([head[18], head[19]]) != 183 {
            continue;
        }
        let size = e.size();
        if best.as_ref().map(|(_, s)| size > *s).unwrap_or(true) {
            best = Some((name, size));
        }
    }
    let (name, _size) = match best {
        Some(b) => b,
        None => return Ok(None),
    };
    let mut e = zip.by_name(&name).map_err(|e2| format!("zip entry {name}: {e2}"))?;
    let mut buf = Vec::with_capacity(e.size() as usize);
    e.read_to_end(&mut buf).map_err(|e2| format!("read {name}: {e2}"))?;
    std::fs::create_dir_all(extract_dir).map_err(|e2| format!("mkdir: {e2}"))?;
    let out = extract_dir.join("hollowfill-shell.so");
    std::fs::write(&out, &buf).map_err(|e2| format!("write {}: {e2}", out.display()))?;
    Ok(Some((name, out)))
}

/// 单 dex 空壳填体（hollowfill.py 四步编排：静态表定位 → jnitrace →
/// trace2smali → baksmali 拼接 smali 重组）。依赖缺席 / 定位失败 =
/// 结构化错误 + 嫌疑方法清单——绝不静默带壳发货（tosks 真机闪退教训的
/// 机器执行）。seeds = 同包其余发货 dex（jnitrace --seed-dex 的 clinit
/// 静态域播种来源）。
fn fill_hollow(
    tools: &Path,
    hit: &HollowHit,
    so: &Path,
    out: &Path,
    seeds: &[PathBuf],
) -> Result<usize, String> {
    let mut argv: Vec<String> = vec![
        abs(&hit.path),
        "--so".to_string(),
        abs(so),
        "--out".to_string(),
        abs(out),
    ];
    for s in seeds {
        argv.push("--seed-dex".to_string());
        argv.push(abs(s));
    }
    let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let (stdout, _stderr) = embed::run_py(tools, "hollowfill.py", &refs).map_err(|e| {
        format!(
            "hollowfill {}: {e}\nhollow suspects ({}): {}",
            hit.path.display(),
            hit.suspects.len(),
            hit.suspects.join(", ")
        )
    })?;
    // 成功 = stdout 末行 JSON 报告；回读完整性（remaining_hollow）也在其中
    let line = stdout.lines().last().unwrap_or("").trim().to_string();
    let v: serde_json::Value = serde_json::from_str(&line)
        .map_err(|e| format!("hollowfill report parse: {e} (stdout tail: {line})"))?;
    if let Some(rem) = v.get("remaining_hollow") {
        if !rem.is_null() {
            return Err(format!(
                "hollowfill {}: 填后仍有 native 残留 {rem}",
                hit.path.display()
            ));
        }
    }
    let filled = v
        .get("classes")
        .and_then(|c| c.as_object())
        .map(|o| o.values().filter_map(|n| n.as_u64()).sum::<u64>() as usize)
        .unwrap_or(0);
    Ok(filled)
}

/// 执行完整修复管线。
pub fn run_repair(args: &RepairArgs) -> RepairResult {
    let mut result = RepairResult::default();
    let mut logs = Vec::new();

    // 0. 提取 Python 工具链
    let tools = match embed::extract_tools() {
        Ok(t) => t,
        Err(e) => {
            result.error = Some(format!("extract tools: {}", e));
            return result;
        }
    };
    logs.push("[tools] python toolchain extracted".to_string());

    // 0.5 源头解析：显式位置参数 ∪ --from-handoff 闸门产物 → (位置集, 直挂集)
    let (positionals, mut extras) = match resolve_ship_inputs(args) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(e);
            result.logs = logs;
            return result;
        }
    };
    for p in &positionals {
        logs.push(format!("[input] positional: {}", p.display()));
    }
    for p in &extras {
        logs.push(format!("[input] extra-dex (ship as-is): {}", p.display()));
    }

    // 1. 修复每个位置参数 DEX 的校验和和病理（dexdoctor.py --fix，逐文件）
    let mut dex_fixed_paths: Vec<PathBuf> = Vec::with_capacity(positionals.len());
    for dex in &positionals {
        let dex_fixed_path = dex.with_extension("doctor.dex");
        let (out, err) = match embed::run_py(
            &tools,
            "dexdoctor.py",
            &[
                &abs(dex),
                "--fix",
                "-o",
                &abs(&dex_fixed_path),
            ],
        ) {
            Ok(v) => v,
            Err(e) => {
                result.error = Some(format!("dexdoctor: {}", e));
                result.logs = logs;
                return result;
            }
        };
        for line in out.lines() {
            if line.contains("FIXED") {
                result.doctor_fixes.push(line.trim().to_string());
            }
            logs.push(format!("[doctor] {}", line));
        }
        if !err.is_empty() {
            logs.push(format!("[doctor:stderr] {}", err.trim()));
        }
        dex_fixed_paths.push(dex_fixed_path);
    }

    // 1.5 空壳检测 + 自动填体（SKILL §7 完整性前提的机器执行：族 2 翻译族
    // 的 native 空心桩在填体前不可发货——外科剥壳后 ART 首个生命周期调用
    // 即 UnsatisfiedLinkError。触发 = native 方法名命中 LIFECYCLE；
    // 填充集 = 该 dex 全部 native 方法）
    let ship_all: Vec<PathBuf> = dex_fixed_paths
        .iter()
        .chain(extras.iter())
        .cloned()
        .collect();
    let hits = detect_hollow(&ship_all);
    if !hits.is_empty() {
        if args.allow_hollow {
            for h in &hits {
                logs.push(format!(
                    "[hollow] allow-hollow: {} 带 {} 个 native 桩原样发货（触发: {}）",
                    h.path.display(),
                    h.suspects.len(),
                    h.lifecycle.join(", ")
                ));
            }
        } else {
            let work = tools.join("hollowfill-work");
            let (so_name, so_path) = match pick_shell_so(&args.packed_apk, &work) {
                Ok(Some(v)) => v,
                Ok(None) => {
                    result.error = Some(format!(
                        "hollow native stubs detected but no shell .so (assets/*.so, ELF64 aarch64) in packed apk; suspects: {}",
                        hits.iter()
                            .flat_map(|h| h.suspects.iter().cloned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    result.logs = logs;
                    return result;
                }
                Err(e) => {
                    result.error = Some(e);
                    result.logs = logs;
                    return result;
                }
            };
            logs.push(format!("[hollow] shell so: {so_name}"));
            for (i, h) in hits.iter().enumerate() {
                let out = work.join(format!("filled_{i}.dex"));
                let seeds: Vec<PathBuf> = ship_all
                    .iter()
                    .filter(|p| **p != h.path)
                    .cloned()
                    .collect();
                match fill_hollow(&tools, h, &so_path, &out, &seeds) {
                    Ok(n) => {
                        logs.push(format!(
                            "[hollow] {}: {n} 个 native 已填体",
                            h.path.display()
                        ));
                        result
                            .hollow_filled
                            .push(format!("{}: {n} 个 native 已填体", h.path.display()));
                        // 通道内原位替换（位置参数通道 / 直挂通道各归各位，
                        // 序号与保序承诺不变）
                        for slot in dex_fixed_paths.iter_mut().chain(extras.iter_mut()) {
                            if *slot == h.path {
                                *slot = out.clone();
                            }
                        }
                    }
                    Err(e) => {
                        result.error = Some(e);
                        result.logs = logs;
                        return result;
                    }
                }
            }
        }
    }

    // 2. 织入恢复 + 修复管线（repair_all.py 一条命令）
    // repair_all.py 内部做: doctor → clean → deweave → [repack] → [restore]
    //                        → surgery → zipalign → sign
    // 我们只需要调用它并传递正确的参数
    let cmd_args = repair_all_args(args, &dex_fixed_paths, &extras);

    let arg_refs: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
    let (out, err) = match embed::run_py(&tools, "repair_all.py", &arg_refs) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(format!("repair_all: {}", e));
            result.logs = logs;
            return result;
        }
    };

    // 解析 repair_all.py 的输出行
    for line in out.lines() {
        let l = line.trim();
        if l.contains("woven sites restored") {
            if let Some(n) = l.split(':').nth(1).and_then(|s| s.split('(').next())
                .and_then(|s| s.trim().parse::<usize>().ok()) {
                result.deweave_restored = n;
            }
        } else if l.contains("methods merged") {
            // "…restore: N methods merged from reference" — N sits right
            // before "methods" (the [restore:dump] prefix adds colons, so
            // splitting on ':' is unreliable)
            if let Some(pos) = l.find(" methods merged") {
                let digits: String = l[..pos]
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                if let Ok(n) = digits.parse::<usize>() {
                    result.restore_count = n;
                }
            }
        } else if l.contains("method(s) synthesized") {
            // "stubsafe: N method(s) synthesized, M native kept"
            if let Some(pos) = l.find(" method(s) synthesized") {
                let digits: String = l[..pos]
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                if let Ok(n) = digits.parse::<usize>() {
                    result.stubsafe_count = n;
                }
            }
        } else if l.contains("removed android:name") {
            result.surgery_removed = Some(
                l.split('"').nth(1).unwrap_or_default().to_string(),
            );
        } else if l.contains("shell assets removed") {
            // "shell assets removed: 4; shipped dexes: … (all entries…)" ——
            // 数字后同行还有别的段，split(':') 取段会带出分号残渣
            if let Some(n) = counter_after(l, "shell assets removed:") {
                result.shell_assets_removed = n;
            }
        } else if l.contains("4-byte aligned") {
            // zipalign 输出
        } else if l.contains("v2 signed") {
            // 签名输出
        }
        logs.push(format!("{}", l));
    }
    if !err.is_empty() {
        logs.push(format!("[stderr] {}", err.trim()));
    }

    // 3. 清理中间文件（doctor 产物按源头路径推导——填体替换后
    // dex_fixed_paths 已指向填体产物，不能拿它当清理清单；填体产物留在
    // 工具链临时目录，随系统临时区回收）
    for p in &positionals {
        let _ = std::fs::remove_file(p.with_extension("doctor.dex"));
    }

    // 4. 验证输出
    if args.out_apk.exists() {
        result.final_size = std::fs::metadata(&args.out_apk)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        result.success = result.final_size > 0;
    } else {
        result.error = Some("output APK not created".into());
    }

    result.logs = logs;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> RepairArgs {
        RepairArgs {
            packed_apk: PathBuf::from("/tmp/test.apk"),
            dumped_dexes: vec![PathBuf::from("/tmp/test.dex")],
            out_apk: PathBuf::from("/tmp/out.apk"),
            reference_dex: None,
            extra_dumps: vec![],
            extra_dex: vec![],
            from_handoff: false,
            allow_hollow: false,
            key_pem: None,
            cert_der: None,
        }
    }

    #[test]
    fn test_repair_args_default() {
        let args = base_args();
        assert_eq!(args.packed_apk, Path::new("/tmp/test.apk"));
        assert!(args.reference_dex.is_none());
        assert!(args.extra_dumps.is_empty());
        assert!(args.extra_dex.is_empty());
        assert!(!args.from_handoff);
    }

    #[test]
    fn test_repair_all_args_ship_channels() {
        // 通道语义回归（tosks 教训）：--dump 只作 restore 来源、不进成品；
        // 唯一携带 MainActivity 的子 dex 若被塞进 --dump，重打包出的 APK 会
        // 静默丢失整个 classes2.dex。直挂成品必须走 --extra-dex。
        let args = RepairArgs {
            extra_dumps: vec![PathBuf::from("/x/src_only.dex")],
            ..base_args()
        };
        let extras = vec![PathBuf::from("/x/sub1.dex"), PathBuf::from("/x/sub2.dex")];
        let cmd = repair_all_args(&args, &[PathBuf::from("/x/main.doctor.dex")], &extras);
        // --dump / --extra-dex 各自恰好出现一次调用、值正确且保序
        let dump_pos: Vec<usize> = cmd.iter().enumerate()
            .filter(|(_, a)| *a == "--dump").map(|(i, _)| i).collect();
        let extra_pos: Vec<usize> = cmd.iter().enumerate()
            .filter(|(_, a)| *a == "--extra-dex").map(|(i, _)| i).collect();
        assert_eq!(dump_pos.len(), 1);
        assert_eq!(extra_pos.len(), 2);
        assert_eq!(cmd[dump_pos[0] + 1], "/x/src_only.dex");
        assert_eq!(cmd[extra_pos[0] + 1], "/x/sub1.dex");
        assert_eq!(cmd[extra_pos[1] + 1], "/x/sub2.dex");
        assert!(extra_pos[0] < extra_pos[1]);
        // 位置参数仍是「壳 APK + doctor 产物」两件，直挂 dex 绝不混入位置参数
        assert_eq!(&cmd[..4], ["/tmp/test.apk", "/x/main.doctor.dex", "-o", "/tmp/out.apk"]);
    }

    #[test]
    fn test_counter_after_marker_tolerates_trailing_segments() {
        // repair_all.py 现行格式：数字后同行接 "; shipped dexes: … (…)"。
        // 旧实现 split(':') 取第二段得到 "4; shipped dexes"，parse 失败静默归零——
        // 日志写 4、JSON 报 0（tosks 回归实测抓到的不一致）。
        let l = "[repair] shell assets removed: 4; shipped dexes: classes.dex, classes2.dex (all entries 4-byte aligned)";
        assert_eq!(counter_after(l, "shell assets removed:"), Some(4));
        // 旧格式兼容："5" / "5 (all entries…)"
        assert_eq!(counter_after("[repair] shell assets removed: 5", "shell assets removed:"), Some(5));
        assert_eq!(counter_after("[repair] shell assets removed: 7 (all entries 4-byte aligned)", "shell assets removed:"), Some(7));
        // 无 marker / 无数字 → None，不误判
        assert_eq!(counter_after("[repair] nothing here", "shell assets removed:"), None);
        assert_eq!(counter_after("[repair] shell assets removed: none", "shell assets removed:"), None);
    }

    /// 唯一临时目录（无 tempfile 依赖的测试纪律：std-only + 进程号 + 计数器）。
    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "exuvia-pipeline-test-{}-{}-{}", std::process::id(), tag,
            N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn test_resolve_from_handoff_promotes_largest_and_ships_rest() {
        // handoff 收集语义：workspace/*/recovered.dex 按 debt_id 序收集；
        // 无显式位置参数时最大者提升为主 dex，其余保序直挂。
        let dir = scratch("handoff");
        let ws = dir.join("handoff").join("workspace");
        std::fs::create_dir_all(ws.join("debt-0003")).unwrap();
        std::fs::create_dir_all(ws.join("debt-0007")).unwrap();
        std::fs::write(ws.join("debt-0003").join("recovered.dex"), b"small-sub-dex").unwrap();
        std::fs::write(ws.join("debt-0007").join("recovered.dex"), vec![0u8; 4096]).unwrap();

        let args = RepairArgs { dumped_dexes: vec![], from_handoff: true, ..base_args() };
        let (pos, ext) = resolve_ship_inputs_at(&args, &dir.join("handoff")).unwrap();

        assert_eq!(pos.len(), 1);
        assert!(pos[0].ends_with("debt-0007/recovered.dex"));  // 大者为主
        assert_eq!(ext.len(), 1);
        assert!(ext[0].ends_with("debt-0003/recovered.dex"));  // 小者直挂
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_from_handoff_dedups_explicit_channels() {
        // 同一闸门产物显式 --extra-dex 给了、又被 --from-handoff 收集到 → 不重复挂
        let dir = scratch("dedup");
        let ws = dir.join("handoff").join("workspace").join("debt-0001");
        std::fs::create_dir_all(&ws).unwrap();
        let product = ws.join("recovered.dex");
        std::fs::write(&product, b"same-bytes").unwrap();

        let args = RepairArgs {
            extra_dex: vec![product.clone()],
            from_handoff: true,
            ..base_args()
        };
        let (pos, ext) = resolve_ship_inputs_at(&args, &dir.join("handoff")).unwrap();

        assert_eq!(pos, vec![PathBuf::from("/tmp/test.dex")]);
        assert_eq!(ext, vec![product]);  // 仅显式那一份
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_empty_inputs_is_structured_error() {
        let dir = scratch("empty");
        let args = RepairArgs { dumped_dexes: vec![], from_handoff: true, ..base_args() };
        let err = resolve_ship_inputs_at(&args, &dir.join("handoff")).unwrap_err();
        assert!(err.contains("--from-handoff"), "got: {err}");

        let args2 = RepairArgs { dumped_dexes: vec![], ..base_args() };
        let err2 = resolve_ship_inputs_at(&args2, &dir.join("handoff")).unwrap_err();
        assert!(err2.contains("no input dex"), "got: {err2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_hollow_trigger_precision() {
        // 触发 = native ∩ LIFECYCLE；填充集 = 该 dex 全部 native。
        // fixture（dex.rs::hollow_dex_fixture）：native onCreate（触发）+
        // native static zap（非生命周期名——进嫌疑清单但不作触发依据）。
        let dir = scratch("hollow");
        let dex = dir.join("sub.dex");
        std::fs::write(&dex, crate::track_a::dex::hollow_dex_fixture()).unwrap();
        let garbage = dir.join("garbage.dex");
        std::fs::write(&garbage, b"not a dex at all").unwrap();

        let hits = detect_hollow(&[dex.clone(), garbage]);
        assert_eq!(hits.len(), 1, "garbage 不触发、fixture 触发: {hits:?}");
        let h = &hits[0];
        assert_eq!(h.path, dex);
        assert!(h.suspects.iter().any(|s| s.contains("->onCreate()V")));
        assert!(h.suspects.iter().any(|s| s.contains("->zap()V")));
        assert_eq!(h.lifecycle.len(), 1);
        assert!(h.lifecycle[0].contains("->onCreate()V"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pick_shell_so_assets_aarch64_largest() {
        // 挑选规则：assets/ 下 + ELF64 + e_machine==183(AArch64) + 最大者。
        // 干扰项：x86_64 变体、lib/ 下的合法 JNI 库（再大也不入选）、非 .so。
        fn elf_head(machine: u16, total: usize) -> Vec<u8> {
            let mut v = vec![0u8; total.max(20)];
            v[0..4].copy_from_slice(b"\x7fELF");
            v[4] = 2; // ELFCLASS64
            v[18..20].copy_from_slice(&machine.to_le_bytes());
            v
        }
        let dir = scratch("sopick");
        let apk = dir.join("packed.apk");
        {
            let f = std::fs::File::create(&apk).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            let opt = zip::write::SimpleFileOptions::default();
            zw.start_file("assets/libshell_x86.so", opt).unwrap();
            std::io::Write::write_all(&mut zw, &elf_head(62, 9000)).unwrap();
            zw.start_file("assets/libshell_a64.so", opt).unwrap();
            std::io::Write::write_all(&mut zw, &elf_head(183, 4000)).unwrap();
            zw.start_file("assets/libshell_a64_small.so", opt).unwrap();
            std::io::Write::write_all(&mut zw, &elf_head(183, 500)).unwrap();
            // lib/ 下的合法 JNI 库：格式全对但路径不对——永不入选
            zw.start_file("lib/arm64-v8a/libreal.so", opt).unwrap();
            std::io::Write::write_all(&mut zw, &elf_head(183, 99999)).unwrap();
            zw.start_file("assets/readme.txt", opt).unwrap();
            std::io::Write::write_all(&mut zw, b"junk").unwrap();
            zw.finish().unwrap();
        }
        let (name, path) = pick_shell_so(&apk, &dir.join("x")).unwrap().unwrap();
        assert_eq!(name, "assets/libshell_a64.so");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pick_shell_so_no_candidate_is_none() {
        // 无候选 = None（调用方转结构化错误，不静默带壳发货）
        let dir = scratch("sopick0");
        let apk = dir.join("packed.apk");
        {
            let f = std::fs::File::create(&apk).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            let opt = zip::write::SimpleFileOptions::default();
            zw.start_file("classes.dex", opt).unwrap();
            std::io::Write::write_all(&mut zw, b"dex\n035\0").unwrap();
            zw.finish().unwrap();
        }
        assert!(pick_shell_so(&apk, &dir.join("x")).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
