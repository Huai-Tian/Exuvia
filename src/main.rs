//! CLI 入口（README_AGENT §5）。
//! 任何命令前先跑安装完整性校验——installation-broken 拒绝一切运行，不存在降级模式。
//! check 需要 --profile（判断外置通道），故顺序 = parse → check → 分发。
//! 输出恒 JSON（CLI 就是 API）；--version 例外为人类行，--json 时亦 JSON 化。

use exuvia::{install, protocol, report, version};
use clap::{CommandFactory, Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "exuvia",
    about = "Separate the shell from what lives inside.",
    disable_version_flag = true
)]
struct Cli {
    /// 打印版本 + 支持的协议版本
    #[arg(long)]
    version: bool,

    /// 覆盖 SKILL fence 内嵌的默认判断（TOML；解析失败 = installation-broken）
    #[arg(long, value_name = "FILE")]
    profile: Option<std::path::PathBuf>,

    /// 幂等续跑：handoff 的 apk sha256 一致时跳过重剖析
    #[arg(long)]
    resume: bool,

    /// 输出恒 JSON（CLI 就是 API）；此 flag 使 --version 亦 JSON 化
    #[arg(long)]
    json: bool,

    /// 拖入即用：APK 剖析（解包 → 清点 → 熵测量 → handoff/REPORT.json）
    #[arg(value_name = "APK")]
    apk: Option<std::path::PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 按需派生机器可读格式（无静态 schema 文件）
    Schema {
        /// 目标协议名
        #[arg(long)]
        dump: protocol::SchemaName,
    },
    /// 打包卡点工作包（goal 消费端：机械筛选，不排序不评价）
    Next {
        /// 格式化目标文件
        #[arg(long)]
        goal: std::path::PathBuf,
    },
    /// 剖析包操作（validate 自检 / merge proposal 回流）
    Unpack {
        #[command(subcommand)]
        cmd: UnpackCmd,
    },
    /// 洋葱二次分析：对解卡产物（recovered DEX）再剖析 → 下一层欠账地图
    Analyze {
        /// 单个 DEX 文件（如 workspace/<debt_id>/recovered.dex）
        #[arg(long)]
        dex: std::path::PathBuf,
        /// 输出目录（剖析包；默认 handoff-2/）
        #[arg(long, default_value = "handoff-2")]
        out: std::path::PathBuf,
    },
    /// L2 参数空间搜索：已知算法（rc4/xor/aes-cbc + key）× 未知密文段参数 → 机械命中
    /// （轨道 C 桌面化：算法与 key 来自 facts/LLM 复现，段起点/长度由判据链自决）
    Hunt {
        /// 密文载体文件（evidence 切片 / so 内嵌段 / 任意字节流）
        #[arg(long)]
        carrier: std::path::PathBuf,
        /// 标准 RC4 key（hex；可重复：多谓词并行全空间搜索）
        #[arg(long = "rc4", value_name = "HEX")]
        rc4: Vec<String>,
        /// PRGA 变体参数（修饰所有 --rc4；Battle-1 实测变体 = 2,3:5,1）
        #[arg(long, default_value = "1")]
        rc4_stride: String,
        #[arg(long, default_value = "0:0")]
        rc4_seed: String,
        #[arg(long, default_value = "0")]
        rc4_jbias: String,
        /// 循环 XOR key（hex；可重复）
        #[arg(long = "xor", value_name = "HEX")]
        xor: Vec<String>,
        /// AES-128-CBC tail 容器 key（hex 或 16 字节 ASCII；可重复；剖面 aes128cbc-tail-v1，
        /// 起点 trailer 自述 / 头块长度扫描自决 / 子容器长度前缀走查）
        #[arg(long = "aes-cbc", value_name = "KEY")]
        aes_cbc: Vec<String>,
        /// AES-128-CBC IV（hex 或 16 字节 ASCII；修饰所有 --aes-cbc）
        #[arg(long = "aes-iv", value_name = "IV", requires = "aes_cbc")]
        aes_iv: Option<String>,
        /// 子容器前缀 XOR 参数（族默认 0x70/0x66；--aes-xor-prefix 0 = 子容器明文存放）
        #[arg(long = "aes-xor-prefix", default_value = "0x70")]
        aes_xor_prefix: String,
        #[arg(long = "aes-xor-key", default_value = "0x66")]
        aes_xor_key: String,
        /// 输出目录（hunt.json + hits/<n>.dex；默认 hunt/）
        #[arg(long, default_value = "hunt")]
        out: std::path::PathBuf,
    },
    /// 修复管线：dump 的 DEX → 可安装可运行的 APK
    /// （12 轮真机验证的 Python 工具链内嵌于二进制；系统 python3 是前提假设）
    Repair {
        /// 加固后的（壳）APK
        #[arg(value_name = "PACKED_APK")]
        packed: std::path::PathBuf,
        /// dump 出的 DEX 文件（可多个：依次分诊后重打包为 classes.dex, classes2.dex…，
        /// 与 repair_all.py 的位置参数 nargs='+' 同义）
        #[arg(value_name = "DUMPED_DEX")]
        dex: Vec<std::path::PathBuf>,
        /// 输出 APK 路径
        #[arg(short, long)]
        out: std::path::PathBuf,
        /// 参照 DEX（原包 classes.dex；仅内部测试用，生产场景无原包）
        #[arg(long)]
        reference: Option<std::path::PathBuf>,
        /// 额外 dump 来源（第三方 dump / 脱壳阶段产物，可多次）——
        /// 被壳抽取的方法从任何携带其方法体的来源还原，多来源互补
        #[arg(long = "dump", value_name = "DUMP_DEX")]
        dumps: Vec<std::path::PathBuf>,
        /// 直挂成品 dex（原样追加为 classes2..N，不重序列化，可多次、保序）——
        /// 脱壳阶段闸门产物等不可再序列化的成品走这里；与 --dump（只作来源、
        /// 不进成品）是两条不可互换的通道
        #[arg(long = "extra-dex", value_name = "DEX")]
        extra_dex: Vec<std::path::PathBuf>,
        /// 源头通道：自动收集 ./handoff/workspace/*/recovered.dex（存在即已过
        /// 四层闸门）。无显式位置参数时最大者提升为主 dex（受分诊），其余按
        /// debt_id 序直挂；与显式通道 sha256 去重
        #[arg(long = "from-handoff")]
        from_handoff: bool,
    },
}

#[derive(Subcommand)]
enum UnpackCmd {
    /// proposal 回流：四层闸门（语法/格式 → 对账 → 语义双锚 → 销账）
    Merge { dir: std::path::PathBuf },
    /// 剖析包自检（下游消费前跑）
    Validate { dir: std::path::PathBuf },
}

fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    use sha2::Digest as _;
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        use std::io::Read as _;
        let n = f.read(&mut buf).map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!(
        "sha256:{}",
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // 启动校验：失败输出结构化错误（给 Agent 读），退出码 2（DRAFT 值）
    // Repair 子命令例外：它是独立修复工具（Python 工具链内嵌），不依赖 SKILL.md fence
    let is_repair = matches!(cli.cmd, Some(Cmd::Repair { .. }));
    if !is_repair {
        if let Err(e) = install::check(cli.profile.as_deref()) {
            eprintln!(
                "{{\"status\":\"installation-broken\",\"detail\":\"{}\"}}",
                e.replace('"', "'")
            );
            return ExitCode::from(install::BROKEN_EXIT as u8);
        }
    }

    if cli.version {
        if cli.json {
            println!(
                "{{\"version\":\"{}\",\"skill_version\":\"{}\",\"handoff_version\":{},\"goal_version\":{},\"proposal_version\":{}}}",
                version::EXUVIA_VERSION,
                version::SKILL_VERSION,
                version::HANDOFF_VERSION,
                version::GOAL_VERSION,
                version::PROPOSAL_VERSION
            );
        } else {
            println!("exuvia {}", version::EXUVIA_VERSION);
            println!("{}", version::protocol_line());
        }
        return ExitCode::SUCCESS;
    }

    match cli.cmd {
        Some(Cmd::Schema { dump }) => match protocol::schema_dump(dump) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{{\"error\":\"{e}\"}}");
                ExitCode::FAILURE
            }
        },
        Some(Cmd::Next { goal }) => match exuvia::next::build(&goal, std::path::Path::new("handoff")) {
            Ok(wp) => {
                let json = serde_json::to_string_pretty(&wp).unwrap();
                std::fs::write("workpackage.json", &json).ok();
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                ExitCode::FAILURE
            }
        },
        Some(Cmd::Analyze { dex, out }) => {
            match exuvia::track_a::reanalyze::analyze_dex(&dex, &out) {
                Ok(debt) => {
                    let json = serde_json::to_string_pretty(&debt).unwrap();
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                    ExitCode::FAILURE
                }
            }
        }
        Some(Cmd::Hunt { carrier, rc4, rc4_stride, rc4_seed, rc4_jbias, xor, aes_cbc, aes_iv, aes_xor_prefix, aes_xor_key, out }) => {
            use exuvia::track_a::hunt::{hex_to_bytes, key_spec_bytes, run, AesCbcTailParams, Predicate, Rc4Params};
            // 0x.. / 十进制自适解析（dexcontainer.py 的 int(s, 0) 同款 CLI 习惯）
            fn int_auto(s: &str) -> Result<usize, String> {
                match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Some(h) => usize::from_str_radix(h, 16).map_err(|_| format!("bad int {s}")),
                    None => s.parse::<usize>().map_err(|_| format!("bad int {s}")),
                }
            }
            // 变体参数解析（失败 = 结构化错误；默认值 = 标准 RC4）
            let parse_params = || -> Result<Rc4Params, String> {
                let stride = rc4_stride.parse::<u32>().map_err(|_| format!("bad --rc4-stride {rc4_stride}"))?;
                let jbias = rc4_jbias.parse::<u32>().map_err(|_| format!("bad --rc4-jbias {rc4_jbias}"))?;
                let (i, j) = rc4_seed
                    .split_once(':')
                    .ok_or_else(|| format!("bad --rc4-seed {rc4_seed} (expect I:J)"))?;
                let (i, j) = (
                    i.parse::<u32>().map_err(|_| format!("bad --rc4-seed {rc4_seed}"))?,
                    j.parse::<u32>().map_err(|_| format!("bad --rc4-seed {rc4_seed}"))?,
                );
                Ok(Rc4Params { stride, i_seed: i, j_seed: j, jbias })
            };
            let params = match parse_params() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{{\"error\":\"{e}\"}}");
                    return ExitCode::FAILURE;
                }
            };
            let mut predicates = Vec::new();
            for (k, is_rc4) in rc4.iter().map(|k| (k, true)).chain(xor.iter().map(|k| (k, false))) {
                match hex_to_bytes(k) {
                    Ok(key) if !key.is_empty() => {
                        predicates.push(if is_rc4 { Predicate::Rc4 { key, params } } else { Predicate::Xor { key } })
                    }
                    Ok(_) => {
                        eprintln!("{{\"error\":\"key {k} is empty\"}}");
                        return ExitCode::FAILURE;
                    }
                    Err(e) => {
                        eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                        return ExitCode::FAILURE;
                    }
                }
            }
            // AES-CBC tail 容器谓词（--aes-iv 由 clap requires 保证与 --aes-cbc 配对）
            if !aes_cbc.is_empty() {
                let iv = match key_spec_bytes(aes_iv.as_deref().unwrap_or("")) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                        return ExitCode::FAILURE;
                    }
                };
                let (xor_prefix, xor_key) = match (int_auto(&aes_xor_prefix), int_auto(&aes_xor_key)) {
                    (Ok(p), Ok(k)) if k <= 0xff => (p, k as u8),
                    (Ok(_), Ok(_)) => {
                        eprintln!("{{\"error\":\"--aes-xor-key {aes_xor_key} > 0xff\"}}");
                        return ExitCode::FAILURE;
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        eprintln!("{{\"error\":\"{e}\"}}");
                        return ExitCode::FAILURE;
                    }
                };
                for k in &aes_cbc {
                    match key_spec_bytes(k) {
                        Ok(key) => predicates.push(Predicate::AesCbc {
                            key,
                            iv: iv.clone(),
                            params: AesCbcTailParams { xor_prefix, xor_key },
                        }),
                        Err(e) => {
                            eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            match run(&carrier, &predicates, &out) {
                Ok(file) => {
                    let json = serde_json::to_string_pretty(&file).unwrap();
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                    ExitCode::FAILURE
                }
            }
        }
        Some(Cmd::Repair { packed, dex, out, reference, dumps, extra_dex, from_handoff }) => {
            use exuvia::repair::{run_repair, RepairArgs};
            let args = RepairArgs {
                packed_apk: packed,
                dumped_dexes: dex,
                out_apk: out,
                reference_dex: reference,
                extra_dumps: dumps,
                extra_dex,
                from_handoff,
                key_pem: None,
                cert_der: None,
            };
            let result = run_repair(&args);
            let json = serde_json::json!({
                "success": result.success,
                "doctor_fixes": result.doctor_fixes,
                "deweave_restored": result.deweave_restored,
                "restore_count": result.restore_count,
                "stubsafe_count": result.stubsafe_count,
                "surgery_removed": result.surgery_removed,
                "shell_assets_removed": result.shell_assets_removed,
                "final_size": result.final_size,
                "output": args.out_apk,
                "error": result.error,
                "log": result.logs,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            if result.success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some(Cmd::Unpack { cmd }) => match cmd {
            UnpackCmd::Merge { dir } => {
                match exuvia::gate::merge(&dir, std::path::Path::new("handoff"), std::path::Path::new("workpackage.json")) {
                    Ok(out) => {
                        let json = serde_json::to_string_pretty(&out).unwrap();
                        println!("{json}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        // 结构化拒绝：错误码 + 定位 + 期望 + hint（报错是给 Agent 看的）
                        let mut o = serde_json::json!({ "error": e.code, "detail": e.detail });
                        if let Some(h) = &e.hint {
                            o["hint"] = serde_json::json!(h);
                        }
                        eprintln!("{o}");
                        ExitCode::FAILURE
                    }
                }
            }
            UnpackCmd::Validate { dir } => match exuvia::gate::validate(&dir) {
                Ok(v) => {
                    println!("{v}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{{\"error\":\"{}\",\"detail\":\"{}\"}}", e.code, e.detail.replace('"', "'"));
                    ExitCode::FAILURE
                }
            },
        },
        None => match cli.apk {
            Some(apk_path) => {
                // --resume：幂等续跑。已有 handoff 且 apk sha256 一致 → 跳过重剖析
                if cli.resume {
                    if let Ok(raw) = std::fs::read("handoff/REPORT.json") {
                        if let Ok(r) = serde_json::from_slice::<report::Report>(&raw) {
                            if let Ok(cur) = sha256_file(&apk_path) {
                                if r.apk.sha256 == cur {
                                    let out = serde_json::json!({
                                        "resumed": true,
                                        "apk_sha256": r.apk.sha256,
                                        "debt_remaining": r.debt.total,
                                    });
                                    println!("{out}");
                                    return ExitCode::SUCCESS;
                                }
                            }
                        }
                    }
                    // 无 handoff / sha 不符 → 落入全量剖析（断点续跑：换样本从头来）
                }
                match exuvia::track_a::first_pass(&apk_path) {
                    Ok((r, debt, groups)) => {
                        let rjson = serde_json::to_string_pretty(&r).unwrap();
                        let djson = serde_json::to_string_pretty(&debt).unwrap();
                        std::fs::create_dir_all("handoff").ok();
                        std::fs::write("handoff/REPORT.json", &rjson).ok();
                        std::fs::write("handoff/REPORT.md", report::render_markdown(&r)).ok();
                        std::fs::write("handoff/debt.json", &djson).ok();
                        // handoff 结构基线（§4.2）：workspace/ 与 attempts.log 就位（可续作状态）
                        std::fs::create_dir_all("handoff/workspace").ok();
                        if !std::path::Path::new("handoff/attempts.log").exists() {
                            std::fs::write("handoff/attempts.log", b"").ok();
                        }
                        // evidence 落盘：evidence/<debt_id>/{manifest.json, <name>.bin}——多切片共存
                        for g in &groups {
                            let dir = format!("handoff/evidence/{}", g.debt_id);
                            std::fs::create_dir_all(&dir).ok();
                            let mut manifest_slices = Vec::with_capacity(g.slices.len());
                            for s in &g.slices {
                                std::fs::write(format!("{dir}/{}.bin", s.name), &s.bytes).ok();
                                manifest_slices.push(report::SliceEntry {
                                    name: s.name.clone(),
                                    source: s.source.clone(),
                                    symbol: s.symbol.clone(),
                                    st_value: s.st_value,
                                    st_size: s.st_size,
                                    file_offset: s.file_offset,
                                    slice_sha256: sha256_file(std::path::Path::new(&format!(
                                        "{dir}/{}.bin",
                                        s.name
                                    )))
                                    .unwrap_or_default(),
                                });
                            }
                            let m = report::EvidenceManifest {
                                schema: "exuvia.evidence".to_string(),
                                debt_id: g.debt_id.clone(),
                                slices: manifest_slices,
                            };
                            std::fs::write(format!("{dir}/manifest.json"), serde_json::to_vec_pretty(&m).unwrap()).ok();
                        }
                        println!("{rjson}");
                        println!("{djson}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
                        ExitCode::FAILURE
                    }
                }
            }
            None => {
                Cli::command().print_help().unwrap();
                ExitCode::SUCCESS
            }
        },
    }
}
