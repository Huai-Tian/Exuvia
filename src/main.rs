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
    if let Err(e) = install::check(cli.profile.as_deref()) {
        eprintln!(
            "{{\"status\":\"installation-broken\",\"detail\":\"{}\"}}",
            e.replace('"', "'")
        );
        return ExitCode::from(install::BROKEN_EXIT as u8);
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
