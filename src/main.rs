//! CLI 入口（README_AGENT §5）。
//! 任何命令前先跑安装完整性校验——installation-broken 拒绝一切运行，不存在降级模式。

use exuvia::{install, protocol, version};
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

fn main() -> ExitCode {
    // 启动校验：失败输出结构化错误（给 Agent 读），退出码 2（DRAFT 值）
    if let Err(e) = install::check() {
        eprintln!(
            "{{\"status\":\"installation-broken\",\"detail\":\"{}\"}}",
            e.replace('"', "'")
        );
        return ExitCode::from(install::BROKEN_EXIT as u8);
    }

    let cli = Cli::parse();

    if cli.version {
        println!("exuvia {}", version::EXUVIA_VERSION);
        println!("{}", version::protocol_line());
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
            Some(apk_path) => match exuvia::track_a::first_pass(&apk_path) {
                Ok((report, debt, slices)) => {
                    let rjson = serde_json::to_string_pretty(&report).unwrap();
                    let djson = serde_json::to_string_pretty(&debt).unwrap();
                    std::fs::create_dir_all("handoff").ok();
                    std::fs::write("handoff/REPORT.json", &rjson).ok();
                    std::fs::write("handoff/debt.json", &djson).ok();
                    // evidence 切片落盘：slice.bin + hash 锚定 manifest
                    for s in &slices {
                        let dir = format!("handoff/evidence/{}", s.debt_id);
                        std::fs::create_dir_all(&dir).ok();
                        std::fs::write(format!("{dir}/slice.bin"), &s.bytes).ok();
                        let digest = {
                            use sha2::Digest as _;
                            format!(
                                "sha256:{}",
                                sha2::Sha256::digest(&s.bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
                            )
                        };
                        let m = exuvia::report::EvidenceManifest {
                            schema: "exuvia.evidence".to_string(),
                            debt_id: s.debt_id.clone(),
                            so: s.so_name.clone(),
                            symbol: s.symbol.clone(),
                            st_value: s.st_value,
                            st_size: s.st_size,
                            file_offset: s.file_offset,
                            slice_sha256: digest,
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
            },
            None => {
                Cli::command().print_help().unwrap();
                ExitCode::SUCCESS
            }
        },
    }
}
