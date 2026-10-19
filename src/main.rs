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
        None => match cli.apk {
            Some(apk_path) => match exuvia::track_a::first_pass(&apk_path) {
                Ok(report) => {
                    let json = serde_json::to_string_pretty(&report).unwrap();
                    std::fs::create_dir_all("handoff").ok();
                    std::fs::write("handoff/REPORT.json", &json).ok();
                    println!("{json}");
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
