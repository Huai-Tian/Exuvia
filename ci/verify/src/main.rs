//! ci-verify CLI 壳（核心在 lib.rs）。
//!   register <corpus-dir>                语料登记 → corpus.json
//!   check <orig> <packed> <handoff-dir>  原包对账 → 覆盖率指标

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args.get(1).map(String::as_str) {
        Some("register") if args.len() == 3 => ci_verify::register(Path::new(&args[2])),
        Some("check") if args.len() == 5 => {
            ci_verify::check(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4]))
        }
        _ => Err(format!(
            "usage: {} register <corpus-dir> | check <orig.apk> <packed.apk> <handoff-dir>",
            args.first().map(String::as_str).unwrap_or("ci-verify")
        )),
    };
    match out {
        Ok(s) => {
            println!("{s}");
        }
        Err(e) => {
            eprintln!("{{\"error\":\"{}\"}}", e.replace('"', "'"));
            std::process::exit(1);
        }
    }
}
