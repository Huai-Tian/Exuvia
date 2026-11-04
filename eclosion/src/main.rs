// 羽化(eclosion)——Exuvia 脱壳功能的动态手段执行端。
// 零内置策略的纯执行引擎:策略全部来自工单(SKILL §10 契约三件套耦合)。
//
// 0.1.0 骨架内容:
// - probe 动词:第 1 段设备探针(#11–#15,ART 符号/走读自证 + KPM 通道核验)
// - run/stop/status 守护三动词:占位,响亮未实现(随第 3 段骨架落地)
use std::process::exit;

mod probe;

// ---- JSON 行输出工具(probe 各模块共用;父模块私有项对子模块可见) ----
fn jescape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}
fn emit(fields: &[(&str, String)]) {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    println!("{{{}}}", body.join(","));
}
fn js(s: &str) -> String { format!("\"{}\"", jescape(s)) }
fn jn<T: std::fmt::Display>(v: T) -> String { v.to_string() }
fn jh(v: u64) -> String { format!("\"0x{v:x}\"") }

fn usage() -> ! {
    eprintln!("羽化 exuvia-eclosion v0.1.0 —— 零策略纯执行引擎(只读、零注入)");
    eprintln!("用法:");
    eprintln!("  exuvia-eclosion run      守护启动(占位——响亮未实现)");
    eprintln!("  exuvia-eclosion stop     守护停止(占位)");
    eprintln!("  exuvia-eclosion status   守护状态(占位)");
    eprintln!("  exuvia-eclosion probe <env|art|kpm|all> [--pkg <包名>]   第 1 段设备探针");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); }
    match args[1].as_str() {
        "run" | "stop" | "status" => {
            // 响亮未实现:静默 = 罪
            eprintln!("未实现:守护动词 run/stop/status 随第 3 段骨架落地(当前 0.1.0 仅含 probe 动词)");
            exit(3);
        }
        "probe" => probe::dispatch(&args[2..]),
        _ => usage(),
    }
}
