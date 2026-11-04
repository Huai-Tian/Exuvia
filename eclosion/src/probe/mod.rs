// 第 1 段设备探针(#11–#15):ART 符号发现/走读自证 + KPM 通道核验。
// 设计原则:不假设任何 ART 结构偏移;上机自发现、自证
// (dex 魔数 + header file_size/checksum + location 串三重交叉验证)。
// 只读:对目标进程零写入、零注入、零附着。

pub mod art;
pub mod elf;
pub mod kpm;
pub mod memio;

use crate::{emit, jn, js};
use std::process::exit;

pub fn dispatch(args: &[String]) {
    if args.is_empty() { usage(); }
    let mut pkg: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pkg" if i + 1 < args.len() => { pkg = Some(args[i + 1].clone()); i += 2; }
            _ => i += 1,
        }
    }
    match args[0].as_str() {
        "env" => env_probe(),
        "art" => { let p = pkg.unwrap_or_else(|| usage()); art::run(&p); }
        "kpm" => kpm::run(),
        "all" => { let p = pkg.unwrap_or_else(|| usage()); env_probe(); art::run(&p); kpm::run(); }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("probe 子命令: env | art --pkg <包名> | kpm | all --pkg <包名>");
    exit(2);
}

fn env_probe() {
    let prop = |key: &str| -> String {
        std::fs::read_to_string("/system/build.prop").unwrap_or_default()
            .lines().find_map(|l| l.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
            .unwrap_or_default()
    };
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let cstr = |b: *const std::os::raw::c_char| unsafe { std::ffi::CStr::from_ptr(b) }.to_string_lossy().to_string();
    let art_paths: Vec<&str> = [
        "/apex/com.android.art/lib64/libart.so",
        "/system/lib64/libart.so",
    ].iter().cloned().filter(|p| std::path::Path::new(p).exists()).collect();
    let enforce = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim().to_string()).unwrap_or_else(|_| "absent".into());
    emit(&[
        ("k", js("env")),
        ("sdk", js(&prop("ro.build.version.sdk"))),
        ("abi", js(&prop("ro.product.cpu.abi"))),
        ("kernel", js(&cstr(uts.release.as_ptr() as *const _))),
        ("page_size", jn(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })),
        ("art_libs", js(&art_paths.join(","))),
        ("selinux_enforce", js(&enforce)),
        ("uid", jn(unsafe { libc::getuid() })),
    ]);
}
