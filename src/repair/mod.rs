//! 修复管线嵌入层（产品化方案：Rust 壳 + 内嵌 Python 工具链）。
//!
//! 设计决策（2026-10-21 拍板）：Python 工具链已通过 12 轮真机验证（11 个根因全修，
//! v1+v2 双双成功），完全重写引入 bug 的风险 >> 重写收益。项目架构已假设系统
//! python3（README_AGENT §0 "IDA 模式"）。本模块将 Python 脚本嵌入 Rust 二进制，
//! 运行时提取到临时目录并调用 python3 按管线顺序执行。
//!
//! CLI: `exuvia repair <packed.apk> <dumped.dex> -o out.apk [--reference ref.dex]`
//!
//! 管线: doctor → clean → deweave → [repack(可选)] → [restore(可选)] → surgery
//!       → zipalign → sign v2

pub mod embed;
pub mod pipeline;

pub use pipeline::{run_repair, RepairArgs, RepairResult};
