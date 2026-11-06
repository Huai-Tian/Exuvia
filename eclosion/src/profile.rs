// 驱动对接层:driver profile(用户侧配置,不进 exuvia 契约——立项书 §4)。
// 形态无关(裁定#31):transport.kind 预留 syscall/ioctl/proc/netlink/file,
// 首期实现 syscall(真驱动)+ file(模拟通道,桌面自走通专用)。
// profile 是数据不是代码:cmd 数字全部来自 profile,请求布局名从内置小注册表选
// (布局 = 机械结构体拼装器,不含协议数字;协议数字全在 profile)。

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DRIVER_PROFILE_VERSION: i64 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverProfile {
    pub driver_profile_version: i64,
    /// 用户侧自由命名(工单/manifest 机器字段永不出现驱动标识;profile 是设备侧配置)
    pub name: String,
    pub version: String,
    pub transport: Transport,
    pub ops: Ops,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Transport {
    /// 死 syscall 钩通道:syscall(nr, magic_arg0, req_ptr, cmd)——cmd 位置由 cmd_pos 给
    #[serde(rename = "syscall")]
    Syscall { nr: u16, magic_arg0: u64, cmd_pos: u8 },
    /// 模拟通道(桌面自走通专用):image = 目标内存映像文件,maps = maps 文本,pid = 假目标 pid
    #[serde(rename = "file")]
    File { image: String, maps: String, pid: u32 },
}

/// 请求布局注册表(代码侧;profile 用名字选)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Layout {
    /// 40B: {pid:u32, pad, addr:u64, buf:u64, size:u64, flags:u32, pad}(ditpro 读)
    #[serde(rename = "read40_v1")]
    Read40V1,
    /// 24B: {pid:u32, pad, name_ptr:u64, base_out:u64}(ditpro 模块基址)
    #[serde(rename = "modbase24_v1")]
    ModBase24V1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ops {
    pub read: Option<OpRead>,
    pub read_list: Option<OpBare>,
    pub write: Option<OpBare>,
    pub hide_proc: Option<OpBare>,
    pub pid_of: Option<OpBare>,
    pub mod_base: Option<OpModBase>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpRead {
    pub cmd: u32,
    pub layout: Layout,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpModBase {
    pub cmd: u32,
    pub layout: Layout,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpBare {
    pub cmd: u32,
}

impl DriverProfile {
    pub fn load(path: &Path) -> Result<DriverProfile, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("profile 读取失败 {}: {e}", path.display()))?;
        let p: DriverProfile = serde_json::from_str(&text).map_err(|e| format!("profile 解析失败: {e}"))?;
        if p.driver_profile_version != DRIVER_PROFILE_VERSION {
            return Err(format!("driver_profile_version {} 不支持(本版 = {DRIVER_PROFILE_VERSION})", p.driver_profile_version));
        }
        Ok(p)
    }

    /// 编译期内置默认方案(ditpro,2026-11-06 逆向实证):
    /// syscall(18, 0x268, req_ptr, cmd);0x400 读 / 0x100 基址 / 0x50 查 pid;读路径无密钥。
    pub fn builtin_default() -> DriverProfile {
        DriverProfile {
            driver_profile_version: DRIVER_PROFILE_VERSION,
            name: "ditpro-rw".into(),
            version: "1.4.2".into(),
            transport: Transport::Syscall { nr: 18, magic_arg0: 0x268, cmd_pos: 2 },
            ops: Ops {
                read: Some(OpRead { cmd: 0x400, layout: Layout::Read40V1 }),
                read_list: Some(OpBare { cmd: 0x401 }),
                write: Some(OpBare { cmd: 0x200 }),
                hide_proc: Some(OpBare { cmd: 0x40 }),
                pid_of: Some(OpBare { cmd: 0x50 }),
                mod_base: Some(OpModBase { cmd: 0x100, layout: Layout::ModBase24V1 }),
            },
        }
    }

    /// 能力通道(工单 stealth.driver.channels 的核对依据)
    pub fn channels(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.ops.read.is_some() { v.push("phys_read".to_string()); }
        if self.ops.write.is_some() { v.push("phys_write".to_string()); }
        if self.ops.hide_proc.is_some() { v.push("hide_proc".to_string()); }
        v
    }

    /// 能力核对(立项书 §4:缺项 = 大声拒绝)
    pub fn capability_check(&self, required: &[String]) -> Result<(), String> {
        let have = self.channels();
        let missing: Vec<&String> = required.iter().filter(|r| !have.contains(r)).collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!("驱动能力缺项: 需要 {:?} 现有 {:?}", missing, have))
        }
    }
}
