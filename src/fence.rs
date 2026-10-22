//! SKILL.md profile fence 提取器。
//! 锚点语义（SKILL.md §8）：info string 精确等于 `toml profile` 的 fenced block；
//! 提取不到或 TOML 语法错误 = installation-broken。

#[derive(Debug)]
pub enum FenceError {
    NotFound,
    TomlParse(toml::de::Error),
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FenceError::NotFound => write!(f, "profile fence not found (info string `toml profile`)"),
            FenceError::TomlParse(e) => write!(f, "fence TOML parse error: {e}"),
        }
    }
}

/// 提取 fence 原文（不含 fence 标记行）。
pub fn extract(skill_md: &str) -> Result<String, FenceError> {
    let mut in_fence = false;
    let mut out = String::new();
    for line in skill_md.lines() {
        let t = line.trim();
        if !in_fence {
            if t == "```toml profile" {
                in_fence = true;
            }
        } else if t == "```" {
            return Ok(out);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Err(FenceError::NotFound)
}

/// 提取并解析为 TOML 值（启动校验入口）。
pub fn parse(skill_md: &str) -> Result<toml::Value, FenceError> {
    toml::from_str(&extract(skill_md)?).map_err(FenceError::TomlParse)
}
