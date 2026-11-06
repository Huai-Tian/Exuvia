// 会话层:§10.4 词表的信封编解码(speak() 帧承载,单帧 ≤64KB)。
// 无保活帧(裁定 27);order_id 即幂等键;数据面走文件族不占词。

use crate::proto::*;

pub struct SessionTx {
    seq: u64,
}

impl Default for SessionTx {
    fn default() -> Self { SessionTx { seq: 0 } }
}

impl SessionTx {
    /// 造信封(发送方单调序号自增)
    pub fn make(&mut self, kind: SessionKind, order_id: Option<String>, body: serde_json::Value) -> SessionEnvelope {
        self.seq += 1;
        SessionEnvelope {
            schema: "exuvia.session".into(),
            session_version: SESSION_VERSION,
            kind,
            seq: self.seq,
            order_id,
            body,
        }
    }

    /// 编码为 speak 文本帧;超 64KB 响亮拒绝(控制面设计上限)
    pub fn encode(&mut self, kind: SessionKind, order_id: Option<String>, body: serde_json::Value) -> Result<String, String> {
        let env = self.make(kind, order_id, body);
        let s = serde_json::to_string(&env).map_err(|e| e.to_string())?;
        if s.len() > 64 * 1024 {
            return Err(format!("会话帧超 64KB({} B):{:?}", s.len(), env.kind));
        }
        Ok(s)
    }
}

/// 解码对端帧(未知字段/错版本/坏词 = 协议错误,响亮拒绝)
pub fn decode(text: &str) -> Result<SessionEnvelope, String> {
    let env: SessionEnvelope = serde_json::from_str(text).map_err(|e| format!("信封解析失败: {e}"))?;
    if env.schema != "exuvia.session" {
        return Err(format!("$schema 不符: {}", env.schema));
    }
    if env.session_version != SESSION_VERSION {
        return Err(format!("session_version {} 不支持(本端 = {SESSION_VERSION})", env.session_version));
    }
    Ok(env)
}
