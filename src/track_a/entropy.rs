//! 香农熵测量——难度信号的第一项物理兑现（bits/byte，0..8）。
//! 分层纪律：测量在 Rust，分档在 fence（阈值字段未挣得前不存在），含义在下游。

pub struct EntropyCounter {
    counts: [u64; 256],
    total: u64,
}

impl EntropyCounter {
    pub fn new() -> Self {
        Self { counts: [0; 256], total: 0 }
    }

    /// 流式更新（大 asset 不落内存）
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.counts[b as usize] += 1;
        }
        self.total += data.len() as u64;
    }

    pub fn bits_per_byte(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let n = self.total as f64;
        let mut h = 0.0f64;
        for &c in &self.counts {
            if c > 0 {
                let p = c as f64 / n;
                h -= p * p.log2();
            }
        }
        // 保留 3 位小数，避免产物字节随浮点尾数漂移
        (h * 1000.0).round() / 1000.0
    }
}

impl Default for EntropyCounter {
    fn default() -> Self {
        Self::new()
    }
}
