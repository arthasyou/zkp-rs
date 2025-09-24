use p3_field::{Field, integers::QuotientMap};
use crate::config::{CircuitConfig, CircuitParams};
use crate::error::ZkpError;

/// 计算轨迹（Execution Trace）的列定义
/// 
/// Trace 矩阵布局：每行代表一个时间步，每列代表一个电路变量
#[derive(Debug, Clone)]
pub struct TraceLayout {
    /// SHA-256 状态寄存器列（8个32位字 = 32列）
    pub sha_state_cols: std::ops::Range<usize>,
    /// SHA-256 消息调度列（64个32位字 = 64列） 
    pub sha_schedule_cols: std::ops::Range<usize>,
    /// 原文字节值列
    pub plaintext_col: usize,
    /// 子串字节值列
    pub substring_col: usize,
    /// 字节匹配标志列（0/1）
    pub match_flag_col: usize,
    /// 偏移位置指示器列（标记匹配窗口）
    pub offset_indicator_col: usize,
    /// 范围检查列（确保字节值在[0,255]）
    pub range_check_col: usize,
    /// 总列数
    pub total_columns: usize,
}

impl Default for TraceLayout {
    fn default() -> Self {
        Self {
            sha_state_cols: 0..32,        // 列 0-31: SHA-256 状态 (8个寄存器 * 4字节)
            sha_schedule_cols: 32..96,    // 列 32-95: 消息调度 (64个字 * 1列)
            plaintext_col: 96,            // 列 96: 原文字节
            substring_col: 97,            // 列 97: 子串字节
            match_flag_col: 98,           // 列 98: 匹配标志
            offset_indicator_col: 99,     // 列 99: 偏移指示器
            range_check_col: 100,         // 列 100: 范围检查
            total_columns: 101,
        }
    }
}

/// 计算轨迹生成器
#[derive(Debug, Clone)]
pub struct TraceGenerator {
    layout: TraceLayout,
    config: CircuitConfig,
}

impl TraceGenerator {
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            layout: TraceLayout::default(),
            config,
        }
    }

    /// 计算所需的 trace 长度
    pub fn compute_trace_length(&self, params: &CircuitParams) -> usize {
        let witness = params.witness.as_ref().expect("Witness required for trace generation");
        
        // SHA-256 需要的步数：对于单块，需要64轮
        let sha_steps = if self.config.enable_multi_block_sha {
            // 多块支持：每512位一块，每块64轮
            let blocks = (witness.plaintext.len() + 63) / 64; // 向上取整
            blocks * 64
        } else {
            64 // 单块固定64轮
        };

        // 字节处理步数：原文长度
        let byte_steps = witness.plaintext.len();

        // 取最大值，确保所有约束都能得到验证
        sha_steps.max(byte_steps).max(64) // 最小64步
    }

    /// 生成完整的计算轨迹
    pub fn generate_trace<F: Field + QuotientMap<u8>>(&self, params: &CircuitParams) -> Result<Vec<Vec<F>>, ZkpError> {
        let witness = params.witness.as_ref()
            .ok_or(ZkpError::InvalidWitness("Missing witness".to_string()))?;
        
        let trace_length = self.compute_trace_length(params);
        let mut trace = vec![vec![F::ZERO; trace_length]; self.layout.total_columns];

        // 1. 生成 SHA-256 轨迹
        self.generate_sha256_trace(&mut trace, witness, trace_length)?;

        // 2. 生成字节处理轨迹
        self.generate_byte_trace(&mut trace, params, trace_length)?;

        // 3. 生成子串匹配轨迹
        self.generate_substring_trace(&mut trace, params, trace_length)?;

        // 4. 生成范围检查轨迹
        self.generate_range_check_trace(&mut trace, witness, trace_length)?;

        Ok(trace)
    }

    /// 生成 SHA-256 相关的 trace 列
    fn generate_sha256_trace<F: Field + QuotientMap<u8>>(
        &self,
        trace: &mut [Vec<F>],
        witness: &crate::config::CircuitWitness,
        trace_length: usize,
    ) -> Result<(), ZkpError> {
        // TODO: 使用 p3-sha256 实现完整的 SHA-256 轨迹生成
        // 这里做简化实现，实际应该包含：
        // - 消息预处理和 padding
        // - 64轮的消息调度 (W[t] = ...)
        // - 8个状态寄存器的更新 (a, b, c, d, e, f, g, h)
        // - 每轮的压缩函数计算

        use sha2::{Digest, Sha256};
        
        // 计算最终哈希作为验证（实际电路中需要逐步计算）
        let mut hasher = Sha256::new();
        hasher.update(&witness.plaintext);
        let hash = hasher.finalize();

        // 在最后几行存储哈希输出用于约束检查
        if trace_length >= 32 {
            for (i, &byte) in hash.iter().enumerate() {
                if i < self.layout.sha_state_cols.len() && trace_length > 32 {
                    trace[self.layout.sha_state_cols.start + i][trace_length - 32 + i] = 
                        F::from_int(byte);
                }
            }
        }

        Ok(())
    }

    /// 生成字节处理轨迹
    fn generate_byte_trace<F: Field + QuotientMap<u8>>(
        &self,
        trace: &mut [Vec<F>],
        params: &CircuitParams,
        trace_length: usize,
    ) -> Result<(), ZkpError> {
        let witness = params.witness.as_ref().unwrap();

        // 填充原文字节到 trace
        for (i, &byte) in witness.plaintext.iter().enumerate() {
            if i < trace_length {
                trace[self.layout.plaintext_col][i] = F::from_int(byte);
            }
        }

        Ok(())
    }

    /// 生成子串匹配轨迹
    fn generate_substring_trace<F: Field + QuotientMap<u8>>(
        &self,
        trace: &mut [Vec<F>],
        params: &CircuitParams,
        trace_length: usize,
    ) -> Result<(), ZkpError> {
        let witness = params.witness.as_ref().unwrap();
        let substring = &params.public_inputs.substring;
        let offset = witness.offset;

        // 标记匹配窗口和填充子串字节
        for (i, &byte) in substring.iter().enumerate() {
            let pos = offset + i;
            if pos < trace_length {
                // 填充子串字节
                trace[self.layout.substring_col][pos] = F::from_int(byte);
                
                // 设置偏移指示器（标记这是匹配窗口）
                trace[self.layout.offset_indicator_col][pos] = F::ONE;
                
                // 设置匹配标志（如果字节匹配）
                if pos < witness.plaintext.len() && witness.plaintext[pos] == byte {
                    trace[self.layout.match_flag_col][pos] = F::ONE;
                }
            }
        }

        Ok(())
    }

    /// 生成范围检查轨迹
    fn generate_range_check_trace<F: Field + QuotientMap<u8>>(
        &self,
        trace: &mut [Vec<F>],
        witness: &crate::config::CircuitWitness,
        trace_length: usize,
    ) -> Result<(), ZkpError> {
        // 为每个字节设置范围检查标志（确保在[0,255]范围内）
        for (i, _byte) in witness.plaintext.iter().enumerate() {
            if i < trace_length {
                // 简单的范围检查：如果字节值合法则设为1
                // u8 类型的字节总是在 [0, 255] 范围内
                trace[self.layout.range_check_col][i] = F::ONE;
            }
        }

        Ok(())
    }

    pub fn get_layout(&self) -> &TraceLayout {
        &self.layout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CircuitWitness, PublicInputs};
    use p3_goldilocks::Goldilocks;
    use p3_field::PrimeCharacteristicRing;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_trace_generation() {
        let config = CircuitConfig::default();
        let generator = TraceGenerator::new(config.clone());

        let plaintext = b"hello world!".to_vec();
        let substring = b"hello".to_vec();
        
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let commitment = hasher.finalize().into();

        let params = CircuitParams {
            config,
            public_inputs: PublicInputs {
                commitment,
                substring,
            },
            witness: Some(CircuitWitness {
                plaintext,
                offset: 0,
            }),
        };

        let trace = generator.generate_trace::<Goldilocks>(&params).unwrap();
        
        // 验证 trace 的基本属性
        assert_eq!(trace.len(), 101); // 总列数
        assert!(trace[0].len() >= 64); // 至少64行

        // 验证字节数据被正确填充
        assert_eq!(trace[96][0], Goldilocks::from_int(b'h')); // 第一个字符
        assert_eq!(trace[99][0], Goldilocks::ONE); // 偏移指示器
        assert_eq!(trace[98][0], Goldilocks::ONE); // 匹配标志
    }
}