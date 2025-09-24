use p3_field::{Field, integers::QuotientMap};
use sha2::{Digest, Sha256};

use super::Circuit;
use crate::{
    config::{CircuitConfig, CircuitParams},
    error::ZkpError,
};

/// 子串包含证明电路
///
/// 电路目标：证明公开子串 `s` 包含在某个原文中，且原文的 SHA-256 哈希等于公开承诺
///
/// 约束系统：
/// 1. 哈希一致性：SHA256(plaintext) == commitment
/// 2. 子串匹配：对窗口 [k, k+|s|) 逐字节约束 plaintext[k+j] == s[j]
/// 3. 范围检查：k 合法（0 ≤ k ≤ |plaintext| - |s|）
/// 4. 字节范围：所有字节值在 [0, 255] 范围内
#[derive(Debug, Clone)]
pub struct SubstringCircuit {
    config: CircuitConfig,
}

impl SubstringCircuit {
    pub fn new(config: CircuitConfig) -> Self {
        Self { config }
    }

    /// 验证输入参数的有效性
    fn validate_params(&self, params: &CircuitParams) -> Result<(), ZkpError> {
        let witness = params
            .witness
            .as_ref()
            .ok_or(ZkpError::InvalidWitness("Missing witness".to_string()))?;

        // 检查原文长度限制
        if witness.plaintext.len() > self.config.max_text_len {
            return Err(ZkpError::InvalidWitness(format!(
                "Plaintext too long: {} > {}",
                witness.plaintext.len(),
                self.config.max_text_len
            )));
        }

        // 检查子串长度限制
        if params.public_inputs.substring.len() > self.config.max_substring_len {
            return Err(ZkpError::InvalidWitness(format!(
                "Substring too long: {} > {}",
                params.public_inputs.substring.len(),
                self.config.max_substring_len
            )));
        }

        // 检查偏移合法性
        if witness.offset + params.public_inputs.substring.len() > witness.plaintext.len() {
            return Err(ZkpError::InvalidWitness(
                "Substring offset out of bounds".to_string(),
            ));
        }

        Ok(())
    }

    /// 验证哈希一致性约束
    fn verify_hash_constraint(&self, params: &CircuitParams) -> Result<bool, ZkpError> {
        let witness = params
            .witness
            .as_ref()
            .ok_or(ZkpError::InvalidWitness("Missing witness".to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&witness.plaintext);
        let computed_hash = hasher.finalize();

        Ok(computed_hash.as_slice() == params.public_inputs.commitment)
    }

    /// 验证子串匹配约束
    fn verify_substring_constraint(&self, params: &CircuitParams) -> Result<bool, ZkpError> {
        let witness = params
            .witness
            .as_ref()
            .ok_or(ZkpError::InvalidWitness("Missing witness".to_string()))?;

        let substring = &params.public_inputs.substring;
        let start = witness.offset;
        let end = start + substring.len();

        if end > witness.plaintext.len() {
            return Ok(false);
        }

        let plaintext_substring = &witness.plaintext[start .. end];
        Ok(plaintext_substring == substring)
    }
}

impl<F: Field + QuotientMap<u8>> Circuit<F> for SubstringCircuit {
    fn generate_trace(&self, params: &CircuitParams) -> Result<Vec<Vec<F>>, ZkpError> {
        self.validate_params(params)?;

        let witness = params.witness.as_ref().unwrap();
        let public_inputs = &params.public_inputs;

        // Trace 布局：
        // - 列0-31: SHA-256 状态寄存器 (a, b, c, d, e, f, g, h)，每个4字节
        // - 列32-95: SHA-256 消息调度 (W[0]...W[63])，每个4字节
        // - 列96: 原文字节值
        // - 列97: 子串字节值
        // - 列98: 字节匹配标志 (0/1)
        // - 列99: 偏移位置指示器
        // - 列100: 范围检查列

        let trace_len = self.config.max_text_len.max(64); // SHA-256 需要至少64步
        let num_columns = 101;
        let mut trace = vec![vec![F::ZERO; trace_len]; num_columns];

        // TODO: 实现完整的 SHA-256 trace 生成
        // 这里先做简化实现，实际应该使用 p3-sha256 的逻辑

        // 填充原文字节
        for (i, &byte) in witness.plaintext.iter().enumerate() {
            trace[96][i] = F::from_int(byte);
        }

        // 填充子串匹配窗口
        let offset = witness.offset;
        for (i, &byte) in public_inputs.substring.iter().enumerate() {
            let pos = offset + i;
            if pos < trace_len {
                trace[97][pos] = F::from_int(byte);
                // 设置匹配标志
                if pos < witness.plaintext.len() && witness.plaintext[pos] == byte {
                    trace[98][pos] = F::ONE;
                }
            }
        }

        // 设置偏移位置指示器
        for i in offset .. offset + public_inputs.substring.len() {
            if i < trace_len {
                trace[99][i] = F::ONE;
            }
        }

        Ok(trace)
    }

    fn verify_constraints(
        &self,
        trace: &[Vec<F>],
        params: &CircuitParams,
    ) -> Result<bool, ZkpError> {
        // 验证哈希约束
        if !self.verify_hash_constraint(params)? {
            return Ok(false);
        }

        // 验证子串匹配约束
        if !self.verify_substring_constraint(params)? {
            return Ok(false);
        }

        // 验证 trace 中的约束
        let _substring_len = params.public_inputs.substring.len();

        // 检查匹配标志约束：在匹配窗口内，所有位置都应该匹配
        for i in 0 .. trace[0].len() {
            if trace[99][i] == F::ONE {
                // 在匹配窗口内
                if trace[98][i] != F::ONE {
                    // 但没有匹配标志
                    return Ok(false);
                }
                // 检查字节值是否匹配
                if trace[96][i] != trace[97][i] {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn get_config(&self) -> CircuitConfig {
        self.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::config::{CircuitWitness, PublicInputs};

    #[test]
    fn test_hello_world_example() {
        let config = CircuitConfig::default();
        let circuit = SubstringCircuit::new(config.clone());

        // 示例：证明 "hello" 属于 "hello world!"
        let plaintext = b"hello world!".to_vec();
        let substring = b"hello".to_vec();

        // 计算承诺
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

        // 生成 trace
        let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
        let trace = circuit_typed.generate_trace(&params).unwrap();

        // 验证约束
        let is_valid = circuit_typed.verify_constraints(&trace, &params).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_substring() {
        let config = CircuitConfig::default();
        let circuit = SubstringCircuit::new(config.clone());

        let plaintext = b"hello world!".to_vec();
        let substring = b"xyz".to_vec(); // 不存在的子串

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

        let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
        let trace = circuit_typed.generate_trace(&params).unwrap();
        let is_valid = circuit_typed.verify_constraints(&trace, &params).unwrap();
        assert!(!is_valid);
    }
}
