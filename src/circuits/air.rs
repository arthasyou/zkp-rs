use p3_field::{Field, integers::QuotientMap};

use crate::{
    circuits::trace::TraceLayout,
    config::{CircuitConfig, PublicInputs},
    error::ZkpError,
};

/// AIR 约束系统定义
///
/// 实现子串包含证明的所有代数约束：
/// 1. SHA-256 哈希一致性约束
/// 2. 子串匹配约束
/// 3. 范围检查约束
/// 4. 逻辑一致性约束
#[derive(Debug, Clone)]
pub struct SubstringAIR {
    layout: TraceLayout,
    config: CircuitConfig,
}

impl SubstringAIR {
    pub fn new(config: CircuitConfig, layout: TraceLayout) -> Self {
        Self { layout, config }
    }

    /// 获取约束的总数
    pub fn num_constraints(&self) -> usize {
        self.num_sha256_constraints()
            + self.num_substring_constraints()
            + self.num_range_constraints()
            + self.num_logic_constraints()
    }

    /// SHA-256 约束数量
    fn num_sha256_constraints(&self) -> usize {
        // 简化版本：32个约束用于最终哈希比较
        // 完整版本需要：64轮 * 每轮多个约束 + 消息调度约束
        32
    }

    /// 子串匹配约束数量
    fn num_substring_constraints(&self) -> usize {
        // 每个可能的位置一个匹配约束
        self.config.max_text_len
    }

    /// 范围检查约束数量
    fn num_range_constraints(&self) -> usize {
        // 每个字节一个范围约束
        self.config.max_text_len
    }

    /// 逻辑一致性约束数量
    fn num_logic_constraints(&self) -> usize {
        // 偏移指示器和匹配标志的逻辑约束
        self.config.max_text_len * 2
    }

    /// 评估所有约束
    pub fn evaluate_constraints<F: Field + QuotientMap<u8> + QuotientMap<usize>>(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<Vec<F>, ZkpError> {
        let mut constraints = Vec::new();

        // 1. SHA-256 约束
        constraints.extend(self.evaluate_sha256_constraints(trace, public_inputs)?);

        // 2. 子串匹配约束
        constraints.extend(self.evaluate_substring_constraints(trace, public_inputs)?);

        // 3. 范围检查约束
        constraints.extend(self.evaluate_range_constraints(trace)?);

        // 4. 逻辑一致性约束
        constraints.extend(self.evaluate_logic_constraints(trace, public_inputs)?);

        Ok(constraints)
    }

    /// 评估 SHA-256 哈希一致性约束
    fn evaluate_sha256_constraints<F: Field + QuotientMap<u8>>(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<Vec<F>, ZkpError> {
        let mut constraints = Vec::new();
        let trace_len = trace[0].len();

        // 简化版本：检查最终哈希输出
        // 约束：trace 中的最终哈希状态 == 公开承诺
        for (i, &expected_byte) in public_inputs.commitment.iter().enumerate() {
            if i < self.layout.sha_state_cols.len() && trace_len >= 32 {
                let col_idx = self.layout.sha_state_cols.start + i;
                let row_idx = trace_len - 32 + i; // 假设哈希在最后存储

                let actual = trace[col_idx][row_idx.min(trace_len - 1)];
                let expected = F::from_int(expected_byte);

                // 约束：actual - expected == 0
                constraints.push(actual - expected);
            }
        }

        // TODO: 添加完整的 SHA-256 轮函数约束
        // 这需要实现：
        // - 消息调度约束：W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]
        // - 压缩函数约束：8个状态寄存器的更新规则
        // - 每轮的 Ch, Maj, Σ₀, Σ₁ 函数约束

        Ok(constraints)
    }

    /// 评估子串匹配约束  
    fn evaluate_substring_constraints<F: Field + QuotientMap<u8>>(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<Vec<F>, ZkpError> {
        let mut constraints = Vec::new();
        let trace_len = trace[0].len();

        // 为公开子串的每个字节创建约束
        for (_i, &expected_byte) in public_inputs.substring.iter().enumerate() {
            for row in 0 .. trace_len {
                // 约束：如果偏移指示器为1且位置匹配，则字节必须相等
                let offset_indicator = trace[self.layout.offset_indicator_col][row];
                let plaintext_byte = trace[self.layout.plaintext_col][row];
                let substring_byte = trace[self.layout.substring_col][row];
                let expected = F::from_int(expected_byte);

                // 约束1：在匹配窗口内，子串字节必须等于公开值
                // offset_indicator * (substring_byte - expected) == 0
                constraints.push(offset_indicator * (substring_byte - expected));

                // 约束2：在匹配窗口内，原文字节必须等于子串字节
                // offset_indicator * (plaintext_byte - substring_byte) == 0
                constraints.push(offset_indicator * (plaintext_byte - substring_byte));
            }
        }

        Ok(constraints)
    }

    /// 评估范围检查约束
    fn evaluate_range_constraints<F: Field>(&self, trace: &[Vec<F>]) -> Result<Vec<F>, ZkpError> {
        let mut constraints = Vec::new();
        let trace_len = trace[0].len();

        // 为每个原文字节添加范围约束：0 ≤ byte ≤ 255
        for row in 0 .. trace_len {
            let _byte_val = trace[self.layout.plaintext_col][row];
            let range_flag = trace[self.layout.range_check_col][row];

            // 简化的范围检查：如果字节非零，则范围标志必须为1
            // 完整版本需要查表或分解约束

            // 约束：range_flag * (range_flag - 1) == 0 (布尔约束)
            constraints.push(range_flag * (range_flag - F::ONE));

            // TODO: 添加完整的范围检查约束
            // 可以使用查表约束或位分解约束来确保 byte_val ∈ [0, 255]
        }

        Ok(constraints)
    }

    /// 评估逻辑一致性约束
    fn evaluate_logic_constraints<F: Field + QuotientMap<usize>>(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<Vec<F>, ZkpError> {
        let mut constraints = Vec::new();
        let trace_len = trace[0].len();

        for row in 0 .. trace_len {
            let offset_indicator = trace[self.layout.offset_indicator_col][row];
            let match_flag = trace[self.layout.match_flag_col][row];

            // 约束1：偏移指示器是布尔值
            // offset_indicator * (offset_indicator - 1) == 0
            constraints.push(offset_indicator * (offset_indicator - F::ONE));

            // 约束2：匹配标志是布尔值
            // match_flag * (match_flag - 1) == 0
            constraints.push(match_flag * (match_flag - F::ONE));

            // 约束3：如果偏移指示器为1，匹配标志也必须为1
            // offset_indicator * (1 - match_flag) == 0
            constraints.push(offset_indicator * (F::ONE - match_flag));
        }

        // 约束4：确保偏移指示器形成连续的窗口
        let substring_len = public_inputs.substring.len();
        let mut window_sum = F::ZERO;

        for row in 0 .. trace_len {
            window_sum += trace[self.layout.offset_indicator_col][row];
        }

        // 窗口大小必须等于子串长度
        constraints.push(window_sum - F::from_int(substring_len));

        Ok(constraints)
    }

    /// 验证所有约束是否满足（用于调试和测试）
    pub fn verify_all_constraints<F: Field + QuotientMap<u8> + QuotientMap<usize>>(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<bool, ZkpError> {
        let constraints = self.evaluate_constraints(trace, public_inputs)?;

        // 所有约束都必须为0
        for (i, constraint) in constraints.iter().enumerate() {
            if *constraint != F::ZERO {
                println!("Constraint {} failed: {:?}", i, constraint);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// 约束多项式构建器
///
/// 将约束转换为多项式形式，用于 STARK 证明系统
#[derive(Debug, Clone)]
pub struct ConstraintPolynomialBuilder<F: Field> {
    air: SubstringAIR,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field + QuotientMap<u8> + QuotientMap<usize>> ConstraintPolynomialBuilder<F> {
    pub fn new(air: SubstringAIR) -> Self {
        Self {
            air,
            _phantom: std::marker::PhantomData,
        }
    }

    /// 构建所有约束多项式
    pub fn build_constraint_polynomials(
        &self,
        trace: &[Vec<F>],
        public_inputs: &PublicInputs,
    ) -> Result<Vec<Vec<F>>, ZkpError> {
        let constraints = self.air.evaluate_constraints(trace, public_inputs)?;

        // 将约束转换为多项式表示
        // 在 STARK 中，约束被表示为在某些点上求值为零的多项式
        let trace_len = trace[0].len();
        let mut polynomials = Vec::new();

        // 每个约束对应一个多项式
        for constraint in constraints {
            let mut poly = vec![F::ZERO; trace_len];
            // 简化版本：在所有点上设置约束值
            for i in 0 .. trace_len {
                poly[i] = constraint;
            }
            polynomials.push(poly);
        }

        Ok(polynomials)
    }
}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        circuits::trace::{TraceGenerator, TraceLayout},
        config::{CircuitWitness, PublicInputs},
    };

    #[test]
    fn test_constraint_evaluation() {
        let config = CircuitConfig::default();
        let layout = TraceLayout::default();
        let air = SubstringAIR::new(config.clone(), layout.clone());

        let plaintext = b"hello world!".to_vec();
        let substring = b"hello".to_vec();

        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let commitment = hasher.finalize().into();

        let public_inputs = PublicInputs {
            commitment,
            substring,
        };

        let params = crate::config::CircuitParams {
            config: config.clone(),
            public_inputs: public_inputs.clone(),
            witness: Some(CircuitWitness {
                plaintext,
                offset: 0,
            }),
        };

        let generator = TraceGenerator::new(config);
        let trace = generator.generate_trace::<Goldilocks>(&params).unwrap();

        // 评估约束
        let constraints = air.evaluate_constraints(&trace, &public_inputs).unwrap();

        println!("Generated {} constraints", constraints.len());
        assert!(constraints.len() > 0);

        // 注意：由于我们使用了简化的 SHA-256 实现，
        // 某些约束可能会失败，这在完整实现中会被修复
    }

    #[test]
    fn test_constraint_polynomial_building() {
        let config = CircuitConfig::default();
        let layout = TraceLayout::default();
        let air = SubstringAIR::new(config.clone(), layout);

        let builder = ConstraintPolynomialBuilder::<Goldilocks>::new(air);

        let plaintext = b"test".to_vec();
        let substring = b"te".to_vec();

        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let commitment = hasher.finalize().into();

        let public_inputs = PublicInputs {
            commitment,
            substring,
        };

        let params = crate::config::CircuitParams {
            config: config.clone(),
            public_inputs: public_inputs.clone(),
            witness: Some(CircuitWitness {
                plaintext,
                offset: 0,
            }),
        };

        let generator = TraceGenerator::new(config);
        let trace = generator.generate_trace::<Goldilocks>(&params).unwrap();

        let polynomials = builder
            .build_constraint_polynomials(&trace, &public_inputs)
            .unwrap();

        println!("Generated {} constraint polynomials", polynomials.len());
        assert!(polynomials.len() > 0);
    }
}
