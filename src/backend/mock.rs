use crate::core::{Claim, Proof, Prove, Statement, Witness};

/// 一个假的 Prover 实现：
/// - prove: 把 claim + witness 拼接成一个假的 proof
/// - verify: 检查 witness 是否满足 claim
pub struct MockProver;

impl Prove for MockProver {
    fn prove(&self, statement: &Statement, witness: &Witness) -> Proof {
        let mut proof_data = Vec::new();

        // 把 claim 序列化成字符串放入 proof
        match &statement.claim {
            Claim::Substring { value } => {
                proof_data.extend_from_slice(value.as_bytes());
            }
        }

        // 再加上 witness 的原文
        proof_data.extend_from_slice(&witness.plaintext);

        Proof { inner: proof_data }
    }

    fn verify(&self, statement: &Statement, proof: &Proof) -> bool {
        match &statement.claim {
            Claim::Substring { value } => {
                // 验证逻辑：witness 原文包含了 claim.value
                // 这里简单地从 proof 中恢复 witness 并检查
                String::from_utf8_lossy(&proof.inner).contains(value)
            }
        }
    }
}
