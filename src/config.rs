use serde::{Deserialize, Serialize};

/// 电路配置参数
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// 原文最大长度（字节）
    pub max_text_len: usize,
    /// 子串最大长度（字节） 
    pub max_substring_len: usize,
    /// 是否启用多块 SHA-256 支持
    pub enable_multi_block_sha: bool,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            // MVP: 单块 SHA-256，原文不超过55字节
            max_text_len: 55,
            max_substring_len: 32,
            enable_multi_block_sha: false,
        }
    }
}

/// 电路公开输入参数
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputs {
    /// 原文的 SHA-256 承诺（32字节）
    pub commitment: [u8; 32],
    /// 要证明的公开子串
    pub substring: Vec<u8>,
}

/// 电路私有输入参数（见证）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitWitness {
    /// 完整的原文（UTF-8字节）
    pub plaintext: Vec<u8>,
    /// 子串在原文中的偏移位置
    pub offset: usize,
}

/// 电路参数集合
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitParams {
    pub config: CircuitConfig,
    pub public_inputs: PublicInputs,
    pub witness: Option<CircuitWitness>, // 验证时为 None
}