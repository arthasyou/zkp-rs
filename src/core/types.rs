use serde::{Deserialize, Serialize};

/// 原始字节封装
pub type Bytes = Vec<u8>;

/// 数据承诺（通常是哈希或 Merkle 根）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub inner: Bytes,
}

/// ZKP 生成的证明
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub inner: Bytes,
}

/// 公开的声明（要证明的命题）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub commitment: Commitment,
    pub claim: Claim,
}

/// 命题的种类
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Claim {
    /// 证明原文包含某个子串
    Substring { value: String },
    // 以后可以扩展更多，比如:
    // Range { min: i64, max: i64 },
    // Regex { pattern: String },
}

/// 私密见证（证明者持有）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    pub plaintext: Bytes,
}
