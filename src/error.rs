use thiserror::Error;

/// 零知识证明系统的错误类型
#[derive(Error, Debug, Clone)]
pub enum ZkpError {
    /// 无效的见证（私有输入）
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// 无效的公开输入
    #[error("Invalid public input: {0}")]
    InvalidPublicInput(String),

    /// 约束不满足
    #[error("Constraint not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    /// 证明生成失败
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// 证明验证失败
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// 配置错误
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// 序列化错误
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// 内部错误
    #[error("Internal error: {0}")]
    InternalError(String),
}