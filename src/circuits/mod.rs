pub mod substring_circuit;
pub mod trace;
pub mod air;

use crate::config::{CircuitConfig, CircuitParams};
use crate::error::ZkpError;
use p3_field::Field;

/// 电路接口定义
pub trait Circuit<F: Field> {
    /// 生成计算轨迹（execution trace）
    fn generate_trace(&self, params: &CircuitParams) -> Result<Vec<Vec<F>>, ZkpError>;
    
    /// 验证约束是否满足
    fn verify_constraints(&self, trace: &[Vec<F>], params: &CircuitParams) -> Result<bool, ZkpError>;
    
    /// 获取电路配置
    fn get_config(&self) -> CircuitConfig;
}