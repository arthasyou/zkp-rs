use zkp_rs::circuits::substring_circuit::SubstringCircuit;
use zkp_rs::circuits::trace::TraceGenerator;
use zkp_rs::circuits::air::SubstringAIR;
use zkp_rs::circuits::Circuit;
use zkp_rs::config::{CircuitConfig, CircuitParams, PublicInputs, CircuitWitness};

use p3_goldilocks::Goldilocks;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 零知识子串包含证明演示");
    println!("============================");

    // 1. 配置电路
    let config = CircuitConfig::default();
    println!("📋 电路配置:");
    println!("  - 最大原文长度: {} 字节", config.max_text_len);
    println!("  - 最大子串长度: {} 字节", config.max_substring_len);
    println!();

    // 2. 准备测试数据
    let plaintext = b"hello world!".to_vec();
    let substring = b"hello".to_vec();
    let offset = 0;

    println!("🔐 私有输入（证明者持有）:");
    println!("  - 原文: {:?}", String::from_utf8_lossy(&plaintext));
    println!("  - 子串偏移: {}", offset);
    println!();

    // 3. 计算承诺
    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let commitment = hasher.finalize().into();

    println!("🌍 公开输入（验证者可见）:");
    println!("  - 承诺（SHA-256）: {}", hex::encode(&commitment));
    println!("  - 公开子串: {:?}", String::from_utf8_lossy(&substring));
    println!();

    // 4. 创建电路参数
    let params = CircuitParams {
        config: config.clone(),
        public_inputs: PublicInputs {
            commitment,
            substring,
        },
        witness: Some(CircuitWitness {
            plaintext,
            offset,
        }),
    };

    // 5. 生成证明
    println!("🛠️  证明生成阶段:");
    let circuit: SubstringCircuit = SubstringCircuit::new(config.clone());
    let circuit_with_field: &dyn Circuit<Goldilocks> = &circuit;
    
    println!("  - 生成计算轨迹...");
    let trace = circuit_with_field.generate_trace(&params)?;
    println!("    轨迹大小: {} 列 × {} 行", trace.len(), trace[0].len());

    println!("  - 验证约束...");
    let is_valid = circuit_with_field.verify_constraints(&trace, &params)?;
    println!("    基础约束: {}", if is_valid { "✅ 通过" } else { "❌ 失败" });

    // 6. AIR 约束验证
    println!("  - 评估 AIR 约束...");
    let trace_generator = TraceGenerator::new(config.clone());
    let layout = trace_generator.get_layout();
    let air = SubstringAIR::new(config, layout.clone());
    
    let air_valid = air.verify_all_constraints::<Goldilocks>(&trace, &params.public_inputs)?;
    println!("    AIR 约束: {}", if air_valid { "✅ 通过" } else { "❌ 失败" });
    println!("    约束数量: {}", air.num_constraints());

    println!();
    println!("🎯 演示结果:");
    if is_valid && air_valid {
        println!("  ✅ 电路设计验证成功！");
        println!("  ✅ 子串 \"hello\" 确实包含在原文中");
        println!("  ✅ 哈希承诺验证通过");
        println!("  ✅ 所有约束满足");
    } else {
        println!("  ❌ 验证失败，请检查电路实现");
    }

    println!();
    println!("📝 注意事项:");
    println!("  - 这是一个简化的演示实现");
    println!("  - 完整的 STARK 证明生成需要集成 p3-uni-stark");
    println!("  - SHA-256 约束使用了简化版本，生产环境需要完整实现");
    
    Ok(())
}