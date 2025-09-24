use std::time::Instant;

use p3_goldilocks::Goldilocks;
use sha2::{Digest, Sha256};
use zkp_rs::{
    circuits::{
        Circuit, air::SubstringAIR, substring_circuit::SubstringCircuit, trace::TraceGenerator,
    },
    config::{CircuitConfig, CircuitParams, CircuitWitness, PublicInputs},
    error::ZkpError,
};

/// 完整的子串包含证明示例
///
/// 演示如何使用零知识电路证明 "hello world" 作为公开信息
/// 属于更长原文的一部分，且不泄露原文的其他内容
fn main() -> Result<(), ZkpError> {
    println!("🚀 零知识子串包含证明演示");
    println!("=====================================");

    // 1. 设置电路配置
    let config = CircuitConfig {
        max_text_len: 128,             // 支持更长的原文
        max_substring_len: 32,         // 支持更长的子串
        enable_multi_block_sha: false, // MVP版本使用单块
    };

    println!("📋 电路配置:");
    println!("  - 最大原文长度: {} 字节", config.max_text_len);
    println!("  - 最大子串长度: {} 字节", config.max_substring_len);
    println!("  - 多块SHA支持: {}", config.enable_multi_block_sha);
    println!();

    // 2. 准备测试数据
    run_hello_world_example(&config)?;
    run_complex_example(&config)?;
    run_failure_example(&config)?;

    println!("✅ 所有测试完成！");
    Ok(())
}

/// 基础示例：证明 "hello" 属于 "hello world!"
fn run_hello_world_example(config: &CircuitConfig) -> Result<(), ZkpError> {
    println!("📌 示例1: 基础子串证明");
    println!("--------------------");

    let start = Instant::now();

    // 原文和要证明的子串
    let plaintext = b"hello world!".to_vec();
    let substring = b"hello".to_vec();
    let offset = 0; // "hello" 在开头

    println!("🔐 私有输入（证明者持有）:");
    println!("  - 原文: {:?}", String::from_utf8_lossy(&plaintext));
    println!("  - 子串偏移: {}", offset);

    // 计算承诺（SHA-256哈希）
    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let commitment = hasher.finalize().into();

    println!("🌍 公开输入（所有人可见）:");
    println!("  - 承诺（SHA-256）: {}", hex::encode(&commitment));
    println!("  - 公开子串: {:?}", String::from_utf8_lossy(&substring));

    // 创建电路参数
    let params = CircuitParams {
        config: config.clone(),
        public_inputs: PublicInputs {
            commitment,
            substring: substring.clone(),
        },
        witness: Some(CircuitWitness { plaintext, offset }),
    };

    // 3. 生成证明（证明者侧）
    println!("\n🛠️  证明生成阶段:");
    let circuit = SubstringCircuit::new(config.clone());

    println!("  - 生成计算轨迹...");
    let trace_start = Instant::now();
    let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
    let trace = circuit_typed.generate_trace(&params)?;
    println!("    轨迹大小: {} 列 × {} 行", trace.len(), trace[0].len());
    println!("    耗时: {:?}", trace_start.elapsed());

    println!("  - 验证约束...");
    let constraint_start = Instant::now();
    let is_valid = circuit_typed.verify_constraints(&trace, &params)?;
    println!(
        "    约束验证: {}",
        if is_valid { "✅ 通过" } else { "❌ 失败" }
    );
    println!("    耗时: {:?}", constraint_start.elapsed());

    // 4. AIR 约束评估
    println!("  - 评估 AIR 约束...");
    let trace_generator = TraceGenerator::new(config.clone());
    let layout = trace_generator.get_layout();
    let air = SubstringAIR::new(config.clone(), layout.clone());

    let air_start = Instant::now();
    let air_valid = air.verify_all_constraints(&trace, &params.public_inputs)?;
    println!(
        "    AIR 约束: {}",
        if air_valid {
            "✅ 通过"
        } else {
            "❌ 失败"
        }
    );
    println!("    约束数量: {}", air.num_constraints());
    println!("    耗时: {:?}", air_start.elapsed());

    println!("⏱️  总耗时: {:?}", start.elapsed());
    println!();

    Ok(())
}

/// 复杂示例：证明子串在中间位置
fn run_complex_example(config: &CircuitConfig) -> Result<(), ZkpError> {
    println!("📌 示例2: 中间位置子串证明");
    println!("----------------------");

    let start = Instant::now();

    let plaintext = b"This is a demonstration sentence that includes the phrase hello world for testing purposes.".to_vec();
    let substring = b"hello world".to_vec();
    let offset = 70; // "hello world" 在中间位置

    println!("🔐 私有输入:");
    println!("  - 原文长度: {} 字节", plaintext.len());
    println!(
        "  - 原文预览: {:?}...{:?}",
        String::from_utf8_lossy(&plaintext[.. 20]),
        String::from_utf8_lossy(&plaintext[plaintext.len() - 20 ..])
    );
    println!("  - 子串偏移: {}", offset);

    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let commitment = hasher.finalize().into();

    println!("🌍 公开输入:");
    println!("  - 承诺: {}", hex::encode(&commitment));
    println!("  - 公开子串: {:?}", String::from_utf8_lossy(&substring));

    let params = CircuitParams {
        config: config.clone(),
        public_inputs: PublicInputs {
            commitment,
            substring,
        },
        witness: Some(CircuitWitness { plaintext, offset }),
    };

    let circuit = SubstringCircuit::new(config.clone());
    let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
    let trace = circuit_typed.generate_trace(&params)?;
    let is_valid = circuit_typed.verify_constraints(&trace, &params)?;

    println!(
        "\n🛠️  证明结果: {}",
        if is_valid { "✅ 成功" } else { "❌ 失败" }
    );
    println!("⏱️  耗时: {:?}", start.elapsed());
    println!();

    Ok(())
}

/// 失败示例：尝试证明不存在的子串
fn run_failure_example(config: &CircuitConfig) -> Result<(), ZkpError> {
    println!("📌 示例3: 负面测试（应该失败）");
    println!("-------------------------");

    let start = Instant::now();

    let plaintext = b"hello world!".to_vec();
    let fake_substring = b"goodbye".to_vec(); // 不存在的子串
    let offset = 0;

    println!("🔐 私有输入:");
    println!("  - 原文: {:?}", String::from_utf8_lossy(&plaintext));
    println!(
        "  - 尝试证明不存在的子串: {:?}",
        String::from_utf8_lossy(&fake_substring)
    );

    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let commitment = hasher.finalize().into();

    let params = CircuitParams {
        config: config.clone(),
        public_inputs: PublicInputs {
            commitment,
            substring: fake_substring,
        },
        witness: Some(CircuitWitness { plaintext, offset }),
    };

    let circuit = SubstringCircuit::new(config.clone());
    let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
    let trace = circuit_typed.generate_trace(&params)?;
    let is_valid = circuit_typed.verify_constraints(&trace, &params)?;

    println!(
        "\n🛠️  证明结果: {}",
        if is_valid {
            "❌ 意外成功（BUG！）"
        } else {
            "✅ 正确失败"
        }
    );
    println!("⏱️  耗时: {:?}", start.elapsed());
    println!();

    Ok(())
}

/// 性能基准测试
#[allow(dead_code)]
fn run_benchmark(config: &CircuitConfig) -> Result<(), ZkpError> {
    println!("📊 性能基准测试");
    println!("==============");

    let iterations = 10;
    let mut total_time = std::time::Duration::new(0, 0);

    for i in 0 .. iterations {
        let plaintext = format!("Test message number {} with some content", i).into_bytes();
        let substring = b"message".to_vec();
        let offset = plaintext.iter().position(|&b| b == b'm').unwrap_or(0);

        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let commitment = hasher.finalize().into();

        let params = CircuitParams {
            config: config.clone(),
            public_inputs: PublicInputs {
                commitment,
                substring,
            },
            witness: Some(CircuitWitness { plaintext, offset }),
        };

        let start = Instant::now();
        let circuit = SubstringCircuit::new(config.clone());
        let circuit_typed: &dyn Circuit<Goldilocks> = &circuit;
        let trace = circuit_typed.generate_trace(&params)?;
        let _is_valid = circuit_typed.verify_constraints(&trace, &params)?;
        let elapsed = start.elapsed();

        total_time += elapsed;
        println!("  第 {} 次: {:?}", i + 1, elapsed);
    }

    println!("📈 基准结果:");
    println!("  - 总耗时: {:?}", total_time);
    println!("  - 平均耗时: {:?}", total_time / iterations);
    println!(
        "  - 吞吐量: {:.2} 证明/秒",
        iterations as f64 / total_time.as_secs_f64()
    );

    Ok(())
}
