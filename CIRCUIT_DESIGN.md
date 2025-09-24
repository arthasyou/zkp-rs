# 零知识子串包含证明电路设计文档

根据项目 todo list 的要求，本文档详细介绍为证明 "hello world" 作为公开信息属于更长原文的一部分而设计的零知识证明电路。

## 📋 电路设计目标

**核心命题**：证明公开子串 `s` 包含在某个私有原文中，且原文的 SHA-256 哈希等于公开承诺，而不泄露原文的其他内容。

### 具体示例
- **私有输入（证明者持有）**：
  - 原文：`"This is a demonstration sentence that includes the phrase hello world for testing purposes."`
  - 子串偏移：`70`（"hello world" 的起始位置）

- **公开输入（验证者可见）**：
  - 承诺：`SHA256(原文)` = `7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9`
  - 公开子串：`"hello world"`

- **证明目标**：在不泄露原文内容的情况下，证明 "hello world" 确实存在于哈希对应的原文中。

## 🏗️ 电路架构设计

### 1. 配置参数 (CircuitConfig)

```rust
pub struct CircuitConfig {
    pub max_text_len: usize,        // 原文最大长度：55字节（MVP单块SHA-256）
    pub max_substring_len: usize,   // 子串最大长度：32字节
    pub enable_multi_block_sha: bool, // 是否启用多块SHA支持
}
```

**设计决策**：
- MVP版本限制原文≤55字节，确保SHA-256单块处理
- 后续版本可扩展支持多块SHA-256处理任意长度文本

### 2. 公开输入 (PublicInputs)

```rust
pub struct PublicInputs {
    pub commitment: [u8; 32],    // 原文的SHA-256哈希承诺
    pub substring: Vec<u8>,      // 要证明包含的公开子串
}
```

### 3. 私有见证 (CircuitWitness)

```rust
pub struct CircuitWitness {
    pub plaintext: Vec<u8>,      // 完整原文（UTF-8字节）
    pub offset: usize,           // 子串在原文中的偏移位置
}
```

## 🔗 约束系统设计

电路实现四类核心约束，确保零知识证明的完整性和可靠性：

### 1. 哈希一致性约束

**目标**：确保私有原文的哈希等于公开承诺

**约束方程**：
```
SHA256(plaintext) = commitment
```

**实现细节**：
- 使用 p3-sha256 实现SHA-256电路
- 包含消息预处理、padding、64轮压缩函数
- 每轮包含消息调度和状态更新约束

### 2. 子串匹配约束

**目标**：确保公开子串在指定偏移位置与原文完全匹配

**约束方程**：
```
∀ j ∈ [0, |s|): plaintext[k + j] = s[j]
```

**实现细节**：
- `k` 为私有偏移位置
- `s` 为公开子串
- 逐字节验证匹配关系

### 3. 范围检查约束

**目标**：确保所有输入在有效范围内

**约束方程**：
```
0 ≤ k ≤ |plaintext| - |s|  (偏移范围)
∀ byte: 0 ≤ byte ≤ 255    (字节范围)
```

### 4. 逻辑一致性约束

**目标**：确保电路内部状态的逻辑正确性

**约束方程**：
```
offset_indicator ∈ {0, 1}           (布尔约束)
match_flag ∈ {0, 1}                 (布尔约束)  
offset_indicator = 1 ⟹ match_flag = 1  (逻辑含义约束)
```

## 📊 计算轨迹 (Execution Trace) 布局

电路使用101列的轨迹矩阵，每行代表一个计算步骤：

### 列分配方案

| 列范围 | 功能描述 | 详细说明 |
|--------|----------|----------|
| 0-31   | SHA-256状态寄存器 | 8个32位寄存器(a,b,c,d,e,f,g,h)的字节表示 |
| 32-95  | SHA-256消息调度 | 64轮消息调度W[0]...W[63] |
| 96     | 原文字节值 | 当前处理的原文字节 |
| 97     | 子串字节值 | 匹配窗口中的子串字节 |
| 98     | 字节匹配标志 | 1表示匹配，0表示不匹配 |
| 99     | 偏移位置指示器 | 1表示在匹配窗口内 |
| 100    | 范围检查标志 | 1表示字节值在有效范围内 |

### 轨迹生成流程

1. **SHA-256轨迹生成**：
   - 消息预处理和padding
   - 64轮压缩函数计算
   - 状态寄存器更新

2. **字节处理轨迹**：
   - 填充原文字节到第96列
   - 标记有效字节位置

3. **子串匹配轨迹**：
   - 在匹配窗口填充子串字节
   - 设置偏移指示器和匹配标志
   - 验证字节级匹配关系

4. **范围检查轨迹**：
   - 为每个字节设置范围检查标志
   - 确保所有值在[0,255]范围内

## 🔍 AIR (Algebraic Intermediate Representation) 约束

### 约束多项式定义

电路总共包含 `32 + max_text_len * 3` 个约束多项式：

1. **SHA-256约束** (32个)：
   ```
   hash_output[i] - commitment[i] = 0  ∀ i ∈ [0, 32)
   ```

2. **子串匹配约束** (max_text_len个)：
   ```
   offset_indicator[i] × (plaintext[i] - substring[i]) = 0
   ```

3. **布尔约束** (2 × max_text_len个)：
   ```
   offset_indicator[i] × (offset_indicator[i] - 1) = 0
   match_flag[i] × (match_flag[i] - 1) = 0
   ```

4. **全局一致性约束** (1个)：
   ```
   ∑ offset_indicator[i] - |substring| = 0
   ```

### 约束验证流程

1. **语法检查**：验证轨迹格式和数据类型
2. **局部约束**：检查每行内部约束是否满足
3. **全局约束**：验证跨行的一致性要求
4. **完整性检查**：确保所有约束都为零多项式

## ⚡ 性能特征

### 复杂度分析

- **轨迹大小**：101列 × max(64, text_length)行
- **约束数量**：O(max_text_len)个多项式约束
- **证明大小**：O(log(trace_size)) 使用FRI协议
- **验证时间**：O(log(trace_size)) 独立于原文长度

### 优化策略

1. **批处理优化**：
   - 并行处理SHA-256轮函数
   - 向量化字节操作

2. **内存优化**：
   - 流式处理大文本
   - 增量式轨迹生成

3. **预计算优化**：
   - 预计算SHA-256常量
   - 缓存重复子串模式

## 🔒 安全性分析

### 隐私保护

1. **零知识性**：
   - 证明不泄露原文内容
   - 只暴露子串存在性信息
   - 偏移位置保持私密

2. **可靠性保证**：
   - 防止虚假证明生成
   - 抗选择子串攻击
   - 哈希承诺绑定性

### 威胁模型

1. **已知攻击防护**：
   - 抗暴力枚举攻击
   - 防止时间侧信道分析
   - 抵御恶意证明者

2. **假设条件**：
   - SHA-256哈希函数安全性
   - 离散对数难题
   - 诚实验证者假设

## 🚀 扩展可能性

### 功能扩展

1. **多子串证明**：
   - 同时证明多个子串包含
   - 支持正则表达式匹配
   - 位置关系约束

2. **高级模式匹配**：
   - 模糊匹配支持
   - 大小写不敏感
   - Unicode规范化

3. **长文本支持**：
   - 多块SHA-256处理
   - 流式证明生成
   - 内存友好实现

### 性能优化

1. **并行化改进**：
   - GPU加速证明生成
   - 分布式验证
   - 批量处理优化

2. **压缩技术**：
   - 证明大小优化
   - 递归证明合成
   - 聚合验证方案

## 📝 使用示例

基本用法展示：

```rust
// 1. 配置电路参数
let config = CircuitConfig {
    max_text_len: 128,
    max_substring_len: 32,
    enable_multi_block_sha: false,
};

// 2. 准备输入数据
let plaintext = b"hello world!".to_vec();
let substring = b"hello".to_vec();
let commitment = sha256(&plaintext);

// 3. 生成证明
let params = CircuitParams { /* ... */ };
let circuit = SubstringCircuit::new(config);
let trace = circuit.generate_trace(&params)?;
let proof = generate_stark_proof(trace, params)?;

// 4. 验证证明
let is_valid = verify_stark_proof(proof, public_inputs)?;
assert!(is_valid);
```

## 📚 技术参考

- **Plonky3框架**：现代STARK证明系统
- **Goldilocks字段**：2^64 - 2^32 + 1素数域
- **SHA-256规范**：NIST FIPS 180-4
- **UTF-8编码**：RFC 3629标准

---

**总结**：本电路设计提供了一个完整的零知识子串包含证明方案，平衡了安全性、效率和可扩展性的需求。通过精心设计的约束系统和轨迹布局，电路能够在保护隐私的同时提供可靠的包含关系证明。