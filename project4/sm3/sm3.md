# SM3算法实现

## 1. SM3 算法介绍

### 1.1预处理阶段

预处理阶段包括 **消息填充** 和 **设置初始值 H₀** 两步。

#### 消息填充

确保填充后的消息长度是 512-bit 的整数倍。填充规则与 SHA-256 算法相同。

#### 设置初始值 H₀

H₀ 由 8 个 32-bit 字组成，具体如下：

H₀[0] = 0x7380166f <br>
H₀[1] = 0x4914b2b9<br>
H₀[2] = 0x172442d7<br>
H₀[3] = 0xda8a0600<br>
H₀[4] = 0xa96f30bc<br>
H₀[5] = 0x163138aa<br>
H₀[6] = 0xe38dee4d<br>
H₀[7] = 0xb0fb0e4e<br>

### 1.2杂凑值计算阶段

将填充后的消息分割成 `t` 个 512-bit 分组 `M₀, M₁, ..., M_{t−1}`。对每一个 `i = 0, ..., t−1`，执行以下操作：

#### 步骤 1：消息扩展

将每个 512-bit 的消息分组 `Mᵢ` 扩展为 132 个 32-bit 字：

- 首先生成 68 个字 `W₀, ..., W₆₇`：

Wⱼ = Mᵢⱼ ， 0 ≤ j ≤ 15<br>
Wⱼ = P₁(Wⱼ₋₁₆ ⊕ Wⱼ₋₉ ⊕ (Wⱼ₋₃ ≪ 15)) ⊕ (Wⱼ₋₁ ≪ 7) ⊕ Wⱼ₋₆， 16 ≤ j ≤ 67<br>
其中：<br>
P₁(x) = x ⊕ (x ≪ 15) ⊕ (x ≪ 23)

- 然后生成 64 个字 `W′₀, ..., W′₆₃`：<br>

W′ⱼ = Wⱼ ⊕ Wⱼ₊₄

#### 步骤 2：初始化 8 个寄存器

将链接变量 `Hᵢ` 赋值给 8 个 32-bit 字：

a = Hᵢ[0]<br>
b = Hᵢ[1]<br>
c = Hᵢ[2]<br>
d = Hᵢ[3]<br>
e = Hᵢ[4]<br>
f = Hᵢ[5]<br>
g = Hᵢ[6]<br>
h = Hᵢ[7]<br>
#### 步骤 3：压缩函数迭代

对 `j = 0, ..., 63`，进行如下操作：

SS1 = ((a ≪ 12) + e + (Tⱼ ≪ j)) ≪ 7<br>
SS2 = SS1 ⊕ (a ≪ 12)<br>
TT1 = FFⱼ(a, b, c) + d + SS2 + W′ⱼ<br>
TT2 = GGⱼ(e, f, g) + h + SS1 + Wⱼ<br>
<br>
d = c<br>
c = b ≪ 9<br>
b = a<br>
a = TT1<br>

h = g<br>
g = f ≪ 19<br>
f = e<br>
e = P₀(TT2)<br>

##### 常数 Tⱼ 的定义：

Tⱼ = 0x79cc4519， 0 ≤ j ≤ 15
Tⱼ = 0x7a879d8a，16 ≤ j ≤ 63
##### 函数定义：

- 设 `x, y, z` 为 32-bit 字，则：

FFⱼ(x, y, z) = <br>
x ⊕ y ⊕ z， 0 ≤ j ≤ 15<br>
(x ∧ y) ∨ (x ∧ z) ∨ (y ∧ z)， 16 ≤ j ≤ 63<br>

GGⱼ(x, y, z) =<br>
x ⊕ y ⊕ z， 0 ≤ j ≤ 15<br>
(x ∧ y) ∨ (¬x ∧ z)， 16 ≤ j ≤ 63<br>

P₀(x) = x ⊕ (x ≪ 9) ⊕ (x ≪ 17)<br>

#### 步骤 4：更新链接变量

Hᵢ₊₁[0] = a ⊕ Hᵢ[0]<br>
Hᵢ₊₁[1] = b ⊕ Hᵢ[1]<br>
Hᵢ₊₁[2] = c ⊕ Hᵢ[2]<br>
Hᵢ₊₁[3] = d ⊕ Hᵢ[3]<br>
Hᵢ₊₁[4] = e ⊕ Hᵢ[4]<br>
Hᵢ₊₁[5] = f ⊕ Hᵢ[5]<br>
Hᵢ₊₁[6] = g ⊕ Hᵢ[6]<br>
Hᵢ₊₁[7] = h ⊕ Hᵢ[7]<br>

### 最终输出

处理完所有 `t` 个消息分组后，输出最终的 256-bit 杂凑值：<br>

Hₜ[0] || Hₜ[1] || Hₜ[2] || Hₜ[3] || Hₜ[4] || Hₜ[5] || Hₜ[6] || Hₜ[7]

## 2. 算法详细描述

### 2.1 初始值
SM3算法的初始哈希值（256位）：
```
IV = 7380166F 4914B2B9 172442D7 DA8A0600
     A96F30BC 163138AA E38DEE4D B0FB0E4E
```

### 2.2 常量定义
算法中使用的常量T_j：
- 当 0 ≤ j ≤ 15 时，T_j = 79CC4519
- 当 16 ≤ j ≤ 63 时，T_j = 7A879D8A

### 2.3 布尔函数
**FF函数**：
- 当 0 ≤ j ≤ 15 时，FF_j(X,Y,Z) = X ⊕ Y ⊕ Z
- 当 16 ≤ j ≤ 63 时，FF_j(X,Y,Z) = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)

**GG函数**：
- 当 0 ≤ j ≤ 15 时，GG_j(X,Y,Z) = X ⊕ Y ⊕ Z
- 当 16 ≤ j ≤ 63 时，GG_j(X,Y,Z) = (X ∧ Y) ∨ (¬X ∧ Z)

### 2.4 置换函数
**P0置换**：P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)

**P1置换**：P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)

### 2.5 消息扩展
对每个512位消息分组，生成132个32位字：
- W0, W1, ..., W67（68个字）
- W'0, W'1, ..., W'63（64个字）

扩展规则：
- W_i = B_i（i = 0,1,...,15）
- W_i = P1(W_{i-16} ⊕ W_{i-9} ⊕ (W_{i-3} ≪ 15)) ⊕ (W_{i-13} ≪ 7) ⊕ W_{i-6}（i = 16,17,...,67）
- W'_j = W_j ⊕ W_{j+4}（j = 0,1,...,63）

## 3. 代码实现分析

### 3.1 数据结构
```c
typedef struct {
    uint32_t state[8];          // 8个32位状态字
    uint64_t count;             // 已处理的字节数
    unsigned char buffer[64];   // 输入缓冲区
} SM3_CTX;
```

### 3.2 核心函数说明

#### 3.2.1 初始化函数
```c
void sm3_init(SM3_CTX *ctx)
```
功能：初始化SM3上下文，设置初始哈希值

#### 3.2.2 更新函数
```c
void sm3_update(SM3_CTX *ctx, const unsigned char *data, size_t len)
```
功能：处理输入数据，支持流式处理

#### 3.2.3 终结函数
```c
void sm3_final(SM3_CTX *ctx, unsigned char digest[SM3_DIGEST_LENGTH])
```
功能：完成填充和最后的压缩，输出最终哈希值

#### 3.2.4 压缩函数
```c
static void sm3_compress(SM3_CTX *ctx, const unsigned char block[64])
```
功能：SM3的核心压缩函数，处理单个512位分组

### 3.3 关键实现细节

#### 3.3.1 字节序处理
SM3算法要求使用大端序（Big-Endian），实现中提供了字节序转换函数：
```c
static uint32_t load_bigendian_32(const unsigned char *x);
static void store_bigendian_32(unsigned char *x, uint32_t u);
```

#### 3.3.2 循环移位
使用宏定义实现高效的左循环移位：
```c
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
```

#### 3.3.3 消息填充
按照SM3标准进行填充：
1. 在消息后添加单个'1'位
2. 填充'0'位使消息长度≡448 (mod 512)
3. 添加64位长度信息（大端序）

## 4. api使用

### 4.1 基本使用
```c
#include "sm3.h"

int main() {
    unsigned char digest[SM3_DIGEST_LENGTH];
    const char *message = "hello world";
    
    // 直接计算哈希
    sm3_hash((unsigned char*)message, strlen(message), digest);
    
    // 打印结果
    print_hash(digest);
    return 0;
}
```

### 4.2 流式处理
```c
SM3_CTX ctx;
unsigned char digest[SM3_DIGEST_LENGTH];

sm3_init(&ctx);
sm3_update(&ctx, (unsigned char*)"hello", 5);
sm3_update(&ctx, (unsigned char*)" world", 6);
sm3_final(&ctx, digest);
```

## 5. 测试向量

### 5.1 标准测试向量
| 输入消息 | 期望输出（十六进制） |
|----------|---------------------|
| "abc" | 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 |
| "" | 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b |
| "abcd..."(64字符) | debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732 |




## 实验优化
对于大量数据的并行处理，可以考虑多线程优化方案。后续将会跟进优化实现


## 版本历史

- v1.0(2025.7.19): 初始实现版本
- 支持完整的SM3算法
- 通过标准测试向量验证
