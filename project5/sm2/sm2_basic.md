# SM2：基本原理与基础实现

## 目录
- 概述
- SM2 推荐域参数
- 椭圆曲线数学基础（仿射坐标）
- 基本运算：点加、点倍、模逆
- 密钥生成
- 签名算法
- 验证算法
- 基础 Python 伪代码 / 示例（仿射坐标）
- 性能分析


## 概述
SM2 是基于椭圆曲线的公钥密码算法标准，常用于签名、密钥交换与公钥加密（本文件以签名/验证为主）。SM2 的签名结构与 ECDSA 有相似之处，但引入了 ZA（将用户 ID 与公钥/参数绑定的哈希值）来强化身份绑定。基础实现通常采用仿射坐标，直观但在大量算术运算中性能和抗侧信道能力较弱。

---

## SM2 推荐域参数（十六进制）
- p（素数域模）  
  `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF`
- a  
  `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC`
- b  
  `0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93`
- Gx  
  `0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7`
- Gy  
  `0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0`
- n（基点阶）  
  `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123`


## 椭圆曲线数学基础（仿射坐标）
在素数域 `Fp` 上的短 Weierstrass 曲线：

y^2 = x^3 + a*x + b (mod p)


仿射坐标两点运算公式：

- 若 P1 = O（无穷远点），P1 + P2 = P2。
- 若 x1 == x2 且 y1 == -y2 (mod p)，则和为 O。
- 否则：
  - 加法（P1 != P2）：
    ```
    s = (y2 - y1) * inv_mod(x2 - x1, p) mod p
    x3 = (s*s - x1 - x2) mod p
    y3 = (s*(x1 - x3) - y1) mod p
    ```
  - 倍点（P1 == P2 且 y1 != 0）：
    ```
    s = (3*x1*x1 + a) * inv_mod(2*y1, p) mod p
    x3 = (s*s - 2*x1) mod p
    y3 = (s*(x1 - x3) - y1) mod p
    ```

`inv_mod` 表示模逆（对素数模可以用扩展欧几里得或费马小定理）。

---

## 基本运算：点加、点倍、模逆
- **模逆（modular inverse）**：
  - 扩展欧几里得（EGCD）是通用方法。
  - 若模为素数 p，可用费马小定理：`a^(p-2) mod p`（在 Python 中用 `pow(a, p-2, p)`）。
- **实现注意**：
  - 处理无穷远点时使用 `None` 或特殊标记。
  - 所有中间运算取模 `p`。
  - 对于阶 `n` 的取模（如签名中的运算），模应为 `n` 而不是 `p`。

---

## ZA（用户标识绑定值）计算说明
ZA 将 `ID`（用户标识）、域参数与公钥绑定到摘要中，防止公钥替换攻击。计算步骤：

1. `ENTL = len(ID) * 8`（用 2 字节大端表示）。
2. 构造 `za_data = ENTL || ID || a || b || Gx || Gy || Px || Py`（每项按固定字节长度，如 32 字节大端）。
3. 对 `za_data` 做哈希（标准为 SM3；若用 SHA-256 则与标准不兼容，仅实验使用）。

---

## 密钥生成（KeyPair）
- 私钥 `d` 在 `[1, n-1]` 随机生成（必须使用 CSPRNG）。
- 公钥 `P = d * G`（标量乘）。

示例要点：
- 使用系统安全随机数（Python 用 `secrets.randbelow(n-1)+1` 或 `random.SystemRandom()`）。
- 生成后验证公钥（在曲线上且 `nP == O`）。

---

## 签名算法（逐步）
给定消息 `M`、私钥 `d`、用户 ID：
1. 计算 `ZA`，再计算 `e = Hash(ZA || M)`，将哈希结果转为大整数 `e`.
2. 随机取 `k in [1, n-1]`。
3. 计算 `(x1, y1) = k * G`。
4. `r = (e + x1) mod n`。若 `r == 0` 或 `r + k ≡ 0 (mod n)` 则重选 `k`。
5. 计算 `s = ((1 + d)^(-1) * (k - r*d)) mod n`。若 `s == 0` 则重选 `k`。
6. 输出签名 `(r, s)`。

---

## 验证算法（逐步）
给定 `M`、签名 `(r, s)`、公钥 `P`、用户 ID：
1. 检查 `1 <= r < n` 且 `1 <= s < n`，否则拒绝。
2. 计算 `ZA`，`e = Hash(ZA || M)`.
3. `t = (r + s) mod n`，若 `t == 0` 拒绝。
4. 计算点 `point = s*G + t*P`（可用 Shamir 同时乘法优化）。
5. `v = (e + x1) mod n`，其中 `x1` 为 `point` 的 x 坐标。接受当且仅当 `v == r`。

---

## 基础 Python 伪代码（仿射实现，示例）
```python
def inv_mod(a, m):
    return pow(a, m-2, m)  # 仅当 m 为素数时使用

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1,y1 = P1; x2,y2 = P2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        s = (3*x1*x1 + a) * inv_mod(2*y1 % p, p) % p
    else:
        s = (y2 - y1) * inv_mod((x2 - x1) % p, p) % p
    x3 = (s*s - x1 - x2) % p
    y3 = (s*(x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k, P):
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

