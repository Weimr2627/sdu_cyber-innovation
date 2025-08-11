import random
import hashlib
from typing import List, Tuple, Set, Dict


class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"



def print_separator(title: str, color=Color.CYAN):
    """打印分隔线与标题"""
    print(f"\n{color}" + "="*70)
    print(f"{Color.BOLD}[{title}]{Color.RESET}{color}".center(70))
    print("-"*70 + Color.RESET)

def print_table(headers: List[str], rows: List[List[str]], max_width: int = 18, 
               header_color=Color.GREEN, row_colors=[Color.RESET, Color.YELLOW]):
    """打印格式化表格，支持交替行颜色"""
    # 计算每列最大宽度
    col_widths = []
    for i in range(len(headers)):
        max_len = len(headers[i])
        for row in rows:
            if len(row[i]) > max_len:
                max_len = len(row[i])
        col_widths.append(min(max_len + 2, max_width))  # 限制最大宽度
    
    # 打印表头
    header_line = "|".join([headers[i].ljust(col_widths[i]) for i in range(len(headers))])
    print(f"{header_color}|{header_line}|{Color.RESET}")
    
    # 打印分隔线
    sep_line = "|".join(["-"*col_widths[i] for i in range(len(headers))])
    print(f"{Color.BLUE}|{sep_line}|{Color.RESET}")
    
    # 打印行（交替颜色）
    for idx, row in enumerate(rows):
        row_color = row_colors[idx % len(row_colors)]
        row_line = "|".join([row[i].ljust(col_widths[i]) for i in range(len(headers))])
        print(f"{row_color}|{row_line}|{Color.RESET}")

def print_info(message: str, color=Color.BLUE):
    """打印信息性消息"""
    print(f"{color}ℹ️ {message}{Color.RESET}")

def print_success(message: str):
    """打印成功消息"""
    print(f"{Color.GREEN}✅ {message}{Color.RESET}")

def print_step(step_num: int, message: str):
    """打印步骤信息"""
    print(f"\n{Color.PURPLE}{Color.BOLD}步骤 {step_num}:{Color.RESET} {message}")

# ------------------------------
# 协议参数与基础工具函数
# ------------------------------

def init_protocol(p: int = None, g: int = None) -> Dict[str, int]:
    """初始化协议参数"""
    if p is None:
        p = 2147483647  # 大质数 (2^31 - 1)
    if g is None:
        g = 2  # 生成元
    return {"p": p, "g": g}

def hash_to_group(identifier: str, p: int) -> int:
    """将标识符哈希到循环群元素"""
    hash_bytes = hashlib.sha256(identifier.encode()).digest()
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    return hash_int % p

def mod_pow(base: int, exp: int, mod: int) -> int:
    """高效模幂运算: (base^exp) mod mod"""
    return pow(base, exp, mod)

def generate_private_key(p: int) -> int:
    """生成私有密钥（群中的随机元素）"""
    return random.randint(1, p - 2)

# ------------------------------
# 加法同态加密函数
# ------------------------------

def generate_he_keypair() -> Tuple[int, int, Dict]:
    """生成同态加密的公私钥对，并返回密钥信息"""
    private_key = random.randint(10000, 99999)
    public_key = private_key * 3 + 1  # 简单的密钥生成
    key_info = {
        "类型": "加法同态加密",
        "公钥": public_key,
        "私钥": private_key,
        "说明": "公钥用于加密，私钥用于解密"
    }
    return public_key, private_key, key_info

def he_encrypt(plaintext: int, public_key: int) -> Tuple[int, Dict]:
    """同态加密，返回密文和加密信息"""
    noise = random.randint(1, 50)
    ciphertext = (plaintext * public_key + noise) % (10**12)
    encrypt_info = {
        "明文": plaintext,
        "噪声": noise,
        "密文": ciphertext,
        "公式": f"{plaintext} * {public_key} + {noise} mod 1e12"
    }
    return ciphertext, encrypt_info

def he_decrypt(ciphertext: int, public_key: int, private_key: int) -> Tuple[int, Dict]:
    """同态解密，返回明文和解密信息"""
    plaintext = (ciphertext // public_key) % (10**8)
    decrypt_info = {
        "密文": ciphertext,
        "明文": plaintext,
        "公式": f"{ciphertext} // {public_key} mod 1e8"
    }
    return plaintext, decrypt_info

def he_add(c1: int, c2: int) -> Tuple[int, Dict]:
    """同态加法，返回结果和加法信息"""
    result = (c1 + c2) % (10**12)
    add_info = {
        "密文1": c1,
        "密文2": c2,
        "结果": result,
        "公式": f"{c1} + {c2} mod 1e12"
    }
    return result, add_info

# ------------------------------
# 参与方1的操作函数
# ------------------------------

def party1_round1(identifiers: Set[str], p: int, g: int) -> Tuple[List[int], int, Dict[str, int], List[Dict]]:
    """参与方1第一轮操作"""
    print_separator("参与方1 - 第一轮处理")
    k1 = generate_private_key(p)
    print_info(f"参与方1生成私有密钥: k1 = {k1}")
    print_info(f"处理逻辑: 对每个标识符计算 H(vi)^k1 mod {p}")
    
    mapped = {}
    result = []
    details = []
    
    for iden in identifiers:
        h = hash_to_group(iden, p)
        val = mod_pow(h, k1, p)
        mapped[iden] = val
        
        # 只显示哈希值的前8位，避免过长
        h_short = f"{h:,}"[:8] + "..." if h > 1e8 else h
        val_short = f"{val:,}"[:8] + "..." if val > 1e8 else val
        
        details.append({
            "标识符": iden,
            "哈希值H(vi)": h_short,
            "计算后H(vi)^k1": val_short,
            "公式": f"H({iden})^{k1} mod {p}"
        })
        result.append(val)
    
    # 打印处理详情表格
    headers = ["标识符", "哈希值H(vi)", "计算后H(vi)^k1", "公式"]
    rows = [[str(d[h]) for h in headers] for d in details]
    print_table(headers, rows)
    
    random.shuffle(result)  # 打乱顺序保护隐私
    print_info(f"打乱后发送给参与方2的数据: [{', '.join([f'{x:,}'[:6]+'...' for x in result[:3]])}, ...]")
    return result, k1, mapped, details

def party1_round3(round2_data: List[Tuple[int, int, Dict]], 
                 k1: int, 
                 p: int, 
                 party1_mapped: Dict[str, int]) -> Tuple[int, List[Dict]]:
    """参与方1第三轮操作: 计算交集并求和"""
    print_separator("参与方1 - 第三轮处理")
    # 构建参与方1的元素集合
    party1_elements = set(party1_mapped.values())
    print_info(f"参与方1元素集合大小: {len(party1_elements)} 个元素")
    print_info(f"处理逻辑: 计算 H(wj)^(k1*k2) 并检查是否在本地集合中")
    
    encrypted_sum = 0
    count = 0
    details = []
    sum_details = []
    
    for idx, (h_wj_k2, enc_tj, enc_info) in enumerate(round2_data):
        # 计算 H(wj)^(k1*k2)
        h_wj_k1k2 = mod_pow(h_wj_k2, k1, p)
        
        # 显示简化的值
        h_wj_k2_short = f"{h_wj_k2:,}"[:8] + "..." if h_wj_k2 > 1e8 else h_wj_k2
        h_wj_k1k2_short = f"{h_wj_k1k2:,}"[:8] + "..." if h_wj_k1k2 > 1e8 else h_wj_k1k2
        
        # 检查是否在交集中
        in_intersection = h_wj_k1k2 in party1_elements
        details.append({
            "序号": idx + 1,
            "H(wj)^k2": h_wj_k2_short,
            "计算后H(wj)^(k1*k2)": h_wj_k1k2_short,
            "是否在交集中": f"{Color.GREEN}是{Color.RESET}" if in_intersection else f"{Color.RED}否{Color.RESET}",
            "对应加密值": enc_info["密文"]
        })
        
        if in_intersection:
            count += 1
            sum_details.append({
                "操作": f"添加第{count}个元素",
                "值": enc_tj,
                "累计和": encrypted_sum if encrypted_sum != 0 else "初始值"
            })
            
            if encrypted_sum == 0:
                encrypted_sum = enc_tj
            else:
                encrypted_sum, add_info = he_add(encrypted_sum, enc_tj)
                sum_details[-1]["加法详情"] = f"{add_info['密文1']:,} + {add_info['密文2']:,} = {add_info['结果']:,}"
    
    # 打印交集检查表格
    headers = ["序号", "H(wj)^k2", "计算后H(wj)^(k1*k2)", "是否在交集中", "对应加密值"]
    rows = [[str(d[h]) for h in headers] for d in details]
    print_table(headers, rows)
    
    # 打印求和过程
    print("\n" + "-"*50)
    print(f"{Color.BOLD}交集元素求和过程:{Color.RESET}")
    sum_headers = ["操作", "值", "累计和", "加法详情"] if len(sum_details) > 0 and "加法详情" in sum_details[0] else ["操作", "值", "累计和"]
    sum_rows = []
    for d in sum_details:
        row = [str(d[h]) for h in sum_headers if h in d]
        sum_rows.append(row)
    print_table(sum_headers, sum_rows, row_colors=[Color.CYAN, Color.RESET])
    
    print_success(f"参与方1: 找到 {count} 个交集元素，加密总和 = {encrypted_sum:,}")
    return encrypted_sum, details

# ------------------------------
# 参与方2的操作函数
# ------------------------------

def party2_round2(party1_data: List[int], 
                 pairs: List[Tuple[str, int]], 
                 p: int, g: int, 
                 public_key: int) -> Tuple[List[Tuple[int, int, Dict]], int, List[Dict]]:
    """参与方2第二轮操作"""
    print_separator("参与方2 - 第二轮处理")
    k2 = generate_private_key(p)
    print_info(f"参与方2生成私有密钥: k2 = {k2}")
    print_info(f"处理逻辑1: 对参与方1的数据计算 H(vi)^(k1*k2) mod {p} (本地验证)")
    print_info(f"处理逻辑2: 对自己的键值对计算 H(wj)^k2 mod {p} 并加密值")
    
    # 处理参与方1的数据（仅本地验证，不传输）
    processed_p1 = []
    for idx, h_vi_k1 in enumerate(party1_data[:3]):  # 只显示前3个
        val = mod_pow(h_vi_k1, k2, p)
        val_short = f"{val:,}"[:8] + "..." if val > 1e8 else val
        processed_p1.append({
            "序号": idx + 1,
            "接收值H(vi)^k1": f"{h_vi_k1:,}"[:8] + "...",
            "计算后H(vi)^(k1*k2)": val_short
        })
    
    # 打印参与方1数据处理表格
    headers_p1 = ["序号", "接收值H(vi)^k1", "计算后H(vi)^(k1*k2)"]
    rows_p1 = [[str(d[h]) for h in headers_p1] for d in processed_p1]
    print("\n参与方1数据处理 (前3项):")
    print_table(headers_p1, rows_p1)
    
    # 处理参与方2自己的数据
    result = []
    details = []
    for wj, tj in pairs:
        h_wj = hash_to_group(wj, p)
        h_wj_k2 = mod_pow(h_wj, k2, p)
        enc_tj, enc_info = he_encrypt(tj, public_key)
        
        # 显示简化的值
        h_wj_short = f"{h_wj:,}"[:8] + "..." if h_wj > 1e8 else h_wj
        h_wj_k2_short = f"{h_wj_k2:,}"[:8] + "..." if h_wj_k2 > 1e8 else h_wj_k2
        
        details.append({
            "标识符": wj,
            "值tj": tj,
            "哈希值H(wj)": h_wj_short,
            "计算后H(wj)^k2": h_wj_k2_short,
            "加密值": enc_info["密文"]
        })
        result.append((h_wj_k2, enc_tj, enc_info))
    
    # 打印参与方2数据处理表格
    headers_p2 = ["标识符", "值tj", "哈希值H(wj)", "计算后H(wj)^k2", "加密值"]
    rows_p2 = [[str(d[h]) for h in headers_p2] for d in details]
    print("\n参与方2数据处理:")
    print_table(headers_p2, rows_p2)
    
    random.shuffle(result)  # 打乱顺序保护隐私
    print_info(f"打乱后发送给参与方1的数据: [{', '.join([f'({x[0]:,}'[:6]+'..., ...)' for x in result[:3]])}, ...]")
    return result, k2, details

# ------------------------------
# 协议执行函数
# ------------------------------

def run_protocol(party1_ids: Set[str], 
                party2_pairs: List[Tuple[str, int]], 
                protocol_params: Dict[str, int]) -> int:
    """执行完整的私有交集求和协议，带优化可视化输出"""
    p = protocol_params["p"]
    g = protocol_params["g"]
    
    print_separator("协议初始化", Color.PURPLE)
    print(f"{Color.BOLD}协议参数:{Color.RESET} 质数p = {p}, 生成元g = {g}")
    print(f"{Color.BOLD}参与方1数据:{Color.RESET} {sorted(party1_ids)} (共{len(party1_ids)}个标识符)")
    print(f"{Color.BOLD}参与方2数据:{Color.RESET} {[f'({w},{t})' for w,t in party2_pairs]} (共{len(party2_pairs)}个键值对)")
    
    # 计算预期结果
    intersection = [w for w,t in party2_pairs if w in party1_ids]
    expected_sum = sum([t for w,t in party2_pairs if w in party1_ids])
    print(f"{Color.BOLD}预期交集:{Color.RESET} {intersection}")
    print(f"{Color.BOLD}预期结果:{Color.RESET} {expected_sum}")
    
    # 步骤1: 参与方2生成同态加密密钥对
    print_step(1, "生成同态加密密钥对")
    he_pub, he_priv, key_info = generate_he_keypair()
    key_headers = ["类型", "公钥", "私钥", "说明"]
    key_rows = [[str(key_info[h]) for h in key_headers]]
    print_table(key_headers, key_rows)
    
    # 步骤2: 参与方1执行第一轮操作
    print_step(2, "参与方1执行第一轮计算")
    party1_data, k1, party1_mapped, party1_details = party1_round1(party1_ids, p, g)
    
    # 步骤3: 参与方2执行第二轮操作
    print_step(3, "参与方2执行第二轮计算")
    party2_data, k2, party2_details = party2_round2(party1_data, party2_pairs, p, g, he_pub)
    
    # 步骤4: 参与方1执行第三轮操作
    print_step(4, "参与方1计算加密的交集和")
    encrypted_sum, round3_details = party1_round3(party2_data, k1, p, party1_mapped)
    
    # 步骤5: 参与方2解密结果
    print_step(5, "参与方2解密最终结果")
    final_sum, decrypt_info = he_decrypt(encrypted_sum, he_pub, he_priv)
    decrypt_headers = ["密文", "明文", "公式"]
    decrypt_rows = [[str(decrypt_info[h]) for h in decrypt_headers]]
    print_table(decrypt_headers, decrypt_rows)
    
    return final_sum

# ------------------------------
# 示例运行
# ------------------------------

if __name__ == "__main__":
    print(f"{Color.BOLD}=== 基于DDH的私有交集求和协议==={Color.RESET}")
    
    # 初始化协议参数
    params = init_protocol()
    
    # 参与方数据
    party1_identifiers = {"alice", "bob", "charlie", "david", "eve"}
    party2_pairs = [
        ("alice", 10), ("bob", 20), ("frank", 15),
        ("charlie", 30), ("grace", 25)
    ]
    
    # 执行协议
    result = run_protocol(party1_identifiers, party2_pairs, params)
    
    print_separator("协议结果总结", Color.GREEN)
    print(f"{Color.BOLD}{Color.GREEN}最终计算得到的交集元素总和: {result}{Color.RESET}")
    print_success("协议执行完成")
