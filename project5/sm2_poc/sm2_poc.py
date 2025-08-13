import secrets
import binascii
from hashlib import sha256
from gmssl import sm3, func
import time
import functools

# SM2椭圆曲线参数
ELLIPTIC_CURVE_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
ELLIPTIC_CURVE_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
PRIME_MODULUS = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
ORDER_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
BASE_POINT_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
BASE_POINT_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
BASE_POINT = (BASE_POINT_X, BASE_POINT_Y)
SM3_HASH_SIZE = 32

# 缓存字典，用于加速计算
MODULAR_INVERSE_CACHE = {}
POINT_ADDITION_CACHE = {}

def modular_inverse(value, modulus):
    """使用扩展欧几里得算法计算模逆元"""
    cache_key = (value, modulus)
    if cache_key in MODULAR_INVERSE_CACHE:
        return MODULAR_INVERSE_CACHE[cache_key]
    
    if value == 0:
        return 0

    lm, hm = 1, 0
    low, high = value % modulus, modulus
    while low > 1:
        ratio = high // low
        next_m, next_h = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = next_m, next_h, lm, low

    result = lm % modulus
    MODULAR_INVERSE_CACHE[cache_key] = result
    return result

def sm2_point_addition(pt1, pt2):
    """SM2椭圆曲线上的点加法"""
    cache_key = (pt1, pt2)
    if cache_key in POINT_ADDITION_CACHE:
        return POINT_ADDITION_CACHE[cache_key]

    if pt1 == (0, 0): return pt2
    if pt2 == (0, 0): return pt1

    x1, y1 = pt1
    x2, y2 = pt2

    if x1 == x2:
        if y1 == y2:
            # 点加倍
            slope = (3 * x1 * x1 + ELLIPTIC_CURVE_A) * modular_inverse(2 * y1, PRIME_MODULUS)
        else:
            return (0, 0) # 无穷远点
    else:
        # 点加法
        slope = (y2 - y1) * modular_inverse(x2 - x1, PRIME_MODULUS)

    slope %= PRIME_MODULUS
    x3 = (slope * slope - x1 - x2) % PRIME_MODULUS
    y3 = (slope * (x1 - x3) - y1) % PRIME_MODULUS
    
    result = (x3, y3)
    POINT_ADDITION_CACHE[cache_key] = result
    return result

def sm2_scalar_multiplication(scalar, point):
    """SM2椭圆曲线上的标量乘法，使用双加算法"""
    result = (0, 0)
    current_point = point
    while scalar:
        if scalar & 1:
            result = sm2_point_addition(result, current_point)
        current_point = sm2_point_addition(current_point, current_point)
        scalar >>= 1
    return result

def compute_user_hash(user_id, public_key_x, public_key_y):
    """计算用户标识哈希值 (ZA)"""
    id_bitlen = len(user_id.encode('utf-8')) * 8
    
    components = [
        id_bitlen.to_bytes(2, 'big'),
        user_id.encode('utf-8'),
        ELLIPTIC_CURVE_A.to_bytes(32, 'big'),
        ELLIPTIC_CURVE_B.to_bytes(32, 'big'),
        BASE_POINT_X.to_bytes(32, 'big'),
        BASE_POINT_Y.to_bytes(32, 'big'),
        public_key_x.to_bytes(32, 'big'),
        public_key_y.to_bytes(32, 'big')
    ]
    data_to_hash = b''.join(components)
    
    return sm3.sm3_hash(func.bytes_to_list(data_to_hash))

def generate_keypair():
    """生成SM2密钥对"""
    private_key = secrets.randbelow(ORDER_N - 1) + 1
    public_key = sm2_scalar_multiplication(private_key, BASE_POINT)
    return private_key, public_key

def sign_message_with_k(d_key, message_text, user_id_str, public_key_coords, random_k):
    """使用指定的k值生成SM2签名。"""
    za_bytes = bytes.fromhex(compute_user_hash(user_id_str, public_key_coords[0], public_key_coords[1]))
    data_for_hash = za_bytes + message_text.encode('utf-8')
    
    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_val = int(hash_result, 16)

    # 标量乘法 R_point = k * G
    r_point = sm2_scalar_multiplication(random_k, BASE_POINT)
    x_coord_r = r_point[0]
    
    r_val = (e_val + x_coord_r) % ORDER_N
    if r_val == 0 or r_val + random_k == ORDER_N:
        return None, None

    inv_val = modular_inverse(1 + d_key, ORDER_N)
    s_val = (inv_val * (random_k - r_val * d_key)) % ORDER_N
    
    return r_val, s_val

def ecdsa_sign_for_poc(private_key_d, message_data, random_k_val):
    """ECDSA签名，使用相同的SM2参数，用于POC验证"""
    msg_bytes = message_data.encode('utf-8')
    hash_output = sha256(msg_bytes).digest()
    e_val_ecdsa = int.from_bytes(hash_output, 'big') % ORDER_N

    r_point = sm2_scalar_multiplication(random_k_val, BASE_POINT)
    r_val_ecdsa = r_point[0] % ORDER_N
    if r_val_ecdsa == 0:
        return None, None

    inv_k = modular_inverse(random_k_val, ORDER_N)
    s_val_ecdsa = (inv_k * (e_val_ecdsa + private_key_d * r_val_ecdsa)) % ORDER_N
    if s_val_ecdsa == 0:
        return None, None

    return r_val_ecdsa, s_val_ecdsa

def run_all_tests():
    """主函数，运行所有POC验证"""
    print("\n--- PoC 验证：SM2签名随机数误用攻击 ---")

    # 场景一：k值泄露攻击
    print("\n[场景一] 随机数k泄露导致私钥恢复")
    private_key_val, public_key_val = generate_keypair()
    test_user_id = "test_user"
    print(f"原始私钥: {hex(private_key_val)}")

    fixed_k_val = secrets.randbelow(ORDER_N - 1) + 1
    sample_message = "Test message"
    r_sig, s_sig = sign_message_with_k(private_key_val, sample_message, test_user_id, public_key_val, fixed_k_val)

    if r_sig is None:
        print("签名失败，请重试。")
        return
        
    denominator = (s_sig + r_sig) % ORDER_N
    if denominator == 0:
        print("错误：分母为零，无法恢复。")
        return
    
    inv_denom = modular_inverse(denominator, ORDER_N)
    recovered_key = ((fixed_k_val - s_sig) * inv_denom) % ORDER_N
    
    print(f"使用的随机数k: {hex(fixed_k_val)}")
    print(f"恢复的私钥: {hex(recovered_key)}")
    print(f"恢复结果: {private_key_val == recovered_key}")
    print("-" * 40)

    # 场景二：同一私钥、同一用户，重复使用k
    print("\n[场景二] 同一用户、同一k值签名不同消息")
    da, pub_key_A = generate_keypair()
    user_id_A = "user_same_k"
    print(f"原始私钥: {hex(da)}")
    
    k_reused = secrets.randbelow(ORDER_N - 1) + 1
    message_one = "First message."
    message_two = "Second message."

    r1, s1 = sign_message_with_k(da, message_one, user_id_A, pub_key_A, k_reused)
    r2, s2 = sign_message_with_k(da, message_two, user_id_A, pub_key_A, k_reused)
    
    numerator = (s2 - s1) % ORDER_N
    denominator = (s1 - s2 + r1 - r2) % ORDER_N
    if denominator == 0:
        print("错误：分母为零，无法恢复。")
        return
    
    inv_denom = modular_inverse(denominator, ORDER_N)
    recovered_da = (numerator * inv_denom) % ORDER_N
    
    print(f"恢复的私钥: {hex(recovered_da)}")
    print(f"恢复结果: {da == recovered_da}")
    print("-" * 40)

    # 场景三：不同私钥、不同用户，共享同一k
    print("\n[场景三] 不同用户共享同一k值签名")
    da_attacker, pub_key_A = generate_keypair()
    user_id_A = "attacker"
    print(f"攻击者私钥: {hex(da_attacker)}")

    db_victim, pub_key_B = generate_keypair()
    user_id_B = "victim"
    print(f"受害者私钥: {hex(db_victim)}")

    shared_k = secrets.randbelow(ORDER_N - 1) + 1
    
    rA, sA = sign_message_with_k(da_attacker, "Msg from attacker", user_id_A, pub_key_A, shared_k)
    rB, sB = sign_message_with_k(db_victim, "Msg from victim", user_id_B, pub_key_B, shared_k)
    
    k_computed_by_attacker = (sA * (1 + da_attacker) + rA * da_attacker) % ORDER_N
    
    denominator_B = (sB + rB) % ORDER_N
    if denominator_B == 0:
        print("错误：分母为零，无法恢复。")
        return
        
    inv_denom_B = modular_inverse(denominator_B, ORDER_N)
    recovered_db = ((k_computed_by_attacker - sB) * inv_denom_B) % ORDER_N
    
    print(f"恢复的受害者私钥: {hex(recovered_db)}")
    print(f"恢复结果: {db_victim == recovered_db}")
    print("-" * 40)

    # 场景四：SM2与ECDSA签名混合使用同一k值
    print("\n[场景四] SM2与ECDSA混合签名，使用同一k值")
    shared_key_val, shared_pub_key = generate_keypair()
    print(f"原始私钥: {hex(shared_key_val)}")

    k_reused_cross = secrets.randbelow(ORDER_N - 1) + 1

    ecdsa_msg = "ECDSA message"
    r1, s1 = ecdsa_sign_for_poc(shared_key_val, ecdsa_msg, k_reused_cross)
    
    sm2_msg = "SM2 message"
    r2, s2 = sign_message_with_k(shared_key_val, sm2_msg, "hybrid_user", shared_pub_key, k_reused_cross)
    
    ecdsa_hash = sha256(ecdsa_msg.encode('utf-8')).digest()
    e1 = int.from_bytes(ecdsa_hash, 'big') % ORDER_N
    
    numerator_h = (s1 * s2 - e1) % ORDER_N
    denominator_h = (r1 - s1 * s2 - s1 * r2) % ORDER_N
    if denominator_h == 0:
        print("错误：分母为零，无法恢复。")
        return
        
    inv_denom_h = modular_inverse(denominator_h, ORDER_N)
    recovered_key_h = (numerator_h * inv_denom_h) % ORDER_N
    
    print(f"恢复的私钥: {hex(recovered_key_h)}")
    print(f"恢复结果: {shared_key_val == recovered_key_h}")

if __name__ == "__main__":
    run_all_tests()
