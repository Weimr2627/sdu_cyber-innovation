import secrets
import binascii
from gmssl import sm3, func

# SM2椭圆曲线参数，与比特币不同
ELLIPTIC_CURVE_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
ELLIPTIC_CURVE_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
PRIME_MODULUS = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
ORDER_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
BASE_POINT_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
BASE_POINT_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
BASE_POINT = (BASE_POINT_X, BASE_POINT_Y)

# 缓存字典，用于加速计算
MODULAR_INVERSE_CACHE = {}
POINT_ADDITION_CACHE = {}

def modular_inverse(value, modulus):
    """计算模逆元，是椭圆曲线运算的基础"""
    cache_key = (value, modulus)
    if cache_key in MODULAR_INVERSE_CACHE:
        return MODULAR_INVERSE_CACHE[cache_key]
    
    if value == 0: return 0
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
            slope = (3 * x1 * x1 + ELLIPTIC_CURVE_A) * modular_inverse(2 * y1, PRIME_MODULUS)
        else:
            return (0, 0)
    else:
        slope = (y2 - y1) * modular_inverse(x2 - x1, PRIME_MODULUS)
    slope %= PRIME_MODULUS
    x3 = (slope * slope - x1 - x2) % PRIME_MODULUS
    y3 = (slope * (x1 - x3) - y1) % PRIME_MODULUS
    result = (x3, y3)
    POINT_ADDITION_CACHE[cache_key] = result
    return result

def sm2_scalar_multiplication(scalar, point):
    """SM2椭圆曲线上的标量乘法"""
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

def sign_with_sm2(private_key, message, user_id, public_key):
    """使用SM2私钥对消息进行签名"""
    za_bytes = bytes.fromhex(compute_user_hash(user_id, public_key[0], public_key[1]))
    data_for_hash = za_bytes + message.encode('utf-8')
    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_val = int(hash_result, 16)

    while True:
        k_val = secrets.randbelow(ORDER_N - 1) + 1
        r_point = sm2_scalar_multiplication(k_val, BASE_POINT)
        x_r = r_point[0]
        r_val = (e_val + x_r) % ORDER_N
        if r_val == 0 or r_val + k_val == ORDER_N:
            continue
        
        inv_val = modular_inverse(1 + private_key, ORDER_N)
        s_val = (inv_val * (k_val - r_val * private_key)) % ORDER_N
        if s_val != 0:
            return (r_val, s_val)

def verify_sm2_signature(public_key, message, user_id, signature):
    """验证SM2签名"""
    r_val, s_val = signature
    if not (0 < r_val < ORDER_N and 0 < s_val < ORDER_N):
        return False
    
    za_bytes = bytes.fromhex(compute_user_hash(user_id, public_key[0], public_key[1]))
    data_for_hash = za_bytes + message.encode('utf-8')
    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_val = int(hash_result, 16)
    
    t = (r_val + s_val) % ORDER_N
    if t == 0:
        return False
        
    sg = sm2_scalar_multiplication(s_val, BASE_POINT)
    tp = sm2_scalar_multiplication(t, public_key)
    
    x_r_prime_point = sm2_point_addition(sg, tp)
    x_r_prime = x_r_prime_point[0]
    
    r_prime = (e_val + x_r_prime) % ORDER_N
    return r_prime == r_val

if __name__ == "__main__":
    # 模拟中本聪，但我们使用的是SM2算法
    print("--- 伪造中本聪的SM2签名 ---")
    
    # 1. 生成一个“伪造的”私钥和公钥对
    private_key, public_key = generate_keypair()
    
    # 2. 定义一条要签名的消息
    message = "I am Satoshi Nakamoto and I have generated this SM2 signature."
    user_id = "SatoshiNakamoto"
    
    print(f"生成的私钥 (d_A): {hex(private_key)}")
    print(f"生成的公钥 (P_A): ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # 3. 使用私钥进行签名
    signature = sign_with_sm2(private_key, message, user_id, public_key)
    r, s = signature
    
    print("\n--- 签名结果 ---")
    print(f"消息: \"{message}\"")
    print(f"SM2 签名 (r): {hex(r)}")
    print(f"SM2 签名 (s): {hex(s)}")
    
    # 4. 验证签名以证明其合法性
    is_valid = verify_sm2_signature(public_key, message, user_id, signature)
    print(f"\n--- 签名验证 ---")
    print(f"使用公钥验证签名: {is_valid}")
    
    print("\n注意：这个签名在SM2算法体系内是有效的，但它无法被ECDSA验证，因此不能冒充中本聪在比特币网络上的签名。")
