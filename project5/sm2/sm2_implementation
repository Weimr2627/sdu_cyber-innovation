import hashlib
import random
from typing import Tuple, Optional

class SM2:
    """SM2椭圆曲线数字签名算法的Python实现"""
    
    # SM2推荐参数
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    
    def __init__(self):
        self.G = (self.GX, self.GY)
    
    def sm3_hash(self, data: bytes) -> bytes:
        """SM3哈希算法的简化实现（这里使用SHA256作为替代）"""
        # 实际应该使用SM3，这里用SHA256替代演示
        return hashlib.sha256(data).digest()
    
    def mod_inverse(self, a: int, m: int) -> int:
        """模逆运算"""
        if a < 0:
            a = (a % m + m) % m
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("模逆不存在")
        return (x % m + m) % m
    
    def point_add(self, P1: Tuple[int, int], P2: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加运算"""
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        
        x1, y1 = P1
        x2, y2 = P2
        
        if x1 == x2:
            if y1 == y2:
                # 点倍运算
                s = (3 * x1 * x1 + self.A) * self.mod_inverse(2 * y1, self.P) % self.P
            else:
                # 相反点，结果为无穷远点
                return None
        else:
            # 一般点加
            s = (y2 - y1) * self.mod_inverse(x2 - x1, self.P) % self.P
        
        x3 = (s * s - x1 - x2) % self.P
        y3 = (s * (x1 - x3) - y1) % self.P
        
        return (x3, y3)
    
    def point_multiply(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线标量乘法（二进制方法）"""
        if k == 0:
            return None
        if k == 1:
            return P
        
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        
        return result
    
    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        # 生成私钥
        private_key = random.randint(1, self.N - 1)
        # 计算公钥
        public_key = self.point_multiply(private_key, self.G)
        
        return private_key, public_key
    
    def sign(self, message: bytes, private_key: int, user_id: bytes = b"1234567812345678") -> Tuple[int, int]:
        """SM2数字签名"""
        # 计算ZA（用户标识相关）
        entl = len(user_id) * 8
        za_data = entl.to_bytes(2, 'big') + user_id
        za_data += self.A.to_bytes(32, 'big') + self.B.to_bytes(32, 'big')
        za_data += self.GX.to_bytes(32, 'big') + self.GY.to_bytes(32, 'big')
        
        # 公钥坐标
        public_key = self.point_multiply(private_key, self.G)
        xa, ya = public_key
        za_data += xa.to_bytes(32, 'big') + ya.to_bytes(32, 'big')
        
        za = self.sm3_hash(za_data)
        
        # 计算消息摘要
        m_hash = self.sm3_hash(za + message)
        e = int.from_bytes(m_hash, 'big')
        
        while True:
            # 生成随机数k
            k = random.randint(1, self.N - 1)
            
            # 计算椭圆曲线点(x1, y1) = k * G
            point = self.point_multiply(k, self.G)
            if point is None:
                continue
            
            x1, _ = point
            r = (e + x1) % self.N
            
            # 检查r是否为0或r+k是否为0
            if r == 0 or (r + k) % self.N == 0:
                continue
            
            # 计算s
            d_inv = self.mod_inverse(1 + private_key, self.N)
            s = (d_inv * (k - r * private_key)) % self.N
            
            if s != 0:
                return (r, s)
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int], 
               user_id: bytes = b"1234567812345678") -> bool:
        """SM2签名验证"""
        r, s = signature
        
        # 检查签名值范围
        if not (1 <= r < self.N and 1 <= s < self.N):
            return False
        
        # 计算ZA
        entl = len(user_id) * 8
        za_data = entl.to_bytes(2, 'big') + user_id
        za_data += self.A.to_bytes(32, 'big') + self.B.to_bytes(32, 'big')
        za_data += self.GX.to_bytes(32, 'big') + self.GY.to_bytes(32, 'big')
        
        xa, ya = public_key
        za_data += xa.to_bytes(32, 'big') + ya.to_bytes(32, 'big')
        
        za = self.sm3_hash(za_data)
        
        # 计算消息摘要
        m_hash = self.sm3_hash(za + message)
        e = int.from_bytes(m_hash, 'big')
        
        # 计算t = (r + s) mod n
        t = (r + s) % self.N
        if t == 0:
            return False
        
        # 计算椭圆曲线点(x1', y1') = s*G + t*PA
        point1 = self.point_multiply(s, self.G)
        point2 = self.point_multiply(t, public_key)
        point = self.point_add(point1, point2)
        
        if point is None:
            return False
        
        x1, _ = point
        v = (e + x1) % self.N
        
        return v == r

# 使用示例和测试
if __name__ == "__main__":
    sm2 = SM2()
    
    # 生成密钥对
    private_key, public_key = sm2.generate_keypair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # 签名消息
    message = b"Hello, SM2!"
    signature = sm2.sign(message, private_key)
    print(f"签名: (r={hex(signature[0])}, s={hex(signature[1])})")
    
    # 验证签名
    is_valid = sm2.verify(message, signature, public_key)
    print(f"签名验证结果: {is_valid}")
    
    # 测试错误消息的验证
    wrong_message = b"Wrong message"
    is_valid_wrong = sm2.verify(wrong_message, signature, public_key)
    print(f"错误消息验证结果: {is_valid_wrong}")
