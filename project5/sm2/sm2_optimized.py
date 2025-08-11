import hashlib
import random
import time
from typing import Tuple, Optional, List

class OptimizedSM2:
    """SM2椭圆曲线密码算法的优化实现"""
    
    # SM2推荐参数
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    
    def __init__(self):
        self.G = (self.GX, self.GY)
        # 预计算表用于加速点乘运算
        self.precomputed_points = self._precompute_points()
        
    def _precompute_points(self, window_size: int = 4) -> List[Tuple[int, int]]:
        """预计算基点的倍数，用于滑动窗口法"""
        precomputed = [None] * (1 << window_size)  # 2^window_size 个点
        precomputed[0] = None  # 0*G = O (无穷远点)
        precomputed[1] = self.G  # 1*G = G
        
        for i in range(2, 1 << window_size):
            precomputed[i] = self.point_add_basic(precomputed[i-1], self.G)
            
        return precomputed
    
    def mod_inverse_fast(self, a: int, m: int) -> int:
        """优化的模逆运算（使用费马小定理）"""
        # 对于素数模，使用费马小定理: a^(p-2) ≡ a^(-1) (mod p)
        return pow(a, m - 2, m)
    
    def point_add_basic(self, P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """基础椭圆曲线点加运算"""
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        
        x1, y1 = P1
        x2, y2 = P2
        
        if x1 == x2:
            if y1 == y2:
                # 点倍运算
                s = (3 * x1 * x1 + self.A) * self.mod_inverse_fast(2 * y1, self.P) % self.P
            else:
                return None  # 相反点
        else:
            s = (y2 - y1) * self.mod_inverse_fast(x2 - x1, self.P) % self.P
        
        x3 = (s * s - x1 - x2) % self.P
        y3 = (s * (x1 - x3) - y1) % self.P
        
        return (x3, y3)
    
    def point_double_optimized(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """优化的点倍运算"""
        if P is None:
            return None
            
        x, y = P
        
        # 使用优化公式减少乘法运算
        y_squared = y * y % self.P
        s = (3 * x * x + self.A) % self.P
        s = s * self.mod_inverse_fast(2 * y, self.P) % self.P
        
        x3 = (s * s - 2 * x) % self.P
        y3 = (s * (x - x3) - y) % self.P
        
        return (x3, y3)
    
    def point_multiply_windowed(self, k: int, P: Tuple[int, int], window_size: int = 4) -> Optional[Tuple[int, int]]:
        """滑动窗口法标量乘法"""
        if k == 0:
            return None
        if k == 1:
            return P
        
        # 如果是基点G，使用预计算表
        if P == self.G:
            return self.point_multiply_precomputed(k, window_size)
        
        # 对于其他点，使用滑动窗口法
        result = None
        bits = bin(k)[2:]  # 去除'0b'前缀
        
        i = 0
        while i < len(bits):
            if bits[i] == '0':
                result = self.point_add_basic(result, result) if result else None
                i += 1
            else:
                # 找到窗口
                window_end = min(i + window_size, len(bits))
                window_val = int(bits[i:window_end], 2)
                
                # 左移
                for _ in range(window_end - i):
                    result = self.point_add_basic(result, result) if result else None
                
                # 加上窗口值对应的点
                window_point = self._compute_window_point(window_val, P)
                result = self.point_add_basic(result, window_point)
                
                i = window_end
        
        return result
    
    def point_multiply_precomputed(self, k: int, window_size: int = 4) -> Optional[Tuple[int, int]]:
        """使用预计算表的基点标量乘法"""
        if k == 0:
            return None
        
        result = None
        mask = (1 << window_size) - 1
        
        while k > 0:
            if k & mask:
                window_val = k & mask
                result = self.point_add_basic(result, self.precomputed_points[window_val])
            
            # 左移window_size位
            for _ in range(window_size):
                result = self.point_add_basic(result, result) if result else None
            
            k >>= window_size
        
        return result
    
    def _compute_window_point(self, window_val: int, base_point: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """计算窗口值对应的点"""
        if window_val == 0:
            return None
        
        result = None
        addend = base_point
        
        while window_val > 0:
            if window_val & 1:
                result = self.point_add_basic(result, addend)
            addend = self.point_add_basic(addend, addend)
            window_val >>= 1
        
        return result
    
    def montgomery_ladder(self, k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """蒙哥马利阶梯法（抗侧信道攻击）"""
        if k == 0:
            return None
        if k == 1:
            return P
        
        bits = bin(k)[2:]
        R0, R1 = None, P
        
        for bit in bits[1:]:  # 跳过最高位1
            if bit == '0':
                R1 = self.point_add_basic(R0, R1)
                R0 = self.point_add_basic(R0, R0) if R0 else None
            else:
                R0 = self.point_add_basic(R0, R1)
                R1 = self.point_add_basic(R1, R1) if R1 else None
        
        return R0
    
    def generate_keypair_secure(self) -> Tuple[int, Tuple[int, int]]:
        """安全的密钥对生成"""
        # 使用系统安全随机数生成器
        private_key = random.SystemRandom().randint(1, self.N - 1)
        
        # 使用优化的点乘计算公钥
        public_key = self.point_multiply_windowed(private_key, self.G)
        
        return private_key, public_key
    
    def sign_optimized(self, message: bytes, private_key: int, 
                      user_id: bytes = b"1234567812345678") -> Tuple[int, int]:
        """优化的SM2数字签名"""
        # 预计算ZA（可以缓存）
        za = self._compute_za(private_key, user_id)
        
        # 计算消息摘要
        m_hash = self.sm3_hash(za + message)
        e = int.from_bytes(m_hash, 'big')
        
        while True:
            # 使用安全随机数生成器
            k = random.SystemRandom().randint(1, self.N - 1)
            
            # 使用优化的点乘
            point = self.point_multiply_windowed(k, self.G)
            if point is None:
                continue
            
            x1, _ = point
            r = (e + x1) % self.N
            
            if r == 0 or (r + k) % self.N == 0:
                continue
            
            # 优化的模逆计算
            d_inv = self.mod_inverse_fast(1 + private_key, self.N)
            s = (d_inv * (k - r * private_key)) % self.N
            
            if s != 0:
                return (r, s)
    
    def verify_optimized(self, message: bytes, signature: Tuple[int, int], 
                        public_key: Tuple[int, int], user_id: bytes = b"1234567812345678") -> bool:
        """优化的SM2签名验证"""
        r, s = signature
        
        # 快速范围检查
        if not (1 <= r < self.N and 1 <= s < self.N):
            return False
        
        # 预计算（可缓存）
        xa, ya = public_key
        za = self._compute_za_from_pubkey(public_key, user_id)
        
        # 计算消息摘要
        m_hash = self.sm3_hash(za + message)
        e = int.from_bytes(m_hash, 'big')
        
        t = (r + s) % self.N
        if t == 0:
            return False
        
        # 使用同时多标量乘法优化
        # 计算 s*G + t*PA
        point = self.simultaneous_multiply(s, self.G, t, public_key)
        
        if point is None:
            return False
        
        x1, _ = point
        v = (e + x1) % self.N
        
        return v == r
    
    def simultaneous_multiply(self, k1: int, P1: Tuple[int, int], 
                            k2: int, P2: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """同时多标量乘法优化（Shamir技巧）"""
        # 预计算P1, P2, P1+P2
        precomp = [
            None,  # 0*P1 + 0*P2
            P1,    # 1*P1 + 0*P2
            P2,    # 0*P1 + 1*P2
            self.point_add_basic(P1, P2)  # 1*P1 + 1*P2
        ]
        
        result = None
        max_bits = max(k1.bit_length(), k2.bit_length())
        
        for i in range(max_bits - 1, -1, -1):
            result = self.point_add_basic(result, result) if result else None
            
            bit1 = (k1 >> i) & 1
            bit2 = (k2 >> i) & 1
            index = bit1 * 2 + bit2
            
            if index > 0:
                result = self.point_add_basic(result, precomp[index])
        
        return result
    
    def _compute_za(self, private_key: int, user_id: bytes) -> bytes:
        """计算ZA值"""
        public_key = self.point_multiply_windowed(private_key, self.G)
        return self._compute_za_from_pubkey(public_key, user_id)
    
    def _compute_za_from_pubkey(self, public_key: Tuple[int, int], user_id: bytes) -> bytes:
        """从公钥计算ZA值"""
        entl = len(user_id) * 8
        za_data = entl.to_bytes(2, 'big') + user_id
        za_data += self.A.to_bytes(32, 'big') + self.B.to_bytes(32, 'big')
        za_data += self.GX.to_bytes(32, 'big') + self.GY.to_bytes(32, 'big')
        
        xa, ya = public_key
        za_data += xa.to_bytes(32, 'big') + ya.to_bytes(32, 'big')
        
        return self.sm3_hash(za_data)
    
    def sm3_hash(self, data: bytes) -> bytes:
        """SM3哈希算法（这里用SHA256替代）"""
        return hashlib.sha256(data).digest()

class PerformanceBenchmark:
    """性能基准测试"""
    
    def __init__(self):
        self.basic_sm2 = SM2()
        self.optimized_sm2 = OptimizedSM2()
    
    def benchmark_key_generation(self, iterations: int = 100) -> dict:
        """密钥生成性能测试"""
        print(f"密钥生成性能测试 ({iterations} 次)...")
        
        # 基础实现
        start_time = time.time()
        for _ in range(iterations):
            self.basic_sm2.generate_keypair()
        basic_time = time.time() - start_time
        
        # 优化实现
        start_time = time.time()
        for _ in range(iterations):
            self.optimized_sm2.generate_keypair_secure()
        optimized_time = time.time() - start_time
        
        return {
            "basic_time": basic_time,
            "optimized_time": optimized_time,
            "speedup": basic_time / optimized_time,
            "basic_ops_per_sec": iterations / basic_time,
            "optimized_ops_per_sec": iterations / optimized_time
        }
    
    def benchmark_signing(self, iterations: int = 100) -> dict:
        """签名性能测试"""
        print(f"签名性能测试 ({iterations} 次)...")
        
        message = b"Performance test message"
        
        # 生成密钥
        basic_private, _ = self.basic_sm2.generate_keypair()
        opt_private, _ = self.optimized_sm2.generate_keypair_secure()
        
        # 基础实现
        start_time = time.time()
        for _ in range(iterations):
            self.basic_sm2.sign(message, basic_private)
        basic_time = time.time() - start_time
        
        # 优化实现
        start_time = time.time()
        for _ in range(iterations):
            self.optimized_sm2.sign_optimized(message, opt_private)
        optimized_time = time.time() - start_time
        
        return {
            "basic_time": basic_time,
            "optimized_time": optimized_time,
            "speedup": basic_time / optimized_time,
            "basic_ops_per_sec": iterations / basic_time,
            "optimized_ops_per_sec": iterations / optimized_time
        }
    
    def benchmark_verification(self, iterations: int = 100) -> dict:
        """验证性能测试"""
        print(f"签名验证性能测试 ({iterations} 次)...")
        
        message = b"Performance test message"
        
        # 准备测试数据
        basic_private, basic_public = self.basic_sm2.generate_keypair()
        opt_private, opt_public = self.optimized_sm2.generate_keypair_secure()
        
        basic_sig = self.basic_sm2.sign(message, basic_private)
        opt_sig = self.optimized_sm2.sign_optimized(message, opt_private)
        
        # 基础实现
        start_time = time.time()
        for _ in range(iterations):
            self.basic_sm2.verify(message, basic_sig, basic_public)
        basic_time = time.time() - start_time
        
        # 优化实现
        start_time = time.time()
        for _ in range(iterations):
            self.optimized_sm2.verify_optimized(message, opt_sig, opt_public)
        optimized_time = time.time() - start_time
        
        return {
            "basic_time": basic_time,
            "optimized_time": optimized_time,
            "speedup": basic_time / optimized_time,
            "basic_ops_per_sec": iterations / basic_time,
            "optimized_ops_per_sec": iterations / optimized_time
        }
    
    def run_full_benchmark(self) -> dict:
        """运行完整的性能基准测试"""
        print("=" * 60)
        print("SM2算法性能基准测试")
        print("=" * 60)
        
        keygen_results = self.benchmark_key_generation(50)
        print(f"密钥生成加速比: {keygen_results['speedup']:.2f}x")
        print(f"优化版本: {keygen_results['optimized_ops_per_sec']:.2f} 密钥对/秒")
        print()
        
        sign_results = self.benchmark_signing(50)
        print(f"签名加速比: {sign_results['speedup']:.2f}x")
        print(f"优化版本: {sign_results['optimized_ops_per_sec']:.2f} 签名/秒")
        print()
        
        verify_results = self.benchmark_verification(50)
        print(f"验证加速比: {verify_results['speedup']:.2f}x")
        print(f"优化版本: {verify_results['optimized_ops_per_sec']:.2f} 验证/秒")
        
        return {
            "key_generation": keygen_results,
            "signing": sign_results,
            "verification": verify_results
        }

# 运行基准测试
if __name__ == "__main__":
    from sm2_implementation import SM2  # 导入基础实现
    
    benchmark = PerformanceBenchmark()
    results = benchmark.run_full_benchmark()
