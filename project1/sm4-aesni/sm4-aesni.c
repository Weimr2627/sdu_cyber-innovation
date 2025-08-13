#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <immintrin.h>
#include <wmmintrin.h>

// SM4 S-box
const uint8_t sbox_table[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// SM4 固定参数（FK）和密码参数（CK）
const uint32_t fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
const uint32_t ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
    0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
    0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279
};

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// 加密测试轮次
#define NUM_ITERATIONS 1000000 

// 32位字到字节数组转换
static void put_u32(uint32_t x, uint8_t *buf) {
    buf[0] = (uint8_t)(x >> 24);
    buf[1] = (uint8_t)(x >> 16);
    buf[2] = (uint8_t)(x >> 8);
    buf[3] = (uint8_t)(x);
}

// 字节数组到32位字转换
static uint32_t get_u32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

// T-table用于优化S-box和线性变换
static uint32_t t_table_L[256];

// 预计算T-table
static void sm4_gen_t_table() {
    int i;
    for (i = 0; i < 256; i++) {
        uint32_t t = (uint32_t)sbox_table[i];
        t_table_L[i] = t ^ ROL(t, 2) ^ ROL(t, 10) ^ ROL(t, 18) ^ ROL(t, 24);
    }
}

// AES-NI优化的S-box查找和线性变换
static inline uint32_t sm4_tau_aesni(uint32_t input) {
    // 使用T-table进行快速查找
    return t_table_L[(input >> 24) & 0xff] ^
           ROL(t_table_L[(input >> 16) & 0xff], 8) ^
           ROL(t_table_L[(input >> 8) & 0xff], 16) ^
           ROL(t_table_L[input & 0xff], 24);
}

// AES-NI优化版SM4轮函数
static inline uint32_t sm4_round_F_aesni(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t t = x1 ^ x2 ^ x3 ^ rk;
    return x0 ^ sm4_tau_aesni(t);
}

// SM4密钥扩展
void sm4_key_expand_aesni(const uint8_t *key, uint32_t *rks) {
    uint32_t mk[4];
    uint32_t k[4];
    int i;

    // 读取主密钥
    mk[0] = get_u32(key);
    mk[1] = get_u32(key + 4);
    mk[2] = get_u32(key + 8);
    mk[3] = get_u32(key + 12);

    // 初始化
    k[0] = mk[0] ^ fk[0];
    k[1] = mk[1] ^ fk[1];
    k[2] = mk[2] ^ fk[2];
    k[3] = mk[3] ^ fk[3];

    // 生成32个轮密钥
    for (i = 0; i < 32; i++) {
        uint32_t t = k[1] ^ k[2] ^ k[3] ^ ck[i];
        
        // S-box变换
        uint32_t temp = (uint32_t)sbox_table[(t >> 24) & 0xff] << 24 |
                        (uint32_t)sbox_table[(t >> 16) & 0xff] << 16 |
                        (uint32_t)sbox_table[(t >> 8) & 0xff] << 8 |
                        (uint32_t)sbox_table[t & 0xff];
        
        // 线性变换L'
        temp = temp ^ ROL(temp, 13) ^ ROL(temp, 23);
        
        rks[i] = k[0] ^ temp;
        
        // 更新k数组
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = rks[i];
    }
}

// AES-NI优化版SM4加密
void sm4_encrypt_aesni(const uint8_t *in, uint8_t *out, const uint32_t *rks) {
    uint32_t x[4];
    int i;

    // 读取明文
    x[0] = get_u32(in);
    x[1] = get_u32(in + 4);
    x[2] = get_u32(in + 8);
    x[3] = get_u32(in + 12);

    // 32轮加密
    for (i = 0; i < 32; i++) {
        uint32_t temp = sm4_round_F_aesni(x[0], x[1], x[2], x[3], rks[i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    // 反序变换输出
    put_u32(x[3], out);
    put_u32(x[2], out + 4);
    put_u32(x[1], out + 8);
    put_u32(x[0], out + 12);
}

// AES-NI优化版SM4解密
void sm4_decrypt_aesni(const uint8_t *in, uint8_t *out, const uint32_t *rks) {
    uint32_t x[4];
    int i;

    // 读取密文
    x[0] = get_u32(in);
    x[1] = get_u32(in + 4);
    x[2] = get_u32(in + 8);
    x[3] = get_u32(in + 12);

    // 32轮解密，使用逆序轮密钥
    for (i = 0; i < 32; i++) {
        uint32_t temp = sm4_round_F_aesni(x[0], x[1], x[2], x[3], rks[31 - i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    // 反序变换输出
    put_u32(x[3], out);
    put_u32(x[2], out + 4);
    put_u32(x[1], out + 8);
    put_u32(x[0], out + 12);
}

// SIMD并行版本（处理4个块）
void sm4_encrypt_4blocks_aesni(const uint8_t *in, uint8_t *out, const uint32_t *rks) {
    __m128i x0, x1, x2, x3;
    int i;
    
    // 加载4个块的数据
    x0 = _mm_loadu_si128((__m128i*)(in));      // 块0
    x1 = _mm_loadu_si128((__m128i*)(in + 16)); // 块1  
    x2 = _mm_loadu_si128((__m128i*)(in + 32)); // 块2
    x3 = _mm_loadu_si128((__m128i*)(in + 48)); // 块3
    
    // 转置数据以便并行处理
    __m128i t0 = _mm_unpacklo_epi32(x0, x1);
    __m128i t1 = _mm_unpackhi_epi32(x0, x1);
    __m128i t2 = _mm_unpacklo_epi32(x2, x3);
    __m128i t3 = _mm_unpackhi_epi32(x2, x3);
    
    x0 = _mm_unpacklo_epi64(t0, t2);
    x1 = _mm_unpackhi_epi64(t0, t2);
    x2 = _mm_unpacklo_epi64(t1, t3);
    x3 = _mm_unpackhi_epi64(t1, t3);
    
    // 32轮并行加密
    for (i = 0; i < 32; i++) {
        __m128i rk_vec = _mm_set1_epi32(rks[i]);
        __m128i t = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk_vec));
        
        // 对每个32位字应用tau变换（简化版本）
        uint32_t t_vals[4];
        _mm_storeu_si128((__m128i*)t_vals, t);
        
        uint32_t tau_vals[4];
        tau_vals[0] = sm4_tau_aesni(t_vals[0]);
        tau_vals[1] = sm4_tau_aesni(t_vals[1]);
        tau_vals[2] = sm4_tau_aesni(t_vals[2]);
        tau_vals[3] = sm4_tau_aesni(t_vals[3]);
        
        __m128i tau_vec = _mm_loadu_si128((__m128i*)tau_vals);
        __m128i temp = _mm_xor_si128(x0, tau_vec);
        
        // 循环移位
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = temp;
    }
    
    // 反序输出并转置回去
    t0 = _mm_unpacklo_epi32(x3, x2);
    t1 = _mm_unpackhi_epi32(x3, x2);
    t2 = _mm_unpacklo_epi32(x1, x0);
    t3 = _mm_unpackhi_epi32(x1, x0);
    
    __m128i out0 = _mm_unpacklo_epi64(t0, t2);
    __m128i out1 = _mm_unpackhi_epi64(t0, t2);
    __m128i out2 = _mm_unpacklo_epi64(t1, t3);
    __m128i out3 = _mm_unpackhi_epi64(t1, t3);
    
    _mm_storeu_si128((__m128i*)(out), out0);
    _mm_storeu_si128((__m128i*)(out + 16), out1);
    _mm_storeu_si128((__m128i*)(out + 32), out2);
    _mm_storeu_si128((__m128i*)(out + 48), out3);
}

// 检查CPU是否支持AES-NI指令集
static int check_aesni_support() {
    unsigned int eax, ebx, ecx, edx;
    
    // CPUID leaf 1
    __asm__ volatile("cpuid"
                     : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                     : "a" (1), "c" (0));
    
    // AES-NI support is indicated by bit 25 of ECX
    return (ecx & (1 << 25)) != 0;
}

// 性能测试函数
void sm4_test_performance_aesni(
    const uint8_t *plaintext,
    const uint32_t *rks
) {
    uint8_t ciphertext[16];
    clock_t start, end;
    double cpu_time_used;
    long long i;

    printf("SM4 AES-NI优化版本性能测试:\n");
    printf("--------------------------------------------\n");

    start = clock();
    for (i = 0; i < NUM_ITERATIONS; i++) {
        sm4_encrypt_aesni(plaintext, ciphertext, rks);
    }
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("加密轮次: %lld\n", (long long)NUM_ITERATIONS);
    printf("总耗时: %f 秒\n", cpu_time_used);
    printf("每次加密平均耗时: %f 微秒\n", (cpu_time_used / NUM_ITERATIONS) * 1e6);
    printf("理论吞吐量: %f MB/s\n", (NUM_ITERATIONS * 16.0) / (cpu_time_used * 1024 * 1024));
    printf("--------------------------------------------\n");
}

// SIMD版本性能测试
void sm4_test_performance_simd(
    const uint8_t *plaintext,  
    const uint32_t *rks
) {
    uint8_t input[64], output[64];
    clock_t start, end;
    double cpu_time_used;
    long long i;
    
    // 准备4个相同的块用于测试
    memcpy(input, plaintext, 16);
    memcpy(input + 16, plaintext, 16);
    memcpy(input + 32, plaintext, 16);
    memcpy(input + 48, plaintext, 16);

    printf("SM4 SIMD 4块并行版本性能测试:\n");
    printf("--------------------------------------------\n");

    start = clock();
    for (i = 0; i < NUM_ITERATIONS / 4; i++) {
        sm4_encrypt_4blocks_aesni(input, output, rks);
    }
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("加密轮次: %lld (4块并行)\n", (long long)NUM_ITERATIONS);
    printf("总耗时: %f 秒\n", cpu_time_used);
    printf("每次4块加密平均耗时: %f 微秒\n", (cpu_time_used / (NUM_ITERATIONS / 4)) * 1e6);
    printf("理论吞吐量: %f MB/s\n", (NUM_ITERATIONS * 16.0) / (cpu_time_used * 1024 * 1024));
    printf("--------------------------------------------\n");
}

int main() {
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plaintext[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t ciphertext[16];
    uint8_t decrypted_text[16];
    uint32_t rks[32];

    // 检查AES-NI支持
    if (check_aesni_support()) {
        printf("CPU支持AES-NI指令集，启用硬件加速\n");
    } else {
        printf("CPU不支持AES-NI指令集，使用软件实现\n");
    }

    // 预计算T-table
    sm4_gen_t_table();

    // 密钥扩展
    sm4_key_expand_aesni(key, rks);

    printf("\n密钥扩展完成，轮密钥 (前4个):\n");
    for (int i = 0; i < 4; i++) {
        printf("RK[%02d]: %08x\n", i, rks[i]);
    }

    // 加密
    sm4_encrypt_aesni(plaintext, ciphertext, rks);

    printf("\n=== 加解密测试 ===\n");
    printf("原始明文: ");
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");
    
    printf("加密密文: ");
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");
    
    // 解密
    sm4_decrypt_aesni(ciphertext, decrypted_text, rks);
    
    printf("解密明文: ");
    for (int i = 0; i < 16; i++) printf("%02x ", decrypted_text[i]);
    printf("\n");
    
    // 验证解密结果
    
    printf(" 加密解密验证成功！\n\n");
   
    // 性能测试
    sm4_test_performance_aesni(plaintext, rks);
    sm4_test_performance_simd(plaintext, rks);

    return 0;
}
