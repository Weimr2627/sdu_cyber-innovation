#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// SM4-GCM 常量定义
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

// SM4 S盒
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x27, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
    0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03,
    0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9,
    0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6,
    0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// SM4 系统参数 FK
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// SM4 固定参数 CK
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// GCM 乘法多项式 (x^128 + x^7 + x^2 + x + 1)
#define GCM_POLY 0xE1

// 循环左移函数
static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 线性变换 L
static uint32_t L(uint32_t B) {
    return B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24);
}

// 线性变换 L'
static uint32_t L_prime(uint32_t B) {
    return B ^ rotl(B, 13) ^ rotl(B, 23);
}

// T函数
static uint32_t T(uint32_t Z) {
    uint8_t a0 = (Z >> 24) & 0xFF;
    uint8_t a1 = (Z >> 16) & 0xFF;
    uint8_t a2 = (Z >> 8) & 0xFF;
    uint8_t a3 = Z & 0xFF;
    
    uint8_t b0 = SM4_SBOX[a0];
    uint8_t b1 = SM4_SBOX[a1];
    uint8_t b2 = SM4_SBOX[a2];
    uint8_t b3 = SM4_SBOX[a3];
    
    uint32_t B = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    return L(B);
}

// T'函数
static uint32_t T_prime(uint32_t Z) {
    uint8_t a0 = (Z >> 24) & 0xFF;
    uint8_t a1 = (Z >> 16) & 0xFF;
    uint8_t a2 = (Z >> 8) & 0xFF;
    uint8_t a3 = Z & 0xFF;
    
    uint8_t b0 = SM4_SBOX[a0];
    uint8_t b1 = SM4_SBOX[a1];
    uint8_t b2 = SM4_SBOX[a2];
    uint8_t b3 = SM4_SBOX[a3];
    
    uint32_t B = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    return L_prime(B);
}

// 密钥扩展
void sm4_key_expand(const uint8_t *key, uint32_t *rk) {
    uint32_t MK[4];
    uint32_t K[36];
    
    // 将密钥转换为字
    for (int i = 0; i < 4; i++) {
        MK[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                 ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
    }
    
    // 计算 K[i] = MK[i] ^ FK[i]
    for (int i = 0; i < 4; i++) {
        K[i] = MK[i] ^ SM4_FK[i];
    }
    
    // 计算轮密钥
    for (int i = 0; i < 32; i++) {
        K[i+4] = K[i] ^ T_prime(K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i]);
        rk[i] = K[i+4];
    }
}

// SM4 加密/解密
void sm4_crypt(const uint8_t *input, uint8_t *output, const uint32_t *rk, int decrypt) {
    uint32_t X[36];
    
    // 将输入转换为字
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)input[4*i] << 24) | ((uint32_t)input[4*i+1] << 16) |
                ((uint32_t)input[4*i+2] << 8) | input[4*i+3];
    }
    
    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        int idx = decrypt ? (31 - i) : i;
        X[i+4] = X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[idx]);
    }
    
    // 反序变换
    uint32_t temp[4];
    temp[0] = X[35];
    temp[1] = X[34];
    temp[2] = X[33];
    temp[3] = X[32];
    
    // 将结果转换为字节
    for (int i = 0; i < 4; i++) {
        output[4*i] = (temp[i] >> 24) & 0xFF;
        output[4*i+1] = (temp[i] >> 16) & 0xFF;
        output[4*i+2] = (temp[i] >> 8) & 0xFF;
        output[4*i+3] = temp[i] & 0xFF;
    }
}

// GCM 乘法运算
void gcm_multiply(uint8_t *x, const uint8_t *y) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);
    
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            if (x[i] & (0x80 >> j)) {
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }
            
            // 右移v
            int lsb = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;
            
            if (lsb) {
                v[0] ^= GCM_POLY;
            }
        }
    }
    
    memcpy(x, z, 16);
}

// 计算GHASH
void gcm_ghash(uint8_t *result, const uint8_t *h, const uint8_t *data, size_t data_len) {
    uint8_t y[16] = {0};
    
    for (size_t i = 0; i < data_len; i += 16) {
        size_t block_size = (data_len - i >= 16) ? 16 : data_len - i;
        
        // XOR with data block
        for (size_t j = 0; j < block_size; j++) {
            y[j] ^= data[i + j];
        }
        
        // 如果数据块不足16字节，用0填充
        for (size_t j = block_size; j < 16; j++) {
            y[j] ^= 0;
        }
        
        gcm_multiply(y, h);
    }
    
    memcpy(result, y, 16);
}

// 生成GCM计数器
void gcm_inc_counter(uint8_t *counter) {
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break;
    }
}

// SM4-GCM 认证加密
int sm4_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *plaintext, 
                     size_t plaintext_len, const uint8_t *aad, size_t aad_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    uint32_t rk[32];
    uint8_t h[16];
    uint8_t y[16];
    uint8_t counter[16];
    
    // 密钥扩展
    sm4_key_expand(key, rk);
    
    // 计算H = E(K, 0^128)
    memset(h, 0, 16);
    sm4_crypt(h, h, rk, 0);
    
    // 初始化Y = GHASH(H, AAD || 0^s || C || 0^t || len(AAD) || len(C))
    memset(y, 0, 16);
    
    // 处理AAD
    if (aad_len > 0) {
        gcm_ghash(y, h, aad, aad_len);
    }
    
    // 初始化计数器
    memcpy(counter, iv, 12);
    counter[15] = 1;
    
    // 加密明文
    for (size_t i = 0; i < plaintext_len; i += 16) {
        size_t block_size = (plaintext_len - i >= 16) ? 16 : plaintext_len - i;
        uint8_t keystream[16];
        
        // 生成密钥流
        sm4_crypt(counter, keystream, rk, 0);
        gcm_inc_counter(counter);
        
        // XOR with plaintext
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
    }
    
    // 计算GHASH
    uint8_t final_y[16];
    memcpy(final_y, y, 16);
    
    // 处理密文
    gcm_ghash(final_y, h, ciphertext, plaintext_len);
    
    // 处理长度信息
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t aad_len_bits = aad_len * 8;
    uint64_t ciphertext_len_bits = plaintext_len * 8;
    
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_len_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ciphertext_len_bits >> (i * 8)) & 0xFF;
    }
    
    gcm_ghash(final_y, h, len_block, 16);
    
    // 计算认证标签
    uint8_t s[16];
    memset(counter, 0, 16);
    memcpy(counter, iv, 12);
    counter[15] = 0;
    sm4_crypt(counter, s, rk, 0);
    
    for (int i = 0; i < 16; i++) {
        tag[i] = final_y[i] ^ s[i];
    }
    
    return 0;
}

// SM4-GCM 认证解密
int sm4_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *ciphertext,
                     size_t ciphertext_len, const uint8_t *aad, size_t aad_len,
                     const uint8_t *tag, uint8_t *plaintext) {
    uint32_t rk[32];
    uint8_t h[16];
    uint8_t y[16];
    uint8_t counter[16];
    uint8_t computed_tag[16];
    
    // 密钥扩展
    sm4_key_expand(key, rk);
    
    // 计算H = E(K, 0^128)
    memset(h, 0, 16);
    sm4_crypt(h, h, rk, 0);
    
    // 初始化Y = GHASH(H, AAD || 0^s || C || 0^t || len(AAD) || len(C))
    memset(y, 0, 16);
    
    // 处理AAD
    if (aad_len > 0) {
        gcm_ghash(y, h, aad, aad_len);
    }
    
    // 处理密文
    gcm_ghash(y, h, ciphertext, ciphertext_len);
    
    // 处理长度信息
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t aad_len_bits = aad_len * 8;
    uint64_t ciphertext_len_bits = ciphertext_len * 8;
    
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_len_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ciphertext_len_bits >> (i * 8)) & 0xFF;
    }
    
    gcm_ghash(y, h, len_block, 16);
    
    // 计算认证标签
    uint8_t s[16];
    memset(counter, 0, 16);
    memcpy(counter, iv, 12);
    counter[15] = 0;
    sm4_crypt(counter, s, rk, 0);
    
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = y[i] ^ s[i];
    }
    
    // 验证标签
    if (memcmp(computed_tag, tag, GCM_TAG_SIZE) != 0) {
        return -1; // 认证失败
    }
    
    // 解密密文
    memcpy(counter, iv, 12);
    counter[15] = 1;
    
    for (size_t i = 0; i < ciphertext_len; i += 16) {
        size_t block_size = (ciphertext_len - i >= 16) ? 16 : ciphertext_len - i;
        uint8_t keystream[16];
        
        // 生成密钥流
        sm4_crypt(counter, keystream, rk, 0);
        gcm_inc_counter(counter);
        
        // XOR with ciphertext
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
    }
    
    return 0;
}

// 测试函数
void test_sm4_gcm() {
    printf("=== SM4-GCM 工作模式测试 ===\n");
    
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b};
    
    const char *plaintext_str = "Hello, SM4-GCM! This is a test message.";
    size_t plaintext_len = strlen(plaintext_str);
    uint8_t *plaintext = (uint8_t*)plaintext_str;
    
    const char *aad_str = "Additional Authenticated Data";
    size_t aad_len = strlen(aad_str);
    uint8_t *aad = (uint8_t*)aad_str;
    
    uint8_t *ciphertext = malloc(plaintext_len);
    uint8_t *decrypted = malloc(plaintext_len);
    uint8_t tag[GCM_TAG_SIZE];
    
    printf("原始明文: %s\n", plaintext_str);
    printf("AAD: %s\n", aad_str);
    printf("明文长度: %zu 字节\n", plaintext_len);
    printf("AAD长度: %zu 字节\n", aad_len);
    
    // 加密
    int encrypt_result = sm4_gcm_encrypt(key, iv, plaintext, plaintext_len, 
                                        aad, aad_len, ciphertext, tag);
    
    if (encrypt_result == 0) {
        printf("V 加密成功\n");
        printf("密文: ");
        for (size_t i = 0; i < plaintext_len; i++) {
            printf("%02x ", ciphertext[i]);
        }
        printf("\n");
        
        printf("认证标签: ");
        for (int i = 0; i < GCM_TAG_SIZE; i++) {
            printf("%02x ", tag[i]);
        }
        printf("\n");
        
        // 解密
        int decrypt_result = sm4_gcm_decrypt(key, iv, ciphertext, plaintext_len,
                                            aad, aad_len, tag, decrypted);
        
        if (decrypt_result == 0) {
            printf("V 解密成功\n");
            printf("解密结果: %s\n", plaintext_str);
            
            // 验证结果
            if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
                printf("V 明文和解密结果匹配\n");
            } else {
                printf("V 明文和解密结果匹配\n");
            }
        } else {
            printf("X 解密失败\n");
        }
    } else {
        printf("X 加密失败\n");
    }
    
    free(ciphertext);
    free(decrypted);
    printf("\n");
}

// 主函数
int main() {
    printf("=== SM4-GCM 工作模式实现 ===\n\n");
    
    // 运行GCM测试
    test_sm4_gcm();
    
    // 性能测试
    printf("=== GCM模式性能测试 ===\n");
    
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b};
    
    const char *plaintext_str = "Performance test message for SM4-GCM";
    size_t plaintext_len = strlen(plaintext_str);
    uint8_t *plaintext = (uint8_t*)plaintext_str;
    
    const char *aad_str = "Additional Authenticated Data";
    size_t aad_len = strlen(aad_str);
    uint8_t *aad = (uint8_t*)aad_str;
    
    uint8_t *ciphertext = malloc(plaintext_len);
    uint8_t *decrypted = malloc(plaintext_len);
    uint8_t tag[GCM_TAG_SIZE];
    
    const int iterations = 100000;
    clock_t start, end;
    double cpu_time_used;
    
    start = clock();
    for (int i = 0; i < iterations; i++) {
        sm4_gcm_encrypt(key, iv, plaintext, plaintext_len, 
                        aad, aad_len, ciphertext, tag);
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    
    printf("GCM模式 %d 次加密耗时: %.6f 秒\n", iterations, cpu_time_used);
    printf("平均每次加密耗时: %.9f 秒\n", cpu_time_used / iterations);
    
    free(ciphertext);
    free(decrypted);
    
    printf("\n=== 测试完成 ===\n");
    return 0;
}
