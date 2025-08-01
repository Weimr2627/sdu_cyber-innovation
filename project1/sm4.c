#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// SM4 密钥结构
typedef struct {
    uint32_t rk[32];  // 32轮轮密钥
} SM4_Key;

// SM4 常量
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// SM4 S盒
static const uint8_t SBox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 循环左移n位
static inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
//按字节反转字
static inline uint32_t BSWAP32(uint32_t x) {
    return ((x & 0xff000000) >> 24) | 
           ((x & 0x00ff0000) >> 8) | 
           ((x & 0x0000ff00) << 8) | 
           ((x & 0x000000ff) << 24);
}

// S盒变换
static inline uint32_t SM4_Sbox(uint32_t x) {
    return (SBox[x & 0xff]) | 
           (SBox[(x >> 8) & 0xff] << 8) | 
           (SBox[(x >> 16) & 0xff] << 16) | 
           (SBox[(x >> 24) & 0xff] << 24);
}

// 线性变换L
static inline uint32_t SM4_L(uint32_t x) {
    return x ^ ROTL32(x, 2) ^ ROTL32(x, 10) ^ ROTL32(x, 18) ^ ROTL32(x, 24);
}

// 合成置换T
static inline uint32_t SM4_T(uint32_t x) {
    return SM4_L(SM4_Sbox(x));
}

// 密钥扩展用的线性变换L'
static inline uint32_t SM4_L_Prime(uint32_t x) {
    return x ^ ROTL32(x, 13) ^ ROTL32(x, 23);
}

// 密钥扩展用的合成置换T'
static inline uint32_t SM4_T_Prime(uint32_t x) {
    return SM4_L_Prime(SM4_Sbox(x));
}

// 密钥扩展算法
void SM4_KeyInit(const uint8_t* key, SM4_Key* sm4_key) {
    uint32_t MK[4], K[4];
    
    // 读取密钥
    for (int i = 0; i < 4; i++) {
        MK[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | 
                (key[i * 4 + 2] << 8) | key[i * 4 + 3];
    }
    
    // 初始化
    for (int i = 0; i < 4; i++) {
        K[i] = MK[i] ^ FK[i];
    }
    
    // 32轮密钥扩展
    for (int i = 0; i < 32; i++) {
        sm4_key->rk[i] = K[0] ^ SM4_T_Prime(K[1] ^ K[2] ^ K[3] ^ CK[i]);
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = sm4_key->rk[i];
    }
}

// 基础加密函数
void SM4_Encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const SM4_Key* sm4_key) {
    uint32_t X[4];
    
    // 读取明文
    for (int i = 0; i < 4; i++) {
        X[i] = (plaintext[i * 4] << 24) | (plaintext[i * 4 + 1] << 16) | 
               (plaintext[i * 4 + 2] << 8) | plaintext[i * 4 + 3];
    }
    
    // 32轮变换
    for (int i = 0; i < 32; i++) {
        X[0] = X[0] ^ SM4_T(X[1] ^ X[2] ^ X[3] ^ sm4_key->rk[i]);
        
        // 循环左移
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;
    }
    
    // 反序变换并输出
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        ciphertext[i * 4] = (val >> 24) & 0xff;
        ciphertext[i * 4 + 1] = (val >> 16) & 0xff;
        ciphertext[i * 4 + 2] = (val >> 8) & 0xff;
        ciphertext[i * 4 + 3] = val & 0xff;
    }
}

// 基础解密函数
void SM4_Decrypt(const uint8_t* ciphertext, uint8_t* plaintext, const SM4_Key* sm4_key) {
    uint32_t X[4];
    
    // 读取密文
    for (int i = 0; i < 4; i++) {
        X[i] = (ciphertext[i * 4] << 24) | (ciphertext[i * 4 + 1] << 16) | 
               (ciphertext[i * 4 + 2] << 8) | ciphertext[i * 4 + 3];
    }
    
    // 32轮变换 (逆序使用轮密钥)
    for (int i = 0; i < 32; i++) {
        X[0] = X[0] ^ SM4_T(X[1] ^ X[2] ^ X[3] ^ sm4_key->rk[31 - i]);
        
        // 循环左移
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;
    }
    
    // 反序变换并输出
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        plaintext[i * 4] = (val >> 24) & 0xff;
        plaintext[i * 4 + 1] = (val >> 16) & 0xff;
        plaintext[i * 4 + 2] = (val >> 8) & 0xff;
        plaintext[i * 4 + 3] = val & 0xff;
    }
}
// ECB模式加密
void SM4_ECB_Encrypt(const uint8_t* plaintext, uint8_t* ciphertext, 
                     size_t length, const SM4_Key* sm4_key) {
    size_t blocks = length / 16;
    
    for (size_t i = 0; i < blocks; i++) {
        SM4_Encrypt_Fast(plaintext + i * 16, ciphertext + i * 16, sm4_key);
    }
}

// ECB模式解密
void SM4_ECB_Decrypt(const uint8_t* ciphertext, uint8_t* plaintext, 
                     size_t length, const SM4_Key* sm4_key) {
    size_t blocks = length / 16;
    
    for (size_t i = 0; i < blocks; i++) {
        SM4_Decrypt_Fast(ciphertext + i * 16, plaintext + i * 16, sm4_key);
    }
}

// CBC模式加密
void SM4_CBC_Encrypt(const uint8_t* plaintext, uint8_t* ciphertext, 
                     size_t length, const SM4_Key* sm4_key, const uint8_t* iv) {
    uint8_t temp[16];
    uint8_t prev_block[16];
    size_t blocks = length / 16;
    
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < blocks; i++) {
        // XOR with previous block
        for (int j = 0; j < 16; j++) {
            temp[j] = plaintext[i * 16 + j] ^ prev_block[j];
        }
        
        // Encrypt
        SM4_Encrypt_Fast(temp, ciphertext + i * 16, sm4_key);
        
        // Update previous block
        memcpy(prev_block, ciphertext + i * 16, 16);
    }
}

// CBC模式解密
void SM4_CBC_Decrypt(const uint8_t* ciphertext, uint8_t* plaintext, 
                     size_t length, const SM4_Key* sm4_key, const uint8_t* iv) {
    uint8_t temp[16];
    uint8_t prev_block[16];
    size_t blocks = length / 16;
    
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < blocks; i++) {
        // Decrypt
        SM4_Decrypt_Fast(ciphertext + i * 16, temp, sm4_key);
        
        // XOR with previous block
        for (int j = 0; j < 16; j++) {
            plaintext[i * 16 + j] = temp[j] ^ prev_block[j];
        }
        
        // Update previous block
        memcpy(prev_block, ciphertext + i * 16, 16);
    }
}


void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");
}
int main() {
    printf("SM4 加密算法实现测试\n");
    printf("====================\n\n");
    
    // 初始化查表
    SM4_InitTables();
    
    // 标准测试向量
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // 密钥初始化
    SM4_Key sm4_key;
    SM4_KeyInit(key, &sm4_key);
    
    // 基础测试
    printf("1. 基础加密解密测试\n");
    print_hex("密钥", key, 16);
    print_hex("明文", plaintext, 16);
    
    SM4_Encrypt(plaintext, ciphertext, &sm4_key);
    print_hex("密文", ciphertext, 16);
    
    SM4_Decrypt(ciphertext, decrypted, &sm4_key);
    print_hex("解密", decrypted, 16);

    return 0;
}
