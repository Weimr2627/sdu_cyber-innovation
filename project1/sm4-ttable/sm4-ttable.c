#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// SM4 S-box
const uint8_t sbox_table[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa6, 0xc6, 0xe2, 0xb2, 0xcb, 0xad, 0x0c, 0xa4, 0x85, 0x4e, 0xcf, 0x6a, 0x15,
    0xc1, 0x0a, 0x8a, 0xe8, 0x4c, 0x1b, 0xee, 0xb5, 0xae, 0x1e, 0xd0, 0x8b, 0x9e, 0x5b, 0x07, 0x0d,
    0x20, 0xf5, 0xf7, 0x59, 0x68, 0x7b, 0x22, 0x0a, 0xbe, 0x4a, 0xcf, 0x5a, 0x09, 0x63, 0x02, 0x24,
    0x87, 0x5e, 0x3e, 0x4b, 0x01, 0xf6, 0x12, 0x83, 0x2a, 0x52, 0x66, 0x5e, 0x53, 0x8c, 0xf0, 0x4d,
    0xea, 0x66, 0x2c, 0x34, 0x92, 0x1c, 0x5e, 0x83, 0x09, 0x2a, 0x9d, 0x0b, 0x8c, 0x87, 0x5f, 0x6f,
    0xa0, 0x1c, 0xfc, 0x5f, 0x71, 0x27, 0xc4, 0xa1, 0x8a, 0xce, 0x29, 0x69, 0x36, 0x48, 0x3a, 0x75,
    0x95, 0x8d, 0x3e, 0x53, 0x2d, 0x3d, 0x0b, 0x9a, 0x4e, 0x18, 0x03, 0x99, 0x6d, 0xf3, 0x3e, 0x6d,
    0x8b, 0x7b, 0x5c, 0xa3, 0x8f, 0x3d, 0x2c, 0x2f, 0x0c, 0xa4, 0x85, 0x1b, 0x6f, 0x31, 0x07, 0x7d,
    0x40, 0xf3, 0x23, 0xf4, 0x3e, 0x4c, 0x92, 0x2f, 0x54, 0x66, 0x3b, 0xc4, 0x7a, 0x07, 0x50, 0x3f,
    0x42, 0x91, 0x9c, 0x2a, 0x4d, 0x6d, 0x4a, 0x6f, 0x15, 0x58, 0x02, 0x71, 0x26, 0x44, 0xa1, 0x13,
    0x8d, 0x50, 0x1e, 0x29, 0x8f, 0x08, 0xf4, 0x7e, 0x6e, 0x0c, 0x2d, 0x1f, 0x12, 0x6b, 0x9f, 0x88,
    0x4e, 0x22, 0x3d, 0x8e, 0x68, 0x7f, 0x29, 0xcf, 0x28, 0x2b, 0x6e, 0x7b, 0xc4, 0x21, 0xc9, 0x34,
    0x9d, 0x01, 0x10, 0xb3, 0x32, 0x6e, 0x7d, 0x78, 0x3d, 0x2d, 0x1c, 0xa2, 0x26, 0x79, 0x3d, 0x88
};

// SM4 固定参数（FK）和密码参数（CK）
const uint32_t fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
const uint32_t ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939a9f,
    0xa6ad, 0xb2b9c0c7, 0xcecfd0d7, 0xdee5ecf3, 0xf8f9fafb, 0xfcfdfefe,
    0xff000102, 0x03040506, 0x0708090a, 0x0b0c0d0e, 0x0f101112, 0x13141516,
    0x1718191a, 0x1b1c1d1e, 0x1f202122, 0x23242526, 0x2728292a, 0x2b2c2d2e,
    0x2f303132, 0x33343536, 0x3738393a, 0x3b3c3d3e, 0x3f404142, 0x43444546,
    0x4748494a, 0x4b4c4d4e
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

// T-table
// T-table 将 S-box 和 L线性变换结合。
// T[i] = L(S-box(i))
static uint32_t t_table_L[256];

// 预计算T-table
static void sm4_gen_t_table() {
    int i;
    for (i = 0; i < 256; i++) {
        uint32_t t = (uint32_t)sbox_table[i];
        t_table_L[i] = t ^ ROL(t, 2) ^ ROL(t, 10) ^ ROL(t, 18) ^ ROL(t, 24);
    }
}

// SM4轮函数F的优化版本
static uint32_t sm4_round_F_t_table(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t t = x1 ^ x2 ^ x3 ^ rk;
    
    // 使用T-table查找
    uint32_t y = t_table_L[(t >> 24) & 0xff] ^
                 t_table_L[(t >> 16) & 0xff] ^
                 t_table_L[(t >> 8) & 0xff] ^
                 t_table_L[t & 0xff];

    return x0 ^ y;
}

// SM4密钥扩展（与基础版本相同）
void sm4_key_expand(const uint8_t *key, uint32_t *rks) {
    uint32_t mk[4];
    uint32_t k[4];
    int i;

    mk[0] = get_u32(key);
    mk[1] = get_u32(key + 4);
    mk[2] = get_u32(key + 8);
    mk[3] = get_u32(key + 12);

    k[0] = mk[0] ^ fk[0];
    k[1] = mk[1] ^ fk[1];
    k[2] = k[2] ^ fk[2];
    k[3] = mk[3] ^ fk[3];

    for (i = 0; i < 32; i++) {
        uint32_t t = k[1] ^ k[2] ^ k[3] ^ ck[i];
        uint32_t temp = (uint32_t)sbox_table[(t >> 24) & 0xff] << 24 |
                        (uint32_t)sbox_table[(t >> 16) & 0xff] << 16 |
                        (uint32_t)sbox_table[(t >> 8) & 0xff] << 8 |
                        (uint32_t)sbox_table[t & 0xff];
        
        // 线性变换L'
        rks[i] = temp ^ ROL(temp, 13) ^ ROL(temp, 23);
        k[0] ^= rks[i];
        k[1] = k[0];
        k[2] = k[1];
        k[3] = k[2];
    }
}

// T-table 优化版 SM4加密
void sm4_encrypt_t_table(const uint8_t *in, uint8_t *out, const uint32_t *rks) {
    uint32_t x[36];
    int i;

    x[0] = get_u32(in);
    x[1] = get_u32(in + 4);
    x[2] = get_u32(in + 8);
    x[3] = get_u32(in + 12);

    for (i = 0; i < 32; i++) {
        x[i + 4] = sm4_round_F_t_table(x[i], x[i + 1], x[i + 2], x[i + 3], rks[i]);
    }

    put_u32(x[35], out);
    put_u32(x[34], out + 4);
    put_u32(x[33], out + 8);
    put_u32(x[32], out + 12);
}

// T-table 优化版 SM4解密
void sm4_decrypt_t_table(const uint8_t *in, uint8_t *out, const uint32_t *rks) {
    uint32_t x[36];
    int i;

    x[0] = get_u32(in);
    x[1] = get_u32(in + 4);
    x[2] = get_u32(in + 8);
    x[3] = get_u32(in + 12);

    for (i = 0; i < 32; i++) {
        x[i + 4] = sm4_round_F_t_table(x[i], x[i + 1], x[i + 2], x[i + 3], rks[31 - i]);
    }

    put_u32(x[35], out);
    put_u32(x[34], out + 4);
    put_u32(x[33], out + 8);
    put_u32(x[32], out + 12);
}

// 性能测试函数 (针对T-table优化版本)
void sm4_test_performance_t_table(
    const uint8_t *plaintext,
    const uint32_t *rks
) {
    uint8_t ciphertext[16];
    clock_t start, end;
    double cpu_time_used;
    long long i;

    printf("SM4 T-table优化版本性能测试:\n");
    printf("--------------------------------------------\n");

    start = clock();
    for (i = 0; i < NUM_ITERATIONS; i++) {
        sm4_encrypt_t_table(plaintext, ciphertext, rks);
    }
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("加密轮次: %lld\n", (long long)NUM_ITERATIONS);
    printf("总耗时: %f 秒\n", cpu_time_used);
    printf("每次加密平均耗时: %f 微秒\n", (cpu_time_used / NUM_ITERATIONS) * 1e6);
    printf("--------------------------------------------\n");
}


int main() {
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plaintext[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t ciphertext[16];
    uint8_t decrypted_text[16];
    uint32_t rks[32];

    // 在使用T-table之前预先生成
    sm4_gen_t_table();

    // 密钥扩展
    sm4_key_expand(key, rks);

    // 加密
    sm4_encrypt_t_table(plaintext, ciphertext, rks);

    printf("原始明文 (前16字节): ");
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");

    
   // 解密
    sm4_decrypt_t_table(ciphertext, decrypted_text, rks);
    
    printf("解密结果 (前16字节):  ");
    for (int i = 0; i < 16; i++) printf("%02x ", decrypted_text[i]);
    printf("\n");
    // 加密
    
    
    
    
    // 验证解密结果
    if (memcmp(plaintext, decrypted_text, 16) == 0) {
        printf("加密与解密成功！\n");
    } else {
        printf("加密与解密失败！\n");
    }

    // 性能测试
    sm4_test_performance_t_table(plaintext, rks);

    return 0;
}
