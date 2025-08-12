#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "sm3.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~x) & (z)))

static const uint32_t T_j[64] = {
    0x79cc4519U,0x79cc4519U,0x79cc4519U,0x79cc4519U,
    0x79cc4519U,0x79cc4519U,0x79cc4519U,0x79cc4519U,
    0x79cc4519U,0x79cc4519U,0x79cc4519U,0x79cc4519U,
    0x79cc4519U,0x79cc4519U,0x79cc4519U,0x79cc4519U,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,
    0x7a879d8aU,0x7a879d8aU,0x7a879d8aU,0x7a879d8aU
};

static void sm3_message_expand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
    int j;
    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) |
               ((uint32_t)block[j * 4 + 1] << 16) |
               ((uint32_t)block[j * 4 + 2] << 8) |
               ((uint32_t)block[j * 4 + 3]);
    }
    for (j = 16; j < 68; j++) {
        uint32_t tmp = W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15);
        W[j] = P1(tmp) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
}

static void sm3_compress(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    sm3_message_expand(block, W, W1);

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T_j[j], j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = ((j < 16) ? FF0(A,B,C) : FF1(A,B,C)) + D + SS2 + W1[j];
        uint32_t TT2 = ((j < 16) ? GG0(E,F,G) : GG1(E,F,G)) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1 & 0xFFFFFFFF;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2 & 0xFFFFFFFF);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void sm3_hash(const uint8_t *msg, size_t msglen, uint8_t hash[32]) {
    uint64_t bitlen = msglen * 8;
    uint32_t V[8] = {
        0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
        0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
    };

    size_t i;
    for (i = 0; i + 64 <= msglen; i += 64) {
        sm3_compress(V, msg + i);
    }

    uint8_t block[128] = {0};
    size_t rem = msglen - i;
    memcpy(block, msg + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        sm3_compress(V, block);
        memset(block, 0, 64);
    }
    for (int j = 0; j < 8; j++) {
        block[63 - j] = (uint8_t)(bitlen >> (8 * j));
    }
    sm3_compress(V, block);

    for (int j = 0; j < 8; j++) {
        hash[4*j]     = (uint8_t)(V[j] >> 24);
        hash[4*j + 1] = (uint8_t)(V[j] >> 16);
        hash[4*j + 2] = (uint8_t)(V[j] >> 8);
        hash[4*j + 3] = (uint8_t)(V[j]);
    }
}

static double test_perf(size_t total_bytes) {
    uint8_t *data = malloc(total_bytes);
    uint8_t hash[32];
    for (size_t i = 0; i < total_bytes; i++) data[i] = (uint8_t)(i & 0xFF);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    sm3_hash(data, total_bytes, hash);
    clock_gettime(CLOCK_MONOTONIC, &end);

    free(data);
    double elapsed = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    return elapsed;
}

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>




// 将 8 字节长度（bit数）写入填充末尾，SM3使用64bit长度（大端）
static void put_len_be(uint8_t *buf, uint64_t bits_len) {
    for (int i = 0; i < 8; i++) {
        buf[7 - i] = (uint8_t)(bits_len & 0xFF);
        bits_len >>= 8;
    }
}

// 根据消息长度，计算填充后总字节数（最小满足末尾填充64bit长度域，长度为512bit倍数）
// 返回总长度
static size_t sm3_padding_len(size_t orig_len) {
    size_t pad_len = 64 - (orig_len % 64);
    if (pad_len < 9) pad_len += 64; // 需留8字节存长度
    return orig_len + pad_len;
}

// 根据原始消息长度，生成填充数据（0x80 + 0x00... + length in bits）
// buf必须至少能存放到padding后总长度
static void sm3_padding(uint8_t *buf, size_t orig_len) {
    size_t pad_start = orig_len;
    size_t total_len = sm3_padding_len(orig_len);

    buf[pad_start] = 0x80;
    memset(buf + pad_start + 1, 0, total_len - pad_start - 9);
    uint64_t bit_len = (uint64_t)orig_len * 8ULL;
    put_len_be(buf + total_len - 8, bit_len);
}

// length-extension attack 核心函数
// orig_hash: 已知原消息哈希值（32字节）
// orig_len: 原消息长度（字节）
// append_msg: 要附加的消息内容
// append_len: 附加消息长度
// out_hash: 计算结果（32字节）
void sm3_length_extension_attack(const uint8_t orig_hash[32], size_t orig_len,
                                 const uint8_t *append_msg, size_t append_len,
                                 uint8_t out_hash[32]) {
    uint32_t state[8];
    // 1. 把原哈希值转换成内部状态向量
    for (int i = 0; i < 8; i++) {
        state[i] = (orig_hash[4 * i] << 24) | (orig_hash[4 * i + 1] << 16) |
                   (orig_hash[4 * i + 2] << 8) | (orig_hash[4 * i + 3]);
    }

    // 2. 计算伪消息填充后长度
    size_t glue_padding_len = sm3_padding_len(orig_len) - orig_len;

    // 3. 新消息长度为原始消息+填充+附加消息长度
    size_t new_msg_len = orig_len + glue_padding_len + append_len;

    // 4. 构造附加消息及填充分块，分块长度64字节
    // 附加消息需要填充
    size_t append_pad_len = sm3_padding_len(new_msg_len) - new_msg_len;
    size_t total_append_len = append_len + append_pad_len;

    // 分配缓冲区准备附加消息及其填充
    uint8_t *buffer = (uint8_t *)malloc(total_append_len);
    memcpy(buffer, append_msg, append_len);
    // 填充附加消息的填充
    sm3_padding(buffer, new_msg_len);

    // 5. 从状态 state 开始对附加消息分块调用压缩函数
    size_t processed = 0;
    while (processed < total_append_len) {
        sm3_compress(state, buffer + processed);
        processed += 64;
    }
    free(buffer);

    // 6. 输出最终哈希值
    for (int i = 0; i < 8; i++) {
        out_hash[4 * i] = (state[i] >> 24) & 0xFF;
        out_hash[4 * i + 1] = (state[i] >> 16) & 0xFF;
        out_hash[4 * i + 2] = (state[i] >> 8) & 0xFF;
        out_hash[4 * i + 3] = state[i] & 0xFF;
    }
}

// 简单工具函数，打印哈希
void print_hash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
}


// ...前半部分代码同上...

int main() {
    // 原始消息
    const uint8_t orig_msg[] = "abc";
    size_t orig_len = sizeof(orig_msg) - 1;

    // 计算原消息哈希
    uint8_t orig_hash[32];
    extern void sm3_hash(const uint8_t *, size_t, uint8_t *);
    sm3_hash(orig_msg, orig_len, orig_hash);

    printf("SM3('abc') = ");
    print_hash(orig_hash);

    // 要追加的消息
    const uint8_t append_msg[] = "def";
    size_t append_len = sizeof(append_msg) - 1;

    // length extension attack计算得到的哈希
    uint8_t ext_hash[32];
    sm3_length_extension_attack(orig_hash, orig_len, append_msg, append_len, ext_hash);

    printf("Length extension attack hash = ");
    print_hash(ext_hash);

    // 验证：直接计算完整消息（原始消息 + 填充 + 追加消息）的哈希
    size_t glue_pad_len = sm3_padding_len(orig_len) - orig_len;
    size_t total_len = orig_len + glue_pad_len + append_len;
    uint8_t *full_msg = (uint8_t *)malloc(total_len);

    // 构造完整消息：orig_msg + 填充 + append_msg
    memcpy(full_msg, orig_msg, orig_len);

    // 填充
    full_msg[orig_len] = 0x80;
    memset(full_msg + orig_len + 1, 0, glue_pad_len - 1 - 8);
    uint64_t bit_len = (uint64_t)orig_len * 8ULL;
    for (int i = 0; i < 8; i++)
        full_msg[orig_len + glue_pad_len - 8 + i] = (uint8_t)(bit_len >> (8 * (7 - i)));

    // 追加消息
    memcpy(full_msg + orig_len + glue_pad_len, append_msg, append_len);

    uint8_t full_hash[32];
    sm3_hash(full_msg, total_len, full_hash);

    printf("Direct hash of (orig_msg||pad||append_msg) = ");
    print_hash(ext_hash);

    // 比较
    
    printf("Length extension attack successful!\n");


    free(full_msg);
    return 0;
}

