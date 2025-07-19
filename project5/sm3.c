#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// SM3算法常量
#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE 64

// SM3上下文结构
typedef struct {
    uint32_t state[8];          // 哈希状态
    uint64_t count;             // 已处理的位数
    unsigned char buffer[64];   // 输入缓冲区
} SM3_CTX;

// 左循环移位
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3常量T
static uint32_t T(int j) {
    if (j >= 0 && j <= 15) {
        return 0x79CC4519;
    } else if (j >= 16 && j <= 63) {
        return 0x7A879D8A;
    }
    return 0;
}

// 布尔函数FF
static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    } else if (j >= 16 && j <= 63) {
        return (x & y) | (x & z) | (y & z);
    }
    return 0;
}

// 布尔函数GG
static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    } else if (j >= 16 && j <= 63) {
        return (x & y) | (~x & z);
    }
    return 0;
}

// 置换函数P0
static uint32_t P0(uint32_t x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

// 置换函数P1
static uint32_t P1(uint32_t x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// 字节序转换（大端序）
static uint32_t load_bigendian_32(const unsigned char *x) {
    return ((uint32_t)(x[0]) << 24) | 
           ((uint32_t)(x[1]) << 16) | 
           ((uint32_t)(x[2]) << 8) | 
           ((uint32_t)(x[3]));
}

static void store_bigendian_32(unsigned char *x, uint32_t u) {
    x[0] = u >> 24;
    x[1] = u >> 16;
    x[2] = u >> 8;
    x[3] = u;
}

// SM3初始化
void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
    ctx->count = 0;
}

// SM3压缩函数
static void sm3_compress(SM3_CTX *ctx, const unsigned char block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int i;

    // 消息扩展
    for (i = 0; i < 16; i++) {
        W[i] = load_bigendian_32(block + i * 4);
    }

    for (i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL(W[i-3], 15)) ^ ROTL(W[i-13], 7) ^ W[i-6];
    }

    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }

    // 压缩函数
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (i = 0; i < 64; i++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T(i), i)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF(A, B, C, i) + D + SS2 + W1[i];
        TT2 = GG(E, F, G, i) + H + SS1 + W[i];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);

        A &= 0xFFFFFFFF;
        B &= 0xFFFFFFFF;
        C &= 0xFFFFFFFF;
        D &= 0xFFFFFFFF;
        E &= 0xFFFFFFFF;
        F &= 0xFFFFFFFF;
        G &= 0xFFFFFFFF;
        H &= 0xFFFFFFFF;
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// SM3更新
void sm3_update(SM3_CTX *ctx, const unsigned char *data, size_t len) {
    size_t partial, left;

    partial = ctx->count % 64;
    ctx->count += len;
    left = 64 - partial;

    if (len >= left) {
        memcpy(ctx->buffer + partial, data, left);
        sm3_compress(ctx, ctx->buffer);
        data += left;
        len -= left;
        partial = 0;

        while (len >= 64) {
            sm3_compress(ctx, data);
            data += 64;
            len -= 64;
        }
    }

    if (len) {
        memcpy(ctx->buffer + partial, data, len);
    }
}

// SM3终结
void sm3_final(SM3_CTX *ctx, unsigned char digest[SM3_DIGEST_LENGTH]) {
    size_t partial = ctx->count % 64;
    uint64_t bits = ctx->count * 8;
    int i;

    ctx->buffer[partial++] = 0x80;

    if (partial > 56) {
        memset(ctx->buffer + partial, 0, 64 - partial);
        sm3_compress(ctx, ctx->buffer);
        partial = 0;
    }

    memset(ctx->buffer + partial, 0, 56 - partial);

    // 添加长度（大端序）
    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (bits >> (8 * (7 - i))) & 0xFF;
    }

    sm3_compress(ctx, ctx->buffer);

    // 输出哈希值
    for (i = 0; i < 8; i++) {
        store_bigendian_32(digest + i * 4, ctx->state[i]);
    }
}

// 便捷函数：直接计算SM3哈希
void sm3_hash(const unsigned char *data, size_t len, unsigned char digest[SM3_DIGEST_LENGTH]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

// 打印哈希值（十六进制）
void print_hash(const unsigned char *digest) {
    int i;
    for (i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// 测试函数
int main() {
    SM3_CTX ctx;
    unsigned char digest[SM3_DIGEST_LENGTH];
    const char *test_vectors[] = {
        "abc",
        "abcdef",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    };
    int num_tests = 3;
    int i;

    printf("SM3算法测试\n");
    printf("===================\n\n");

    for (i = 0; i < num_tests; i++) {
        printf("测试%d: \"%s\"\n", i + 1, test_vectors[i]);
        
        // 使用便捷函数
        sm3_hash((const unsigned char *)test_vectors[i], strlen(test_vectors[i]), digest);
        printf("哈希值: ");
        print_hash(digest);
        printf("\n");
    }

    // 演示流式处理
    printf("流式处理演示:\n");
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char *)"abc", 3);
    sm3_update(&ctx, (const unsigned char *)"def", 3);
    sm3_final(&ctx, digest);
    printf("\"abcdef\"的哈希值: ");
    print_hash(digest);

    return 0;
}
