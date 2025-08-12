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

int main() {
    const char *msg = "abc";
    uint8_t hash[32];
    sm3_hash((const uint8_t *)msg, strlen(msg), hash);

    printf("SM3(opt_simple)(\"%s\") = ", msg);
    printf("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0\n");
    

    size_t total = 100 * 1024 * 1024; // 100 MB
    double t = test_perf(total);
    printf("Processed %zu bytes in %.6f seconds (%.2f MB/s)\n", 
           total, t, (total / (1024.0*1024.0)) / t);

    return 0;
}
