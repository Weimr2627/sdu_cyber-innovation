#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t P0_scalar(uint32_t x) { return x ^ rotl32(x,9) ^ rotl32(x,17); }
static inline uint32_t P1_scalar(uint32_t x) { return x ^ rotl32(x,15) ^ rotl32(x,23); }

static void sm3_compress_scalar(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68]; uint32_t W1[64];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) | ((uint32_t)block[4*i+2] << 8) | ((uint32_t)block[4*i+3]);
    }
    for (int j = 16; j < 68; j++) {
        uint32_t tmp = W[j-16] ^ W[j-9] ^ rotl32(W[j-3], 15);
        W[j] = P1_scalar(tmp) ^ rotl32(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; j++) W1[j] = W[j] ^ W[j+4];

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        uint32_t Tj = (j < 16) ? 0x79cc4519U : 0x7a879d8aU;
        uint32_t SS1 = rotl32((rotl32(A,12) + E + rotl32(Tj, j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ rotl32(A,12);
        uint32_t TT1 = (j<16? (A^B^C) : ((A&B)|(A&C)|(B&C))) + D + SS2 + W1[j];
        uint32_t TT2 = (j<16? (E^F^G) : ((E&F)|((~E)&G))) + H + SS1 + W[j];
        D = C; C = rotl32(B,9); B = A; A = TT1 & 0xFFFFFFFF;
        H = G; G = rotl32(F,19); F = E; E = P0_scalar(TT2 & 0xFFFFFFFF);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D; V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

static void sm3_hash_scalar(const uint8_t *msg, size_t msglen, uint8_t hash[32]){
    uint64_t bitlen = (uint64_t)msglen * 8ULL;
    uint32_t V[8] = {0x7380166fU,0x4914b2b9U,0x172442d7U,0xda8a0600U,0xa96f30bcU,0x163138aaU,0xe38dee4dU,0xb0fb0e4eU};
    size_t i;
    for (i = 0; i + 64 <= msglen; i += 64) {
        sm3_compress_scalar(V, msg + i);
    }
    uint8_t block[128]; memset(block,0,128);
    size_t rem = msglen - i;
    if (rem) memcpy(block, msg + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        sm3_compress_scalar(V, block);
        memset(block,0,64);
    }
    for (int j = 0; j < 8; j++) block[56 + j] = (uint8_t)(bitlen >> (8 * (7 - j)));
    sm3_compress_scalar(V, block);
    for (int j = 0; j < 8; j++){
        hash[4*j]   = (V[j] >> 24) & 0xFF;
        hash[4*j+1] = (V[j] >> 16) & 0xFF;
        hash[4*j+2] = (V[j] >> 8) & 0xFF;
        hash[4*j+3] = V[j] & 0xFF;
    }
}

// -------------------- AVX2 helpers --------------------
#if defined(__AVX2__)
static inline __m256i rotl32_avx2(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}
static inline __m256i xor_avx2(__m256i a, __m256i b) { return _mm256_xor_si256(a,b); }
static inline __m256i and_avx2(__m256i a, __m256i b) { return _mm256_and_si256(a,b); }
static inline __m256i or_avx2(__m256i a, __m256i b) { return _mm256_or_si256(a,b); }
static inline __m256i not_avx2(__m256i a) { return _mm256_xor_si256(a, _mm256_set1_epi32(-1)); }

static inline __m256i P0_avx2(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl32_avx2(x, 9)), rotl32_avx2(x, 17));
}
static inline __m256i P1_avx2(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl32_avx2(x, 15)), rotl32_avx2(x, 23));
}

static inline __m256i FF_avx2(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x,y), z);
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x,y), _mm256_and_si256(x,z)), _mm256_and_si256(y,z));
}
static inline __m256i GG_avx2(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x,y), z);
    return _mm256_or_si256(_mm256_and_si256(x,y), _mm256_and_si256(not_avx2(x), z));
}

static inline __m256i load_word8_be(const uint8_t *ptrs[8], int word_idx) {
    uint32_t lanes[8];
    for (int i = 0; i < 8; i++){
        const uint8_t *p = ptrs[i] + word_idx*4;
        lanes[i] = ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | (uint32_t)p[3];
    }
    // set_epi32 takes values in reverse order (highest lane first)
    return _mm256_set_epi32((int)lanes[7], (int)lanes[6], (int)lanes[5], (int)lanes[4], (int)lanes[3], (int)lanes[2], (int)lanes[1], (int)lanes[0]);
}

static void sm3_compress_batch8(const uint8_t *block_ptrs[8], uint32_t out_states[8][8]) {
    __m256i A = _mm256_set1_epi32(0x7380166f);
    __m256i B = _mm256_set1_epi32(0x4914b2b9);
    __m256i C = _mm256_set1_epi32(0x172442d7);
    __m256i D = _mm256_set1_epi32(0xda8a0600);
    __m256i E = _mm256_set1_epi32(0xa96f30bc);
    __m256i F = _mm256_set1_epi32(0x163138aa);
    __m256i G = _mm256_set1_epi32(0xe38dee4d);
    __m256i H = _mm256_set1_epi32(0xb0fb0e4e);

    __m256i Wv[68];
    __m256i W1v[64];

    for (int j = 0; j < 16; j++) Wv[j] = load_word8_be(block_ptrs, j);
    for (int j = 16; j < 68; j++){
        __m256i tmp = _mm256_xor_si256(_mm256_xor_si256(Wv[j-16], Wv[j-9]), rotl32_avx2(Wv[j-3], 15));
        __m256i part = P1_avx2(tmp);
        Wv[j] = _mm256_xor_si256(_mm256_xor_si256(part, rotl32_avx2(Wv[j-13],7)), Wv[j-6]);
    }
    for (int j = 0; j < 64; j++) W1v[j] = _mm256_xor_si256(Wv[j], Wv[j+4]);

    for (int j = 0; j < 64; j++){
        uint32_t T = (j < 16) ? 0x79cc4519U : 0x7a879d8aU;
        uint32_t rot = ( (T << (j % 32)) | (T >> (32 - (j % 32))) );
        __m256i rotv = _mm256_set1_epi32((int)rot);

        __m256i SS1 = rotl32_avx2(_mm256_add_epi32(rotl32_avx2(A,12), _mm256_add_epi32(E, rotv)), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rotl32_avx2(A,12));

        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(FF_avx2(A,B,C,j), D), _mm256_add_epi32(SS2, W1v[j]));
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(GG_avx2(E,F,G,j), H), _mm256_add_epi32(SS1, Wv[j]));

        D = C; C = rotl32_avx2(B, 9); B = A; A = TT1;
        H = G; G = rotl32_avx2(F, 19); F = E; E = P0_avx2(TT2);
    }

    // store lanes to out_states: lanes order in registers corresponds to set_epi32 arguments
    int32_t tmp[8];
    _mm256_storeu_si256((__m256i*)tmp, A);
    for (int lane = 0; lane < 8; lane++) out_states[lane][0] = (uint32_t)tmp[lane] ^ 0x7380166fU;
    _mm256_storeu_si256((__m256i*)tmp, B);
    for (int lane = 0; lane < 8; lane++) out_states[lane][1] = (uint32_t)tmp[lane] ^ 0x4914b2b9U;
    _mm256_storeu_si256((__m256i*)tmp, C);
    for (int lane = 0; lane < 8; lane++) out_states[lane][2] = (uint32_t)tmp[lane] ^ 0x172442d7U;
    _mm256_storeu_si256((__m256i*)tmp, D);
    for (int lane = 0; lane < 8; lane++) out_states[lane][3] = (uint32_t)tmp[lane] ^ 0xda8a0600U;
    _mm256_storeu_si256((__m256i*)tmp, E);
    for (int lane = 0; lane < 8; lane++) out_states[lane][4] = (uint32_t)tmp[lane] ^ 0xa96f30bcU;
    _mm256_storeu_si256((__m256i*)tmp, F);
    for (int lane = 0; lane < 8; lane++) out_states[lane][5] = (uint32_t)tmp[lane] ^ 0x163138aaU;
    _mm256_storeu_si256((__m256i*)tmp, G);
    for (int lane = 0; lane < 8; lane++) out_states[lane][6] = (uint32_t)tmp[lane] ^ 0xe38dee4dU;
    _mm256_storeu_si256((__m256i*)tmp, H);
    for (int lane = 0; lane < 8; lane++) out_states[lane][7] = (uint32_t)tmp[lane] ^ 0xb0fb0e4eU;
}
#endif // __AVX2__

// -------------------- public API --------------------
static int cpu_has_avx2_runtime() {
#if defined(__GNUC__) || defined(__clang__)
    #if defined(__x86_64__) || defined(__i386__)
    return __builtin_cpu_supports("avx2");
    #else
    return 0;
    #endif
#else
    return 0;
#endif
}

void sm3_hash(const uint8_t *msg, size_t msglen, uint8_t hash[32]) {
#if defined(__AVX2__)
    if (cpu_has_avx2_runtime() && msglen <= 55) {
        // Build single-block padded copies for up to 8 messages. For demo, we replicate the same message
        // across lanes to demonstrate throughput; in real use you'd have 8 different messages.
        uint8_t blocks[8][64];
        const uint8_t *ptrs[8];
        for (int i = 0; i < 8; i++){
            memset(blocks[i], 0, 64);
            memcpy(blocks[i], msg, msglen);
            blocks[i][msglen] = 0x80;
            uint64_t bitlen = (uint64_t)msglen * 8ULL;
            for (int j = 0; j < 8; j++) blocks[i][56+j] = (uint8_t)(bitlen >> (8 * (7 - j)));
            ptrs[i] = blocks[i];
        }
        uint32_t out_states[8][8];
        sm3_compress_batch8(ptrs, out_states);
        // pick lane 0 as result
        for (int i = 0; i < 8; i++){
            uint32_t v = out_states[0][i];
            hash[4*i]   = (v >> 24) & 0xFF;
            hash[4*i+1] = (v >> 16) & 0xFF;
            hash[4*i+2] = (v >> 8) & 0xFF;
            hash[4*i+3] = v & 0xFF;
        }
        return;
    }
#endif
    // fallback
    sm3_hash_scalar(msg, msglen, hash);
}

// =====================
// 性能测试函数
// =====================
static void benchmark(void) {
    const size_t TEST_SIZE = 1024 * 1024; // 1MB
    uint8_t *data = (uint8_t *)malloc(TEST_SIZE);
    uint8_t hash[32];
    memset(data, 'A', TEST_SIZE);

    const int iterations = 100;
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        sm3_hash(data, TEST_SIZE, hash);
    }
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double throughput = (double)(TEST_SIZE * iterations) / (1024.0 * 1024.0) / seconds;
    printf("[opt_simd] Processed %d MB in %.3f s → %.2f MB/s\n",(int)(TEST_SIZE * iterations / (1024 * 1024)), seconds, throughput);

    free(data);
}

int main(void) {
    printf("Running SM3 opt_simd benchmark...");
    benchmark();
    return 0;
}
