#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------
 *  Refactored SM3 + Merkle Tree (C99)
 *  功能保持一致，命名与结构做了重构
 * ------------------------------------ */

#define SM3_DIGEST_SIZE 32u
#define SM3_BLOCK_SIZE  64u

/* ===================== SM3 ===================== */
static const uint32_t kSM3IV[8] = {
    0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
    0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
};

static const uint32_t kT[64] = {
    /* j = 0..15 -> 0x79CC4519, j = 16..63 -> 0x7A879D8A */
    0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,
    0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,
    0x79CC4519u,0x79CC4519u,0x79CC4519u,0x79CC4519u,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,
    0x7A879D8Au,0x7A879D8Au,0x7A879D8Au,0x7A879D8Au
};

static inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

static inline uint32_t P0(uint32_t x) { return x ^ rotl32(x,9) ^ rotl32(x,17); }
static inline uint32_t P1(uint32_t x) { return x ^ rotl32(x,15) ^ rotl32(x,23); }

static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void store_be32(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

typedef struct {
    uint64_t total_bytes;
    uint32_t s[8];
    uint8_t  buf[SM3_BLOCK_SIZE];
    uint32_t buf_used; /* 0..63 */
} sm3_ctx;

static void sm3_compress(uint32_t s[8], const uint8_t blk[64]) {
    uint32_t W[68];
    uint32_t Wp[64];

    for (int j = 0; j < 16; ++j) W[j] = load_be32(blk + (j<<2));
    for (int j = 16; j < 68; ++j) {
        uint32_t t = W[j-16] ^ W[j-9] ^ rotl32(W[j-3], 15);
        W[j] = P1(t) ^ rotl32(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; ++j) Wp[j] = W[j] ^ W[j+4];

    uint32_t A = s[0], B = s[1], C = s[2], D = s[3];
    uint32_t E = s[4], F = s[5], G = s[6], H = s[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t tmpA = rotl32(A, 12);
        uint32_t SS1 = rotl32(tmpA + E + rotl32(kT[j], (uint32_t)j), 7);
        uint32_t SS2 = SS1 ^ tmpA;
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + Wp[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C; C = rotl32(B, 9); B = A; A = TT1;
        H = G; G = rotl32(F, 19); F = E; E = P0(TT2);
    }

    s[0] ^= A; s[1] ^= B; s[2] ^= C; s[3] ^= D;
    s[4] ^= E; s[5] ^= F; s[6] ^= G; s[7] ^= H;
}

static void sm3_init(sm3_ctx *c) {
    c->total_bytes = 0;
    c->buf_used = 0;
    memcpy(c->s, kSM3IV, sizeof(kSM3IV));
}

static void sm3_update(sm3_ctx *c, const uint8_t *data, size_t len) {
    c->total_bytes += (uint64_t)len;

    /* 填满缓冲区后压缩 */
    if (c->buf_used) {
        uint32_t n = SM3_BLOCK_SIZE - c->buf_used;
        if (len >= n) {
            memcpy(c->buf + c->buf_used, data, n);
            sm3_compress(c->s, c->buf);
            c->buf_used = 0;
            data += n; len -= n;
        } else {
            memcpy(c->buf + c->buf_used, data, len);
            c->buf_used += (uint32_t)len;
            return;
        }
    }

    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(c->s, data);
        data += SM3_BLOCK_SIZE; len -= SM3_BLOCK_SIZE;
    }

    if (len) {
        memcpy(c->buf, data, len);
        c->buf_used = (uint32_t)len;
    }
}

static void sm3_final(sm3_ctx *c, uint8_t out[SM3_DIGEST_SIZE]) {
    uint8_t pad[SM3_BLOCK_SIZE * 2]; /* 最多需要两个块 */
    memset(pad, 0, sizeof(pad));

    uint64_t bit_len = c->total_bytes * 8ull;
    pad[0] = 0x80;

    uint32_t pad_len;
    if (c->buf_used < 56u) {
        pad_len = 56u - c->buf_used;
    } else {
        pad_len = 56u + 64u - c->buf_used;
    }

    sm3_update(c, pad, pad_len);

    /* 写入长度（大端） */
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) {
        len_be[i] = (uint8_t)((bit_len >> (56 - 8 * i)) & 0xFFu);
    }
    sm3_update(c, len_be, 8);

    for (int i = 0; i < 8; ++i) store_be32(c->s[i], out + (i << 2));
}

static void sm3_digest(const uint8_t *msg, size_t n, uint8_t out[SM3_DIGEST_SIZE]) {
    sm3_ctx c; sm3_init(&c); sm3_update(&c, msg, n); sm3_final(&c, out);
}


typedef struct { uint8_t h[SM3_DIGEST_SIZE]; } mnode;

typedef struct {
    mnode  *v;        /* 节点数组（完全二叉树） */
    size_t  n_leaf;   /* 实际叶子个数 */
    size_t  n_all;    /* 总节点数 = tree_size * 2 - 1 */
} mktree;

static void hash_pair_cat(const uint8_t *a, const uint8_t *b, uint8_t out[SM3_DIGEST_SIZE]) {
    uint8_t tmp[SM3_DIGEST_SIZE * 2];
    memcpy(tmp, a, SM3_DIGEST_SIZE);
    memcpy(tmp + SM3_DIGEST_SIZE, b, SM3_DIGEST_SIZE);
    sm3_digest(tmp, sizeof(tmp), out);
}

static size_t next_pow2(size_t n) {
    size_t x = 1; while (x < n) x <<= 1; return x;
}

static mktree *mk_create(const uint8_t **leaf_data, size_t leaf_cnt) {
    size_t tsz = next_pow2(leaf_cnt);
    size_t nodes = tsz * 2 - 1;

    mktree *t = (mktree*)malloc(sizeof(mktree));
    t->n_leaf = leaf_cnt; t->n_all = nodes;
    t->v = (mnode*)malloc(sizeof(mnode) * nodes);

    /* 叶子在最后 tsz 个位置 */
    size_t base = nodes - tsz;
    for (size_t i = 0; i < tsz; ++i) {
        if (i < leaf_cnt) {
            sm3_digest(leaf_data[i], strlen((const char*)leaf_data[i]), t->v[base + i].h);
        } else {
            memset(t->v[base + i].h, 0, SM3_DIGEST_SIZE);
        }
    }

    for (long long i = (long long)base - 1; i >= 0; --i) {
        hash_pair_cat(t->v[i*2 + 1].h, t->v[i*2 + 2].h, t->v[i].h);
    }
    return t;
}

static void mk_root(const mktree *t, uint8_t out[SM3_DIGEST_SIZE]) {
    memcpy(out, t->v[0].h, SM3_DIGEST_SIZE);
}

/* 证明路径：从叶子到根，记录每层兄弟节点 */
static size_t mk_proof(const mktree *t, size_t leaf_idx,
                       uint8_t proof[][SM3_DIGEST_SIZE], size_t maxlen) {
    size_t tsz = next_pow2(t->n_leaf);
    size_t all = t->n_all;
    size_t idx = all - tsz + leaf_idx;
    size_t used = 0;

    while (idx > 0 && used < maxlen) {
        size_t sib = (idx % 2) ? (idx + 1) : (idx - 1);
        memcpy(proof[used++], t->v[sib].h, SM3_DIGEST_SIZE);
        idx = (idx - 1) / 2;
    }
    return used;
}

static int mk_verify(const uint8_t *leaf_hash, size_t leaf_idx,
                     const uint8_t proof[][SM3_DIGEST_SIZE], size_t proof_len,
                     const uint8_t root[SM3_DIGEST_SIZE]) {
    uint8_t cur[SM3_DIGEST_SIZE];
    memcpy(cur, leaf_hash, SM3_DIGEST_SIZE);

    size_t idx = leaf_idx;
    for (size_t i = 0; i < proof_len; ++i) {
        uint8_t pair[SM3_DIGEST_SIZE * 2];
        if ((idx & 1u) == 0) {
            memcpy(pair, cur, SM3_DIGEST_SIZE);
            memcpy(pair + SM3_DIGEST_SIZE, proof[i], SM3_DIGEST_SIZE);
        } else {
            memcpy(pair, proof[i], SM3_DIGEST_SIZE);
            memcpy(pair + SM3_DIGEST_SIZE, cur, SM3_DIGEST_SIZE);
        }
        sm3_digest(pair, sizeof(pair), cur);
        idx >>= 1;
    }
    return memcmp(cur, root, SM3_DIGEST_SIZE) == 0;
}

static void dump_hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}

/* ========== 排序 Merkle（用于不可包含证明） ========== */
static int hash_cmp_bytes(const void *pa, const void *pb) {
    const mnode *a = (const mnode*)pa;
    const mnode *b = (const mnode*)pb;
    return memcmp(a->h, b->h, SM3_DIGEST_SIZE);
}

static mktree *mk_create_sorted(const uint8_t **leaf_data, size_t leaf_cnt) {
    size_t tsz = next_pow2(leaf_cnt);
    size_t nodes = tsz * 2 - 1;
    mktree *t = (mktree*)malloc(sizeof(mktree));
    t->n_leaf = leaf_cnt; t->n_all = nodes;
    t->v = (mnode*)malloc(sizeof(mnode) * nodes);

    size_t base = nodes - tsz;
    for (size_t i = 0; i < leaf_cnt; ++i) {
        sm3_digest(leaf_data[i], strlen((const char*)leaf_data[i]), t->v[base + i].h);
    }
    /* 排序实际叶子 */
    qsort(t->v + base, leaf_cnt, sizeof(mnode), hash_cmp_bytes);
    for (size_t i = leaf_cnt; i < tsz; ++i) {
        memset(t->v[base + i].h, 0, SM3_DIGEST_SIZE);
    }

    for (long long i = (long long)base - 1; i >= 0; --i) {
        hash_pair_cat(t->v[i*2 + 1].h, t->v[i*2 + 2].h, t->v[i].h);
    }
    return t;
}

static long long mk_find_leaf_idx(const mktree *t, const uint8_t target[SM3_DIGEST_SIZE]) {
    size_t tsz = next_pow2(t->n_leaf);
    size_t base = t->n_all - tsz;
    long long lo = 0, hi = (long long)t->n_leaf - 1;
    while (lo <= hi) {
        long long mid = lo + ((hi - lo) >> 1);
        int c = memcmp(target, t->v[base + (size_t)mid].h, SM3_DIGEST_SIZE);
        if (c == 0) return mid;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}

static void mk_non_inclusion_proof(const mktree *t, const uint8_t target[SM3_DIGEST_SIZE],
                                   uint8_t proofs[2][64][SM3_DIGEST_SIZE], size_t plen[2],
                                   size_t *pred_idx, size_t *succ_idx) {
    size_t tsz = next_pow2(t->n_leaf);
    size_t base = t->n_all - tsz;

    *pred_idx = (size_t)-1; *succ_idx = (size_t)-1;
    plen[0] = plen[1] = 0;

    long long lo = 0, hi = (long long)t->n_leaf - 1;
    while (lo <= hi) {
        long long mid = lo + ((hi - lo) >> 1);
        int c = memcmp(target, t->v[base + (size_t)mid].h, SM3_DIGEST_SIZE);
        if (c == 0) {
            return;
        } else if (c < 0) {
            *succ_idx = (size_t)mid;
            hi = mid - 1;
        } else {
            *pred_idx = (size_t)mid;
            lo = mid + 1;
        }
    }

    if (*pred_idx != (size_t)-1) plen[0] = mk_proof(t, *pred_idx, proofs[0], 64);
    if (*succ_idx != (size_t)-1) plen[1] = mk_proof(t, *succ_idx, proofs[1], 64);
}

static int mk_verify_non_inclusion(const uint8_t target[SM3_DIGEST_SIZE],
                                   const uint8_t *pred_hash, size_t pred_idx,
                                   const uint8_t pred_proof[][SM3_DIGEST_SIZE], size_t pred_len,
                                   const uint8_t *succ_hash, size_t succ_idx,
                                   const uint8_t succ_proof[][SM3_DIGEST_SIZE], size_t succ_len,
                                   const uint8_t root[SM3_DIGEST_SIZE]) {
    int pred_ok = 1, succ_ok = 1;

    if (pred_hash) pred_ok = mk_verify(pred_hash, pred_idx, pred_proof, pred_len, root);
    if (succ_hash) succ_ok = mk_verify(succ_hash, succ_idx, succ_proof, succ_len, root);
    if (!pred_ok || !succ_ok) return 0;

    int ord_ok = 1;
    if (pred_hash && succ_hash) {
        ord_ok = (memcmp(pred_hash, target, SM3_DIGEST_SIZE) < 0) &&
                 (memcmp(target, succ_hash, SM3_DIGEST_SIZE) < 0);
    } else if (pred_hash) {
        ord_ok = (memcmp(pred_hash, target, SM3_DIGEST_SIZE) < 0);
    } else if (succ_hash) {
        ord_ok = (memcmp(target, succ_hash, SM3_DIGEST_SIZE) < 0);
    }
    return ord_ok;
}

static void test_merkle_basic(void) {
    size_t n = 100000; /* 10 万叶子 */

    const uint8_t **leaf = (const uint8_t**)malloc(sizeof(uint8_t*) * n);
    char **buf = (char**)malloc(sizeof(char*) * n);
    for (size_t i = 0; i < n; ++i) {
        buf[i] = (char*)malloc(32);
        (void)snprintf(buf[i], 32, "leaf #%zu data", i);
        leaf[i] = (const uint8_t*)buf[i];
    }

    mktree *t = mk_create(leaf, n);
    uint8_t root[SM3_DIGEST_SIZE];
    mk_root(t, root);

    printf("Merkle 根hash: ");
    dump_hex(root, SM3_DIGEST_SIZE); printf("\n");

    size_t target_idx = 12345;
    uint8_t lhash[SM3_DIGEST_SIZE];
    sm3_digest(leaf[target_idx], strlen((const char*)leaf[target_idx]), lhash);

    uint8_t proof[64][SM3_DIGEST_SIZE];
    size_t plen = mk_proof(t, target_idx, proof, 64);

    printf("树的高度: %zu\n", plen);
    printf("证明叶子节点存在性 %zu... ", target_idx);
    int ok = mk_verify(lhash, target_idx, proof, plen, root);
    printf(ok ? "存在性证明成功!\n" : "存在性证明失败!\n");
    printf("\n\n\n");
    for (size_t i = 0; i < n; ++i) free(buf[i]);
    free(buf); free(leaf);
    free(t->v); free(t);
}

static void test_merkle_non_inclusion(void) {
    printf("\nMerkle Tree 不存在性证明\n");
    

    size_t n = 100000;
    const uint8_t **leaf = (const uint8_t**)malloc(sizeof(uint8_t*) * n);
    char **buf = (char**)malloc(sizeof(char*) * n);
    for (size_t i = 0; i < n; ++i) {
        buf[i] = (char*)malloc(32);
        (void)snprintf(buf[i], 32, "leaf #%zu data", i);
        leaf[i] = (const uint8_t*)buf[i];
    }

    mktree *t = mk_create_sorted(leaf, n);
    uint8_t root[SM3_DIGEST_SIZE];
    mk_root(t, root);

    /* 构造一个不在树中的目标 */
    uint8_t target[SM3_DIGEST_SIZE];
    const char *msg = "this data is not in the tree";
    sm3_digest((const uint8_t*)msg, strlen(msg), target);

    while (mk_find_leaf_idx(t, target) != -1) {
        msg = "modified non-existent data";
        sm3_digest((const uint8_t*)msg, strlen(msg), target);
    }

    printf("Target hash (不在树中): ");
    dump_hex(target, SM3_DIGEST_SIZE); printf("\n");

    uint8_t proofs[2][64][SM3_DIGEST_SIZE];
    size_t plen[2];
    size_t pred_i, succ_i;
    mk_non_inclusion_proof(t, target, proofs, plen, &pred_i, &succ_i);

    printf("Predecessor index: %zu\n, proof length: %zu\n", pred_i, plen[0]);
    printf("Successor index: %zu\n, proof length: %zu\n", succ_i, plen[1]);

    uint8_t *pred_h = NULL, *succ_h = NULL;
    size_t tsz = next_pow2(t->n_leaf);
    size_t base = t->n_all - tsz;

    if (pred_i != (size_t)-1) {
        pred_h = t->v[base + pred_i].h;
        printf("Predecessor hash: "); dump_hex(pred_h, SM3_DIGEST_SIZE); printf("\n");
    }
    if (succ_i != (size_t)-1) {
        succ_h = t->v[base + succ_i].h;
        printf("Successor hash: "); dump_hex(succ_h, SM3_DIGEST_SIZE); printf("\n");
    }

    printf("进行不存在性证明... ");
    int ok = mk_verify_non_inclusion(
        target,
        pred_h, pred_i, proofs[0], plen[0],
        succ_h, succ_i, proofs[1], plen[1],
        root
    );
    printf(ok ? "证明成功!\n" : "失败!\n");
    printf("\n\n\n");
    for (size_t i = 0; i < n; ++i) free(buf[i]);
    free(buf); free(leaf);
    free(t->v); free(t);
}

int main(void) {
    test_merkle_basic();
    test_merkle_non_inclusion();
    return 0;
}
