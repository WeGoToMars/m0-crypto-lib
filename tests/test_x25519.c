/* On-target tests for X25519 (QEMU microbit or a board). Test image only.
 * - RFC 7748 sections 5.2 and 6.1 and every Wycheproof x25519 vector
 *   (tests/x25519_vectors.h), compared on the 32 output bytes. The function has no
 *   low-order check and always returns M0C_OK.
 * - The section 5.2 iteration after 1 and 1,000 steps, and after 1,000,000 steps with
 *   -DX25519_ITER_1M.
 * - Every alignment of the three pointers and the overlaps include/m0crypto/x25519.h allows.
 * - Guard bytes around out.
 * - The AAPCS, register-clearing, stack-depth and stack-clearing statements of the header. */
#include <stddef.h>
#include <stdint.h>
#include "m0crypto/x25519.h"
#include "x25519_vectors.h"

void semihost_write0(const char *s);
int check_call8(void *fn, const uint32_t args[8], uint32_t result[2]);
extern uint32_t cc8_volatile[5];   /* r1, r2, r3, r12, lr as fn returned them */
/* Built with CC8_BYTES = 1024: word i is at SP - 1024 + 4 i. */
#define SNAP_WORDS 256
extern uint32_t stack_snapshot[SNAP_WORDS];

void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
void *memset(void *d, int c, size_t n) {
    uint8_t *dd = d;
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
void __aeabi_memclr(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr4(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr8(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memcpy(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy4(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy8(void *d, const void *s, size_t n) { memcpy(d, s, n); }

static void put_hex(uint32_t v) {
    char b[11] = "0x00000000";
    for (int i = 0; i < 8; i++) b[9 - i] = "0123456789abcdef"[(v >> (4 * i)) & 15];
    semihost_write0(b);
}
static int failures, checks;
static void check(int ok, const char *what, uint32_t a, uint32_t b) {
    checks++;
    if (!ok) {
        failures++;
        semihost_write0("FAIL ");
        semihost_write0(what);
        semihost_write0(" ");
        put_hex(a);
        semihost_write0(" ");
        put_hex(b);
        semihost_write0("\n");
    }
}
static int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

#define GUARD 8
#define FILL 0xa5
/* Disjoint buffers: each holds 32 bytes at offset GUARD + 0..3, with guard bytes around. */
static uint8_t sbuf[32 + 2 * GUARD + 4] __attribute__((aligned(4)));
static uint8_t pbuf[32 + 2 * GUARD + 4] __attribute__((aligned(4)));
static uint8_t obuf[32 + 2 * GUARD + 4] __attribute__((aligned(4)));

/* out at obuf + GUARD + oo holds want, every other byte of obuf is still FILL. */
static int out_ok(size_t oo, const uint8_t *want) {
    for (size_t i = 0; i < sizeof obuf; i++) {
        if (i >= GUARD + oo && i < GUARD + oo + 32) continue;
        if (obuf[i] != FILL) return 0;
    }
    return memeq(obuf + GUARD + oo, want, 32);
}
/* One call on disjoint buffers at the given offsets 0..3; checks result, out and the inputs. */
static void run_disjoint(const struct x25519_vec *v, size_t so, size_t po, size_t oo,
                         const char *what, uint32_t tag) {
    memset(sbuf, FILL, sizeof sbuf);
    memset(pbuf, FILL, sizeof pbuf);
    memset(obuf, FILL, sizeof obuf);
    memcpy(sbuf + GUARD + so, v->scalar, 32);
    memcpy(pbuf + GUARD + po, v->point, 32);
    int r = m0c_x25519(obuf + GUARD + oo, sbuf + GUARD + so, pbuf + GUARD + po);
    check(r == M0C_OK, what, tag, (uint32_t)r);
    check(out_ok(oo, v->shared), what, tag, (uint32_t)(so << 8 | po << 4 | oo));
    check(memeq(sbuf + GUARD + so, v->scalar, 32) && memeq(pbuf + GUARD + po, v->point, 32),
          "inputs unchanged", tag, 0);
}

/* Every vector once; the offsets cycle through all 64 combinations. */
static void test_vectors(void) {
    for (unsigned i = 0; i < X25519_VEC_COUNT; i++) {
        const struct x25519_vec *v = &x25519_vecs[i];
        run_disjoint(v, i & 3, (i >> 2) & 3, (i >> 4) & 3, "vector",
                     (uint32_t)v->source << 16 | v->id);
    }
}

/* All 64 alignments of (out, scalar, point) on RFC 7748 5.2 vector 1. */
static void test_alignment(void) {
    for (size_t so = 0; so < 4; so++)
        for (size_t po = 0; po < 4; po++)
            for (size_t oo = 0; oo < 4; oo++)
                run_disjoint(&x25519_vecs[0], so, po, oo, "alignment", 0);
}

/* Overlaps (the header: any overlap; both inputs are read before out is written). In a 96-byte
 * region R, scalar = R + 32, point = R + 32 + d for d in -32..32, and out at each of: the scalar,
 * the point, halfway between, R + 16 and R + 48 (straddling both), R + 0 and R + 64 (touching
 * only one or neither input when d is large). The region has guard bytes on both sides. */
static uint8_t region[GUARD + 96 + GUARD] __attribute__((aligned(4)));
static void test_overlap(void) {
    for (int d = -32; d <= 32; d++) {
        const uint8_t *want = x25519_overlap[d + 32];
        const int outs[] = {32, 32 + d, 32 + d / 2, 16, 48, 0, 64};
        for (unsigned j = 0; j < sizeof outs / sizeof outs[0]; j++) {
            int o = outs[j];
            memset(region, FILL, sizeof region);
            uint8_t *R = region + GUARD;
            for (int i = 0; i < 96; i++) R[i] = X25519_REGION(i);
            int r = m0c_x25519(R + o, R + 32, R + 32 + d);
            uint32_t tag = (uint32_t)(d + 32) << 8 | (uint32_t)o;
            check(r == M0C_OK, "overlap result", tag, (uint32_t)r);
            check(memeq(R + o, want, 32), "overlap out", tag, 0);
            int rest = 1;
            for (int i = -GUARD; i < 96 + GUARD; i++) {
                if (i >= o && i < o + 32) continue;
                uint8_t e = (i < 0 || i >= 96) ? FILL : X25519_REGION(i);
                if (R[i] != e) rest = 0;
            }
            check(rest, "overlap other bytes", tag, 0);
        }
    }
}

/* RFC 7748 section 5.2: k = u = 9; k, u = X25519(k, u), k. The new k is written over u, which
 * the next step drops anyway: the swap is of pointers (out == point, an allowed overlap). */
static uint8_t ka[32], kb[32];
static void test_iterate(void) {
    uint8_t *k = ka, *u = kb;
    memset(ka, 0, 32); memset(kb, 0, 32);
    ka[0] = kb[0] = 9;
    uint32_t n = 0;
#ifdef X25519_ITER_1M
    const uint32_t last = 1000000;
#else
    const uint32_t last = 1000;
#endif
    while (n < last) {
        m0c_x25519(u, k, u);
        uint8_t *t = k; k = u; u = t;
        n++;
        if (n == 1) check(memeq(k, x25519_iter_1, 32), "iterate 1", n, 0);
        if (n == 1000) check(memeq(k, x25519_iter_1000, 32), "iterate 1000", n, 0);
        if (n == 1000000) check(memeq(k, x25519_iter_1000000, 32), "iterate 1000000", n, 0);
    }
    semihost_write0("iterations run: ");
    put_hex(n);
    semihost_write0("\n");
}

/* AAPCS (r4-r11, sp), the header's clearing (r0-r3 and r12 zero; the 480 bytes below the
 * 36 bytes of saved registers zero), and its 516-byte stack bound, from the caller's view. */
#define STACK_BOUND 516
#define SAVED 36
static uint32_t peak;
static void test_abi(void) {
    static const uint16_t which[] = {0, 2, 10, 500};   /* RFC, RFC 6.1, two Wycheproof */
    for (unsigned w = 0; w < sizeof which / sizeof which[0]; w++) {
        const struct x25519_vec *v = &x25519_vecs[which[w]];
        uint32_t args[8] = {0}, res[2];
        memset(obuf, FILL, sizeof obuf);
        memcpy(sbuf + GUARD + 1, v->scalar, 32);
        memcpy(pbuf + GUARD + 2, v->point, 32);
        args[0] = (uint32_t)(obuf + GUARD + 3);
        args[1] = (uint32_t)(sbuf + GUARD + 1);
        args[2] = (uint32_t)(pbuf + GUARD + 2);
        int r = check_call8((void *)m0c_x25519, args, res);
        check(r == M0C_OK, "abi result", w, (uint32_t)r);
        check(res[0] == 0, "abi callee-saved regs", w, res[0]);
        check(cc8_volatile[0] == 0 && cc8_volatile[1] == 0 && cc8_volatile[2] == 0 &&
              cc8_volatile[3] == 0, "abi r1-r3 r12 zero", w, cc8_volatile[0] | cc8_volatile[1] |
              cc8_volatile[2] | cc8_volatile[3]);
        check(res[1] <= STACK_BOUND, "stack bound", w, res[1]);
        if (res[1] > peak) peak = res[1];
        check(out_ok(3, v->shared), "abi output", w, 0);
        /* Words in [SP - 516, SP - 36) must be zero; below SP - 516 still painted. */
        for (unsigned i = 0; i < SNAP_WORDS; i++) {
            uint32_t below = (SNAP_WORDS - i) * 4;   /* bytes below the call-site SP */
            if (below > STACK_BOUND) check(stack_snapshot[i] == 0xa5a5a5a5u, "stack untouched", w, below);
            else if (below > SAVED) check(stack_snapshot[i] == 0, "stack cleared", w, below);
        }
    }
}

int main(void) {
    test_vectors();
    test_alignment();
    test_overlap();
    test_abi();
    test_iterate();
    semihost_write0("vectors: ");
    put_hex(X25519_VEC_COUNT);
    semihost_write0(" (RFC 7748 5.2: 2, 6.1: 4, Wycheproof: rest)\npeak stack bytes: ");
    put_hex(peak);
    semihost_write0("\n");
    semihost_write0(failures ? "RESULT: FAIL " : "RESULT: PASS ");
    put_hex((uint32_t)checks);
    semihost_write0(" checks\n");
    return failures != 0;
}
