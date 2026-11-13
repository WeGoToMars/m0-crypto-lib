/* On-target tests for ChaCha20-Poly1305 and its Poly1305 core (QEMU microbit or a
 * board). Expected values come from tests/aead_vectors.h (Wycheproof, RFC 8439
 * and pyca/cryptography; see tools/gen_aead_vectors.py). Test image only. */
#include <stddef.h>
#include <stdint.h>
#include "m0crypto/chacha20poly1305.h"
#include "aead_vectors.h"

void semihost_write0(const char *s);
int check_call8(void *fn, const uint32_t args[8], uint32_t result[2]);
extern uint32_t cc8_volatile[5];   /* r1, r2, r3, r12, lr as fn returned them */
extern uint32_t stack_snapshot[128];

/* Internal Poly1305 entry points (src/chacha20poly1305.S): local symbols of the release object,
   defined for this image by tools/test_qemu.sh from their offsets in that object. */
void m0c_poly1305_init(uint32_t ctx[16], const uint8_t key[32]);
void m0c_poly1305_blocks(uint32_t ctx[16], const uint8_t *m, size_t nblocks, uint32_t padbit);
void m0c_poly1305_finish(uint32_t ctx[16], uint8_t tag[16]);

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

static int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int allbyte(const uint8_t *a, uint8_t v, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != v) return 0;
    return 1;
}

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

#define V(off) (&vec_blob[(off)])
/* a mod b without a divide instruction (ARMv6-M has none). */
static uint32_t umod(uint32_t a, uint32_t b) {
    while (a >= b) a -= b;
    return a;
}
#define MAXLEN 1024
#define GUARD 8
static uint8_t bufa[MAXLEN + 2 * GUARD + 4];
static uint8_t bufb[MAXLEN + 2 * GUARD + 4];

/* --- Poly1305 core --- */
/* init requires a 4-byte-aligned key (internal contract); copy it to one. */
static void poly_tag(const uint8_t *key, const uint8_t *m, size_t len, int split,
                     uint8_t tag[16]) {
    uint32_t ctx[16];
    uint32_t kw[8];
    uint8_t *k = (uint8_t *)kw, last[16];
    memcpy(k, key, 32);
    m0c_poly1305_init(ctx, k);
    size_t full = len / 16;
    if (split) {
        for (size_t i = 0; i < full; i++) m0c_poly1305_blocks(ctx, m + 16 * i, 1, 1);
    } else {
        m0c_poly1305_blocks(ctx, m, full, 1);
    }
    size_t rem = len % 16;
    if (rem) {   /* RFC 8439 2.5: final partial block gets a 0x01 byte, no 2^128 bit */
        memset(last, 0, 16);
        memcpy(last, m + 16 * full, rem);
        last[rem] = 1;
        m0c_poly1305_blocks(ctx, last, 1, 0);
    }
    m0c_poly1305_finish(ctx, tag);
}

static void test_poly(void) {
    uint8_t tag[16];
    for (unsigned i = 0; i < sizeof poly_vecs / sizeof poly_vecs[0]; i++) {
        const struct poly_vec *p = &poly_vecs[i];
        for (int split = 0; split < 2; split++) {
            poly_tag(V(p->key), V(p->msg), p->len, split, tag);
            check(memeq(tag, V(p->tag), 16), "poly1305 tag", i, (uint32_t)split);
        }
    }
}

/* --- AEAD --- */
enum { M_ALIGNED, M_ODD, M_INPLACE, M_COUNT };

static void run_vec(unsigned vi, const struct aead_vec *v, int mode) {
    const uint8_t *key = V(v->key), *nonce = V(v->nonce), *aad = V(v->aad);
    const uint8_t *pt = V(v->in), *ct = V(v->ct), *tg = V(v->tag);
    size_t len = v->len;
    uint32_t oi = mode == M_ODD ? 3 : 0, oo = mode == M_ODD ? 1 : 0;
    uint8_t *in = bufa + GUARD + oi;
    uint8_t *out = mode == M_INPLACE ? in : bufb + GUARD + oo;
    uint8_t tag[16];
    int r;
    uint32_t id = vi << 4 | (uint32_t)mode;

    if (v->valid) {
        /* encrypt */
        memset(bufa, 0xee, sizeof bufa);
        memset(bufb, 0xee, sizeof bufb);
        memcpy(in, pt, len);
        r = m0c_chacha20poly1305_encrypt(out, tag, in, len, aad, v->aad_len, key, nonce);
        check(r == M0C_OK, "enc ret", id, (uint32_t)r);
        check(memeq(out, ct, len), "enc ct", id, len);
        check(memeq(tag, tg, 16), "enc tag", id, 0);
        check(allbyte(out - GUARD - oo, 0xee, GUARD) && allbyte(out + len, 0xee, GUARD), "enc guard", id, 0);
    }
    /* decrypt of the vector's (ct, tag) */
    memset(bufa, 0xee, sizeof bufa);
    memset(bufb, 0x5a, sizeof bufb);
    memcpy(in, ct, len);
    r = m0c_chacha20poly1305_decrypt(out, tg, in, len, aad, v->aad_len, key, nonce);
    if (v->valid) {
        check(r == M0C_OK, "dec ret", id, (uint32_t)r);
        check(memeq(out, pt, len), "dec pt", id, len);
    } else {
        check(r == M0C_ERR_AUTH, "dec reject ret", id, (uint32_t)r);
        check(mode == M_INPLACE ? memeq(out, ct, len) : allbyte(out, 0x5a, len),
              "dec reject unchanged", id, len);
    }
    if (mode == M_INPLACE) {
        check(allbyte(bufa, 0xee, GUARD) && allbyte(in + len, 0xee, GUARD), "dec guard", id, 0);
    } else {
        check(allbyte(out - GUARD - oo, 0x5a, GUARD) && allbyte(out + len, 0x5a, GUARD), "dec guard", id, 0);
    }
    if (!v->valid || mode != M_ALIGNED) return;

    /* tampering: tag bit, ciphertext byte, aad byte -> reject, out unchanged */
    for (int t = 0; t < 3; t++) {
        uint8_t mtag[16], maad[64];
        size_t alen = v->aad_len;
        const uint8_t *a = aad;
        memcpy(mtag, tg, 16);
        memset(bufb, 0x5a, sizeof bufb);
        memcpy(in, ct, len);
        if (t == 0) {
            mtag[vi & 15] ^= (uint8_t)(1u << (vi & 7));
        } else if (t == 1) {
            if (len == 0) continue;
            in[umod(vi, len)] ^= 0x80;
        } else {
            if (alen == 0 || alen > sizeof maad) continue;
            memcpy(maad, aad, alen);
            maad[umod(vi, alen)] ^= 0x01;
            a = maad;
        }
        r = m0c_chacha20poly1305_decrypt(out, mtag, in, len, a, alen, key, nonce);
        check(r == M0C_ERR_AUTH, "tamper ret", id, (uint32_t)t);
        check(allbyte(bufb, 0x5a, sizeof bufb), "tamper unchanged", id, (uint32_t)t);
    }
}

static void test_aead(void) {
    for (unsigned i = 0; i < sizeof aead_vecs / sizeof aead_vecs[0]; i++) {
        const struct aead_vec *v = &aead_vecs[i];
        if (v->len > MAXLEN) continue;
        for (int m = 0; m < M_COUNT; m++) run_vec(i, v, m);
    }
}

/* Words of stack_snapshot (index i = SP - 512 + 4 i) that must be zero after an
 * AEAD call: AEAD frame CTX/BLK [SP-136, SP-40) = 94..118; the nested ChaCha20 frame
 * [SP-320, SP-180) = 48..83; Poly1305 temporaries [SP-208, SP-180) = 76..83.
 * Both functions now have 36 bytes of saved registers above their cleared frame. */
static uint32_t residue(void) {
    uint32_t n = 0;
    for (int i = 48; i < 83; i++) n += stack_snapshot[i] != 0;
    for (int i = 94; i < 118; i++) n += stack_snapshot[i] != 0;
    return n;
}

static uint32_t peak_enc, peak_dec;

/* Documented register clearing (src/chacha20poly1305.S): a nonempty
 * poly1305_blocks returns r0-r3, r12 and lr zero; poly1305_finish returns r0-r3
 * and r12 zero; the AEAD functions return r1-r3 and r12 zero. */
static uint32_t volatile_nonzero(int with_lr) {
    uint32_t n = 0;
    for (int i = 0; i < 4; i++) n += cc8_volatile[i] != 0;
    if (with_lr) n += cc8_volatile[4] != 0;
    return n;
}

static void test_poly_abi(void) {
    for (unsigned i = 0; i < sizeof poly_vecs / sizeof poly_vecs[0]; i += 7) {
        const struct poly_vec *p = &poly_vecs[i];
        if (p->len < 16) continue;
        uint32_t ctx[16], res[2], args[8] = {0}, kw[8];
        uint8_t tag[16];
        memcpy(kw, V(p->key), 32);
        m0c_poly1305_init(ctx, (const uint8_t *)kw);
        args[0] = (uint32_t)ctx; args[1] = (uint32_t)V(p->msg);
        args[2] = p->len / 16; args[3] = 1;
        int r = check_call8((void *)m0c_poly1305_blocks, args, res);
        check(r == 0 && res[0] == 0, "abi blocks regs", i, res[0]);
        check(volatile_nonzero(1) == 0, "abi blocks r1-r3 r12 lr cleared", i, volatile_nonzero(1));
        args[0] = (uint32_t)ctx; args[1] = (uint32_t)tag;
        r = check_call8((void *)m0c_poly1305_finish, args, res);
        check(r == 0 && res[0] == 0, "abi finish regs", i, res[0]);
        check(volatile_nonzero(0) == 0, "abi finish r1-r3 r12 cleared", i, volatile_nonzero(0));
    }
}

static void test_abi(void) {
    static const unsigned pick[] = {0, 1, 5, 40, 120, 200, 300, 330, 350};
    for (unsigned j = 0; j < sizeof pick / sizeof pick[0]; j++) {
        unsigned vi = pick[j];
        if (vi >= sizeof aead_vecs / sizeof aead_vecs[0]) continue;
        const struct aead_vec *v = &aead_vecs[vi];
        if (v->len > MAXLEN) continue;
        uint8_t tag[16];
        uint32_t res[2], args[8];
        memcpy(bufa, V(v->in), v->len);
        args[0] = (uint32_t)bufb; args[1] = (uint32_t)tag; args[2] = (uint32_t)bufa;
        args[3] = v->len; args[4] = (uint32_t)V(v->aad); args[5] = v->aad_len;
        args[6] = (uint32_t)V(v->key); args[7] = (uint32_t)V(v->nonce);
        int r;
        if (v->valid) {
            r = check_call8((void *)m0c_chacha20poly1305_encrypt, args, res);
            check(r == M0C_OK, "abi enc ret", vi, (uint32_t)r);
            check(res[0] == 0, "abi enc regs", vi, res[0]);
            check(residue() == 0, "abi enc frame cleared", vi, residue());
            check(volatile_nonzero(0) == 0, "abi enc r1-r3 r12 cleared", vi, volatile_nonzero(0));
            if (res[1] > peak_enc) peak_enc = res[1];
        }
        memcpy(bufa, V(v->ct), v->len);
        args[1] = (uint32_t)V(v->tag);
        r = check_call8((void *)m0c_chacha20poly1305_decrypt, args, res);
        check(r == (v->valid ? M0C_OK : M0C_ERR_AUTH), "abi dec ret", vi, (uint32_t)r);
        check(res[0] == 0, "abi dec regs", vi, res[0]);
        check(residue() == 0, "abi dec frame cleared", vi,
              residue());
        check(volatile_nonzero(0) == 0, "abi dec r1-r3 r12 cleared", vi, volatile_nonzero(0));
        /* SP-160 = word 88: the nested ChaCha20 call saves the decrypt's r5 there.
         * After a successful verify it must not hold the expected tag's last byte. */
        if (r == M0C_OK)   /* only an accepted decrypt calls ChaCha20 */
            check(stack_snapshot[88] == 0, "abi dec saved r5 cleared", vi, stack_snapshot[88]);
        if (res[1] > peak_dec) peak_dec = res[1];
    }
}

int main(void) {
    test_poly();
    test_poly_abi();
    test_aead();
    test_abi();
    semihost_write0("peak stack bytes: enc ");
    put_hex(peak_enc);
    semihost_write0(" dec ");
    put_hex(peak_dec);
    semihost_write0("\n");
    semihost_write0(failures ? "RESULT: FAIL " : "RESULT: PASS ");
    put_hex((uint32_t)checks);
    semihost_write0(" checks\n");
    return failures != 0;
}
