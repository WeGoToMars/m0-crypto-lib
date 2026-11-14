/* Interrupt test of m0c_chacha20_xor, m0c_chacha20poly1305_encrypt and
 * m0c_chacha20poly1305_decrypt (QEMU microbit with -icount). Test image only.
 * Every call is compared with the same call without interrupts while SysTick exceptions land at
 * every instruction of it, and periodically, and the handler overwrites the stack below the
 * interrupted SP (tests/irq.c, tests/irq.S). The uninterrupted results are checked against
 * tests/chacha20_vectors.h and a decryption round trip. */
#include "irq.h"
#include "m0crypto/chacha20.h"
#include "m0crypto/chacha20poly1305.h"
#include "chacha20_vectors.h"

extern const char irq_end_m0c_chacha20_xor[], irq_end_m0c_chacha20poly1305_encrypt[],
    irq_end_m0c_chacha20poly1305_decrypt[];

#define XLEN 130          /* chacha_vecs[0]: counter 2, 130 bytes, output at cv_out[0] */
#define ALEN 70
#define AADLEN 21
static struct {
    uint8_t g0[8];
    uint8_t out[XLEN];
    uint8_t g1[6];
    uint8_t tag[16];
    uint8_t g2[8];
} io __attribute__((aligned(4)));
static uint8_t msg[XLEN], aad[AADLEN], ct[ALEN], tag[16];
static int inplace, badtag;

static void fill(uint8_t *p, size_t n, unsigned s) {
    for (size_t i = 0; i < n; i++) p[i] = CV_PATTERN(s, i);
}
static void setup_xor(void) {
    memset(&io, 0x5a, sizeof io);
    if (inplace) memcpy(io.out, msg, XLEN);
}
static void setup_enc(void) {
    memset(&io, 0x5a, sizeof io);
    if (inplace) memcpy(io.out, msg, ALEN);
}
static void setup_dec(void) {
    memset(&io, 0x5a, sizeof io);
    memcpy(io.tag, tag, 16);
    if (badtag) io.tag[5] ^= 0x20;
    if (inplace) memcpy(io.out, ct, ALEN);
}

static const uint32_t periods[] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                   20, 23, 29, 31, 37, 40, 64, 97, 128, 251};
#define NP (sizeof periods / sizeof periods[0])

int main(void) {
    (void)aead_long_vecs;
    irq_init();
    fill(msg, XLEN, 0);
    fill(aad, AADLEN, 1);
    const uint32_t ctr = chacha_vecs[0].counter;

    /* uninterrupted results */
    check(chacha_vecs[0].len == XLEN && chacha_vecs[0].result == 0, "vector", 0, 0);
    setup_xor();
    int r = m0c_chacha20_xor(io.out, msg, XLEN, cv_key, cv_nonce, ctr);
    check(r == 0 && memeq(io.out, cv_out + chacha_vecs[0].out, XLEN), "chacha20 vector", 0,
          (uint32_t)r);
    r = m0c_chacha20poly1305_encrypt(ct, tag, msg, ALEN, aad, AADLEN, cv_key, cv_nonce);
    check(r == 0, "encrypt", 0, (uint32_t)r);
    setup_dec();
    r = m0c_chacha20poly1305_decrypt(io.out, io.tag, ct, ALEN, aad, AADLEN, cv_key, cv_nonce);
    check(r == 0 && memeq(io.out, msg, ALEN), "decrypt round trip", 0, (uint32_t)r);

    irq_target("m0c_chacha20_xor", (const void *)m0c_chacha20_xor, irq_end_m0c_chacha20_xor, 176);
    for (inplace = 0; inplace < 2; inplace++) {
        uint32_t a[8] = {(uint32_t)io.out, inplace ? (uint32_t)io.out : (uint32_t)msg, XLEN,
                         (uint32_t)cv_key, (uint32_t)cv_nonce, ctr, 0, 0};
        irq_cover("xor", (void *)m0c_chacha20_xor, a, setup_xor, &io, sizeof io, 1, periods, NP);
    }
    {   /* counter overflow: returns M0C_ERR_COUNTER (chacha_vecs[3]) */
        inplace = 0;
        uint32_t a[8] = {(uint32_t)io.out, (uint32_t)msg, chacha_vecs[3].len, (uint32_t)cv_key,
                         (uint32_t)cv_nonce, chacha_vecs[3].counter, 0, 0};
        irq_cover("xor counter", (void *)m0c_chacha20_xor, a, setup_xor, &io, sizeof io, 1,
                  periods, NP);
    }
    irq_summary();

    irq_target("m0c_chacha20poly1305_encrypt", (const void *)m0c_chacha20poly1305_encrypt,
               irq_end_m0c_chacha20poly1305_encrypt, 144);
    for (inplace = 0; inplace < 2; inplace++) {
        uint32_t a[8] = {(uint32_t)io.out, (uint32_t)io.tag,
                         inplace ? (uint32_t)io.out : (uint32_t)msg, ALEN, (uint32_t)aad, AADLEN,
                         (uint32_t)cv_key, (uint32_t)cv_nonce};
        irq_cover("encrypt", (void *)m0c_chacha20poly1305_encrypt, a, setup_enc, &io, sizeof io,
                  1, periods, NP);
    }
    irq_summary();

    irq_target("m0c_chacha20poly1305_decrypt", (const void *)m0c_chacha20poly1305_decrypt,
               irq_end_m0c_chacha20poly1305_decrypt, 144);
    for (badtag = 0; badtag < 2; badtag++)
        for (inplace = 0; inplace < 2; inplace++) {
            uint32_t a[8] = {(uint32_t)io.out, (uint32_t)io.tag,
                             inplace ? (uint32_t)io.out : (uint32_t)ct, ALEN, (uint32_t)aad,
                             AADLEN, (uint32_t)cv_key, (uint32_t)cv_nonce};
            irq_cover("decrypt", (void *)m0c_chacha20poly1305_decrypt, a, setup_dec, &io,
                      sizeof io, 1, periods, NP);
        }
    irq_summary();
    return report();
}
