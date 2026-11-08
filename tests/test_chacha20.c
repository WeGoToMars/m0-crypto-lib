/* On-target tests for m0c_chacha20_xor (QEMU microbit or real board). Test image only. */
#include <stddef.h>
#include <stdint.h>
#include "m0crypto/chacha20.h"
#include "ref_chacha20.h"

void semihost_write0(const char *s);
int check_call(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *key,
               const uint8_t *nonce, uint32_t counter, uint32_t result[3]);

/* Freestanding helpers (the compiler may emit calls to these). */
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
/* ARM EABI helpers the compiler may emit for zero-initialisation and copies. */
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

static uint32_t rng = 0x12345678;
static uint32_t xorshift(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

/* RFC 8439 section 2.4.2 */
static const uint8_t rfc_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
static const uint8_t rfc_nonce_242[12] = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
static const char sunscreen[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
    "future, sunscreen would be it.";
static const uint8_t sunscreen_ct[114] = {
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d};
/* RFC 8439 section 2.3.2 */
static const uint8_t rfc_nonce_232[12] = {0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0};
static const uint8_t block_232[64] = {
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e};

#define MAXLEN 2100
#define GUARD 8
static uint8_t inbuf[MAXLEN + 2 * GUARD + 4];
static uint8_t outbuf[MAXLEN + 2 * GUARD + 4];
static uint8_t refbuf[MAXLEN + 4];

static void fill(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)xorshift(); }

static void test_vectors(void) {
    uint8_t buf[114], zero[64] = {0}, ks[64];
    int r = m0c_chacha20_xor(buf, (const uint8_t *)sunscreen, 114, rfc_key, rfc_nonce_242, 1);
    check(r == M0C_OK && memeq(buf, sunscreen_ct, 114), "rfc8439 2.4.2 encrypt", (uint32_t)r, 0);
    r = m0c_chacha20_xor(buf, buf, 114, rfc_key, rfc_nonce_242, 1);
    check(r == M0C_OK && memeq(buf, (const uint8_t *)sunscreen, 114), "rfc8439 2.4.2 decrypt in place",
          (uint32_t)r, 0);
    r = m0c_chacha20_xor(ks, zero, 64, rfc_key, rfc_nonce_232, 1);
    check(r == M0C_OK && memeq(ks, block_232, 64), "rfc8439 2.3.2 block", (uint32_t)r, 0);
    /* key and nonce at odd addresses (the contract allows any alignment) */
    static uint8_t kn[32 + 12 + 8];
    uint8_t *k1 = kn + 1, *n3 = kn + 32 + 3;
    memcpy(k1, rfc_key, 32);
    memcpy(n3, rfc_nonce_242, 12);
    r = m0c_chacha20_xor(buf, (const uint8_t *)sunscreen, 114, k1, n3, 1);
    check(r == M0C_OK && memeq(buf, sunscreen_ct, 114), "rfc8439 2.4.2 unaligned key/nonce",
          (uint32_t)r, 0);
    ref_chacha20_block(rfc_key, 1, rfc_nonce_232, ks);
    check(memeq(ks, block_232, 64), "reference self-check 2.3.2", 0, 0);
}

static uint32_t peak_stack;

/* Compare against the reference for one configuration, with guard bytes around out. */
static void one_case(size_t len, unsigned in_off, unsigned out_off, int inplace, uint32_t counter) {
    uint8_t key[32], nonce[12];
    fill(key, 32);
    fill(nonce, 12);
    fill(inbuf, sizeof inbuf);
    fill(outbuf, sizeof outbuf);
    uint8_t *in = inbuf + GUARD + in_off;
    uint8_t *out = inplace ? in : outbuf + GUARD + out_off;
    uint8_t *region = inplace ? inbuf : outbuf;
    size_t region_len = inplace ? sizeof inbuf : sizeof outbuf;
    static uint8_t before[MAXLEN + 2 * GUARD + 4];
    memcpy(before, region, region_len);
    ref_chacha20_xor(refbuf, in, len, key, nonce, counter);
    uint32_t res[3];
    int r = check_call(out, in, len, key, nonce, counter, res);
    check(r == M0C_OK, "return", (uint32_t)r, (uint32_t)len);
    check(memeq(out, refbuf, len), "output vs reference", (uint32_t)len, in_off * 16 + out_off);
    size_t lo = (size_t)(out - region), hi = lo + len;
    int guards_ok = 1;
    for (size_t i = 0; i < region_len; i++)
        if ((i < lo || i >= hi) && region[i] != before[i]) guards_ok = 0;
    check(guards_ok, "bytes outside out unchanged", (uint32_t)len, in_off * 16 + out_off);
    check(res[0] == 0, "callee-saved registers / sp", res[0], (uint32_t)len);
    check(res[1] <= 176, "peak stack <= 176", res[1], (uint32_t)len);
    if (len) check(res[2] == 0, "frame cleared after return", res[2], (uint32_t)len);
    if (res[1] > peak_stack) peak_stack = res[1];
}

static void test_differential(void) {
    static const size_t lens[] = {0, 1, 2, 3, 4, 5, 31, 32, 33, 63, 64, 65, 127, 128, 129,
                                  191, 192, 193, 255, 256, 257, 500, 1000, 2049};
    for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++)
        for (unsigned io = 0; io < 4; io++) {
            for (unsigned oo = 0; oo < 4; oo++) one_case(lens[li], io, oo, 0, xorshift());
            one_case(lens[li], io, 0, 1, xorshift());
        }
}

static void test_counter_edges(void) {
    uint8_t key[32] = {0}, nonce[12] = {0};
    struct { uint32_t counter; size_t len; int expect; } c[] = {
        {0xffffffffu, 0, M0C_OK},   {0xffffffffu, 1, M0C_OK},   {0xffffffffu, 64, M0C_OK},
        {0xffffffffu, 65, M0C_ERR_COUNTER}, {0xfffffffeu, 128, M0C_OK},
        {0xfffffffeu, 129, M0C_ERR_COUNTER}, {0, 2049, M0C_OK},
        /* huge lengths: rejected from the carry of counter + (len - 1) / 64 alone */
        {0xfc000001u, 0xffffffffu, M0C_ERR_COUNTER}, {0xffffffffu, 0xffffffffu, M0C_ERR_COUNTER},
        {0xfc000002u, 0xffffffffu - 63, M0C_ERR_COUNTER}};
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        fill(inbuf, sizeof inbuf);
        fill(outbuf, sizeof outbuf);
        static uint8_t before[sizeof outbuf];
        memcpy(before, outbuf, sizeof outbuf);
        uint32_t res[3];
        int r = check_call(outbuf, inbuf, c[i].len, key, nonce, c[i].counter, res);
        check(r == c[i].expect, "counter edge return", (uint32_t)r, c[i].counter);
        if (c[i].expect != M0C_OK)
            check(memeq(outbuf, before, sizeof outbuf), "counter error leaves out unchanged",
                  c[i].counter, (uint32_t)c[i].len);
        else if (c[i].len) {
            ref_chacha20_xor(refbuf, inbuf, c[i].len, key, nonce, c[i].counter);
            check(memeq(outbuf, refbuf, c[i].len), "counter edge output", c[i].counter,
                  (uint32_t)c[i].len);
            check(res[2] == 0, "frame cleared after return (edge)", res[2], c[i].counter);
        }
        check(res[0] == 0, "callee-saved registers / sp (edge)", res[0], c[i].counter);
    }
}

int main(void) {
    test_vectors();
    test_differential();
    test_counter_edges();
    semihost_write0("peak stack bytes: ");
    put_hex(peak_stack);
    semihost_write0("\n");
    semihost_write0(failures ? "RESULT: FAIL " : "RESULT: PASS ");
    put_hex((uint32_t)checks);
    semihost_write0(" checks\n");
    return failures != 0;
}
