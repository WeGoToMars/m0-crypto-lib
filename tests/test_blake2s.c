/* On-target tests for BLAKE2s-256 (QEMU microbit or a board): known-answer digests from
 * hashlib (tests/blake2s_vectors.h) for the one-shot path at every input and output
 * alignment, for chunked streaming at many chunk sizes (including empty updates), and the
 * AAPCS and stack-depth checks the proofs state. Test image only. */
#include <stddef.h>
#include <stdint.h>
#include "m0crypto/blake2s.h"
#include "blake2s_vectors.h"

void semihost_write0(const char *s);
int check_call8(void *fn, const uint32_t args[8], uint32_t result[2]);

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

#define MAXLEN 4096
#define GUARD 8
static uint8_t inbuf[MAXLEN + 8] __attribute__((aligned(4)));
static uint8_t outbuf[32 + 2 * GUARD + 4] __attribute__((aligned(4)));
static m0c_blake2s_ctx ctx;

static void fill_in(size_t off, size_t n) {
    for (size_t i = 0; i < n; i++) inbuf[off + i] = B2V_PATTERN(i);
}
static void clear_out(void) { memset(outbuf, 0xa5, sizeof outbuf); }
static int out_ok(size_t off, const uint8_t *want) {
    for (size_t i = 0; i < GUARD + off; i++) if (outbuf[i] != 0xa5) return 0;
    for (size_t i = GUARD + off + 32; i < sizeof outbuf; i++) if (outbuf[i] != 0xa5) return 0;
    return memeq(outbuf + GUARD + off, want, 32);
}

/* One update, every input offset and output offset 0-3. */
static void test_oneshot(void) {
    for (unsigned v = 0; v < B2V_COUNT; v++) {
        for (size_t io = 0; io < 4; io++) {
            for (size_t oo = 0; oo < 4; oo++) {
                if ((io != oo) && v > 60 && v < 200) continue;   /* keep the run short */
                fill_in(io, b2v_len[v]);
                clear_out();
                m0c_blake2s_init(&ctx);
                m0c_blake2s_update(&ctx, inbuf + io, b2v_len[v]);
                m0c_blake2s_final(&ctx, outbuf + GUARD + oo);
                check(out_ok(oo, b2v_digest[v]), "oneshot", v, (uint32_t)(io * 4 + oo));
            }
        }
    }
}

/* Chunked streaming, with an empty update (NULL) between chunks. */
static void test_chunked(void) {
    static const uint16_t chunks[] = {1, 3, 63, 64, 65, 127, 128, 129, 200};
    for (unsigned v = 0; v < B2V_COUNT; v++) {
        if (v > 20 && v < 190 && (v & 3) != 0) continue;   /* a spread of lengths */
        fill_in(1, b2v_len[v]);
        for (unsigned c = 0; c < sizeof chunks / sizeof chunks[0]; c++) {
            if (b2v_len[v] >= 1024 && chunks[c] < 3) continue;   /* bound the 1-byte runs */
            clear_out();
            m0c_blake2s_init(&ctx);
            size_t done = 0;
            while (done < b2v_len[v]) {
                size_t n = b2v_len[v] - done;
                if (n > chunks[c]) n = chunks[c];
                m0c_blake2s_update(&ctx, inbuf + 1 + done, n);
                m0c_blake2s_update(&ctx, NULL, 0);
                done += n;
            }
            m0c_blake2s_final(&ctx, outbuf + GUARD + 1);
            check(out_ok(1, b2v_digest[v]), "chunked", v, chunks[c]);
        }
    }
}

/* AAPCS (r4-r11, sp) and stack depth, from the caller's view. */
static uint32_t peak_init, peak_upd, peak_fin;
static void test_abi(void) {
    uint32_t args[8] = {0}, res[2];
    fill_in(0, 200);
    args[0] = (uint32_t)&ctx;
    check_call8((void *)m0c_blake2s_init, args, res);
    check(res[0] == 0, "abi init regs", res[0], 0);
    peak_init = res[1];
    args[1] = (uint32_t)inbuf; args[2] = 200;
    check_call8((void *)m0c_blake2s_update, args, res);
    check(res[0] == 0, "abi update regs", res[0], 0);
    peak_upd = res[1];
    clear_out();
    args[1] = (uint32_t)(outbuf + GUARD);
    check_call8((void *)m0c_blake2s_final, args, res);
    check(res[0] == 0, "abi final regs", res[0], 0);
    peak_fin = res[1];
    check(out_ok(0, b2v_digest[200]), "abi digest", 0, 0);
    check(peak_init <= 4, "stack init", peak_init, 4);
    check(peak_upd <= 160, "stack update", peak_upd, 160);
    check(peak_fin <= 160, "stack final", peak_fin, 160);
}

int main(void) {
    test_oneshot();
    test_chunked();
    test_abi();
    semihost_write0("peak stack bytes: init ");
    put_hex(peak_init);
    semihost_write0(" update ");
    put_hex(peak_upd);
    semihost_write0(" final ");
    put_hex(peak_fin);
    semihost_write0("\n");
    semihost_write0(failures ? "RESULT: FAIL " : "RESULT: PASS ");
    put_hex((uint32_t)checks);
    semihost_write0(" checks\n");
    return failures != 0;
}
