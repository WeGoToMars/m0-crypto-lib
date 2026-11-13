/* SPDX-License-Identifier: MIT
 * Shared helpers of the board benchmark images (benchmark-only, not library code). */
#include "common.h"

void put_s(const char *s) { semihost_write0(s); }
void put_comma(void) { semihost_write0(","); }

void put_u(uint32_t v) {
    static const uint32_t pow10[] = {1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
                                     10000u, 1000u, 100u, 10u, 1u};
    char b[11];
    int n = 0;
    for (int i = 0; i < 10; i++) {
        char d = 0;
        while (v >= pow10[i]) { v -= pow10[i]; d++; }
        if (d || n || i == 9) b[n++] = (char)('0' + d);
    }
    b[n] = 0;
    semihost_write0(b);
}

void put_hex8(uint32_t v) {
    char b[11] = "0x00000000";
    for (int i = 0; i < 8; i++) b[9 - i] = "0123456789abcdef"[(v >> (4 * i)) & 15];
    semihost_write0(b);
}

void put_bytes_hex(const uint8_t *p, unsigned n) {
    char b[3] = {0, 0, 0};
    for (unsigned i = 0; i < n; i++) {
        b[0] = "0123456789abcdef"[p[i] >> 4];
        b[1] = "0123456789abcdef"[p[i] & 15];
        semihost_write0(b);
    }
}

void fill_message(uint8_t *p, unsigned family, unsigned n) {
    uint32_t x = family == 2 ? 0x2545F491u : 0x9E3779B9u;
    unsigned pattern = 0;
    for (unsigned i = 0; i < n; i++) {
        uint8_t v;
        switch (family) {
        case 0: v = 0; break;
        case 1: v = 0xff; break;
        case 4:
            v = (uint8_t)pattern;
            if (++pattern == 251) pattern = 0;
            break;
        default:
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            v = (uint8_t)(x >> 7);
        }
        p[i] = v;
    }
}

int bytes_equal(const uint8_t *a, const uint8_t *b, unsigned n) {
    unsigned d = 0;
    for (unsigned i = 0; i < n; i++) d |= (unsigned)(a[i] ^ b[i]);
    return d == 0;
}

void timer_start(void) {
    SYST_RVR = 0x00ffffffu;
    SYST_CVR = 0;
    SYST_CSR = 5;   /* ENABLE | CLKSOURCE = processor clock; TICKINT off */
}

uint32_t timer_overhead(void) {
    uint32_t ov = 0xffffffffu;
    for (unsigned i = 0; i < 16; i++) {
        uint32_t t = time_call3((void *)bench_noop, 0, 0, 0);
        if (t < ov) ov = t;
    }
    return ov;
}

void series_add(struct series *s, unsigned i, uint32_t raw, uint32_t overhead) {
    if (raw == TIME_OVERFLOW || raw < overhead) {
        s->invalid = 1;
        s->t[i] = TIME_OVERFLOW;
    } else {
        s->t[i] = raw - overhead;
    }
}

void series_finish(struct series *s) {
    s->min = 0xffffffffu;
    s->max = 0;
    for (unsigned i = 0; i < REPS; i++) {
        if (s->t[i] < s->min) s->min = s->t[i];
        if (s->t[i] > s->max) s->max = s->t[i];
    }
}

void put_series(const struct series *s, int all) {
    put_comma(); put_u(s->min);
    put_comma(); put_u(s->max);
    if (all)
        for (unsigned i = 0; i < REPS; i++) { put_comma(); put_u(s->t[i]); }
}
