/* Straightforward RFC 8439 section 2.4 ChaCha20 reference, used only as a test oracle.
 * Written from the RFC text, independently of src/chacha20.S. SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>
#include "ref_chacha20.h"

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define QR(a, b, c, d)                     \
    a += b; d ^= a; d = rotl(d, 16);       \
    c += d; b ^= c; b = rotl(b, 12);       \
    a += b; d ^= a; d = rotl(d, 8);        \
    c += d; b ^= c; b = rotl(b, 7)

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void ref_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                        uint8_t out[64]) {
    uint32_t s[16], x[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);
    for (int i = 0; i < 16; i++) x[i] = s[i];
    for (int r = 0; r < 10; r++) {
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t w = x[i] + s[i];
        out[4 * i] = (uint8_t)w; out[4 * i + 1] = (uint8_t)(w >> 8);
        out[4 * i + 2] = (uint8_t)(w >> 16); out[4 * i + 3] = (uint8_t)(w >> 24);
    }
}

void ref_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                      const uint8_t nonce[12], uint32_t counter) {
    uint8_t ks[64];
    for (size_t off = 0; off < len; off += 64, counter++) {
        ref_chacha20_block(key, counter, nonce, ks);
        size_t n = len - off < 64 ? len - off : 64;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}
