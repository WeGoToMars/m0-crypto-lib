/* SPDX-License-Identifier: MIT
 * Wrapper argument block shared by the BLAKE2s and X25519 harnesses; the layout
 * matches the ChaCha20-Poly1305 harness and JOB_FORMAT in armv6m.py. */
#ifndef M0C_BENCH_JOB_H
#define M0C_BENCH_JOB_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *out;
    const uint8_t *in;
    size_t len;
    const uint8_t *key, *nonce, *aad;
    size_t aad_len;
    uint8_t *tag;
    int status;
} Job;

/* Caller-held state each public API requires, in bytes. armv6m.py adds it to the
 * measured stack peak below the library call; absent symbols mean none. */
#define CALLER_STATE(wrapper, bytes) \
    __attribute__((used, retain)) const uint32_t caller_state_##wrapper = (bytes)

/* Streaming hash wrappers feed the message in pieces of this many bytes. */
#define CHUNK 16u

/* Length of the update starting at done: one update for a one-shot hash, CHUNK otherwise. */
static inline size_t piece(size_t done, size_t len, size_t chunk) {
    return len - done < chunk ? len - done : chunk;
}
#endif
