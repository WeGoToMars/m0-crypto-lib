/* SPDX-License-Identifier: MIT
 * One unkeyed BLAKE2s-256 hash per wrapper: init, update(s), final, all included.
 * in/len is the message and out receives the 32-byte digest. "hash" wrappers make one
 * update call; "stream" wrappers make one per CHUNK bytes. The BLAKE2 reference and
 * OpenSSL wrappers live in their own files because the headers define the same names. */
#include "job.h"
#include "m0crypto/blake2s.h"
#include <wolfssl/wolfcrypt/blake2.h>

CALLER_STATE(m0c_hash, sizeof(m0c_blake2s_ctx));
CALLER_STATE(m0c_stream, sizeof(m0c_blake2s_ctx));
CALLER_STATE(wolf_hash, sizeof(Blake2s));
CALLER_STATE(wolf_stream, sizeof(Blake2s));

static inline __attribute__((always_inline)) void m0c(Job *j, size_t chunk) {
    m0c_blake2s_ctx c;
    m0c_blake2s_init(&c);
    for (size_t i = 0; i < j->len; i += chunk)
        m0c_blake2s_update(&c, j->in + i, piece(i, j->len, chunk));
    m0c_blake2s_final(&c, j->out);
    j->status = 0;
}
void run_m0c_hash(Job *j) { m0c(j, j->len ? j->len : 1); }
void run_m0c_stream(Job *j) { m0c(j, CHUNK); }

static inline __attribute__((always_inline)) void wolf(Job *j, size_t chunk) {
    Blake2s c;
    int r = wc_InitBlake2s(&c, 32);
    for (size_t i = 0; !r && i < j->len; i += chunk)
        r = wc_Blake2sUpdate(&c, j->in + i, (word32)piece(i, j->len, chunk));
    if (!r) r = wc_Blake2sFinal(&c, j->out, 32);
    j->status = r;
}
void run_wolf_hash(Job *j) { wolf(j, j->len ? j->len : 1); }
void run_wolf_stream(Job *j) { wolf(j, CHUNK); }
