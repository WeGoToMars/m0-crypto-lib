/* SPDX-License-Identifier: MIT
 * OpenSSL's provider-internal BLAKE2s functions, without EVP dispatch; see blake2s.c.
 * The parameter block is caller state during init. */
#include "job.h"
#include "prov/blake2.h"

CALLER_STATE(ossl_hash, sizeof(BLAKE2S_CTX) + sizeof(BLAKE2S_PARAM));
CALLER_STATE(ossl_stream, sizeof(BLAKE2S_CTX) + sizeof(BLAKE2S_PARAM));

static inline __attribute__((always_inline)) void ossl(Job *j, size_t chunk) {
    BLAKE2S_PARAM p;
    BLAKE2S_CTX c;
    ossl_blake2s_param_init(&p);
    int ok = ossl_blake2s_init(&c, &p);
    for (size_t i = 0; ok && i < j->len; i += chunk)
        ok = ossl_blake2s_update(&c, j->in + i, piece(i, j->len, chunk));
    if (ok) ok = ossl_blake2s_final(j->out, &c);
    j->status = ok ? 0 : -1;
}
void run_ossl_hash(Job *j) { ossl(j, j->len ? j->len : 1); }
void run_ossl_stream(Job *j) { ossl(j, CHUNK); }
