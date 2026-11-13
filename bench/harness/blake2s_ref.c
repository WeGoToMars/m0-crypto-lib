/* SPDX-License-Identifier: MIT
 * BLAKE2 reference implementation (ref/blake2s-ref.c); see blake2s.c. */
#include "job.h"
#include "third_party/blake2/ref/blake2.h"

CALLER_STATE(ref_hash, sizeof(blake2s_state));
CALLER_STATE(ref_stream, sizeof(blake2s_state));

static inline __attribute__((always_inline)) void ref(Job *j, size_t chunk) {
    blake2s_state c;
    int r = blake2s_init(&c, 32);
    for (size_t i = 0; !r && i < j->len; i += chunk)
        r = blake2s_update(&c, j->in + i, piece(i, j->len, chunk));
    if (!r) r = blake2s_final(&c, j->out, 32);
    j->status = r;
}
void run_ref_hash(Job *j) { ref(j, j->len ? j->len : 1); }
void run_ref_stream(Job *j) { ref(j, CHUNK); }
