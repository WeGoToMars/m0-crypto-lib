/*
 * m0-crypto: unkeyed BLAKE2s-256 (RFC 7693), incremental API.
 * SPDX-License-Identifier: MIT
 */
#ifndef M0CRYPTO_BLAKE2S_H
#define M0CRYPTO_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t h[8];
    uint64_t count; /* message bytes compressed so far (pending bytes excluded), RFC 7693 t */
    uint8_t buf[64];
    size_t used;
} m0c_blake2s_ctx;

_Static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");

/*
 * Unkeyed BLAKE2s-256 streaming. init(c); update(c, p, n)*; final(c, out) writes
 * the 32-byte digest of the concatenated input.
 *
 * - Context, input and output buffers are disjoint. Input and output may have any
 *   alignment. The context must be word aligned (normal C alignment is 8).
 * - Empty updates permit NULL input. final consumes the context: no update or final
 *   afterward without init.
 * - The caller limits the cumulative length to UINT64_MAX bytes (no overflow check).
 * - Timing: executed instructions and memory access addresses depend only on the pointer
 *   and length arguments, the sequence of lengths, the stack pointer and the code and
 *   return addresses. They never depend on message bytes or on the hash state (proved in
 *   Lean under the machine model, see proofs/).
 * - Stack: init 4 bytes; update and final 160 bytes below the entry SP.
 * - Clearing: update and final return with r0-r3 zero, and each compression zeroes its
 *   100 bytes of working state on the stack. The context is caller memory and is not
 *   cleared: the caller wipes it.
 */
void m0c_blake2s_init(m0c_blake2s_ctx *c);
void m0c_blake2s_update(m0c_blake2s_ctx *c, const uint8_t *p, size_t n);
void m0c_blake2s_final(m0c_blake2s_ctx *c, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
