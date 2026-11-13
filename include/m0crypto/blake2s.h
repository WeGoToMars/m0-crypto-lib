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

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");
#endif

/*
 * Unkeyed BLAKE2s-256 streaming. init(c); update(c, p, n)*; final(c, out) writes
 * the 32-byte digest of the concatenated input.
 *
 * - Context, input and output buffers are disjoint. Input and output may have any
 *   alignment. The context must be word aligned (normal C alignment is 8).
 * - Empty updates permit NULL input. final consumes the context: no update or final
 *   afterward without init.
 * - The caller keeps the cumulative length below 2^64 bytes (no overflow check).
 * - Timing: executed instructions and memory access addresses depend only on the pointer
 *   and length arguments, the sequence of lengths, the stack pointer and the code and
 *   return addresses. They never depend on message bytes or on the hash state (proved in
 *   Lean under the machine model, see proofs/).
 * - Stack (proved): init 4 bytes; update and final 160 bytes below the entry SP.
 * - Clearing (proved): update and final return with r0-r3 zero. The internal
 *   compression routine overwrites its 100 bytes of working state (message copy, v1..v7,
 *   h pointer, padding) with zeros before it returns. The context is caller memory, and
 *   the caller wipes it.
 * - Preconditions of the proofs (Blake2s.Init.Pre, Blake2s.Update.Pre and
 *   Blake2s.Final.Pre in proofs/). SP is the stack pointer at entry; W is the stack
 *   window [SP-4, SP) for init and [SP-160, SP) for update and final. "code" is the
 *   4,748-byte .text of the linked m0crypto_blake2s object. "A disjoint from B" means
 *   both address ranges end at or below 2^32 and do not overlap. An empty range [p, p)
 *   still must not start strictly inside the other range.
 *     all: code start and SP 4-byte aligned; SP >= 4 (init) or SP >= 160 (update,
 *       final); c 4-byte aligned; the 112 context bytes, W and the code pairwise
 *       disjoint;
 *     update and final: the context holds the state of init followed by updates
 *       (as these functions leave it), and the bytes absorbed so far, plus n for
 *       update, total less than 2^64;
 *     update: [p, p+n) disjoint from the context and from W (it may overlap the code);
 *     final: the 32 bytes of out disjoint from the code, W and the context;
 *     LR has bit 0 set (Thumb) and the return address lies outside the code.
 */
void m0c_blake2s_init(m0c_blake2s_ctx *c);
void m0c_blake2s_update(m0c_blake2s_ctx *c, const uint8_t *p, size_t n);
void m0c_blake2s_final(m0c_blake2s_ctx *c, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
