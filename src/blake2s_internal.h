/* SPDX-License-Identifier: MIT
 * Internal CPU-only BLAKE2s-256 interface, not a stable public API.
 * All code is Thumb assembly (blake2s_compress.S, blake2s_copy.S, blake2s_stream.S),
 * assembled as one relocation-free unit. No power-analysis or fault countermeasures.
 * Proof status: the Lean proofs in proofs/ are about this version; which parts of the
 * clearing described below are proved is stated with each item (see CHANGELOG, 0.3.0).
 */
#ifndef M0C_BLAKE2S_INTERNAL_H
#define M0C_BLAKE2S_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t h[8];
    uint64_t count; /* message bytes compressed so far (pending bytes excluded), RFC 7693 t */
    uint8_t buf[64];
    size_t used;
} m0c_blake2s_ctx;
/* blake2s_stream.S hard-codes these offsets (CTX_*). */
_Static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");
_Static_assert(offsetof(m0c_blake2s_ctx, h) == 0, "CTX_H");
_Static_assert(offsetof(m0c_blake2s_ctx, count) == 32, "CTX_COUNT");
_Static_assert(offsetof(m0c_blake2s_ctx, buf) == 40, "CTX_BUF");
_Static_assert(offsetof(m0c_blake2s_ctx, used) == 104, "CTX_USED");
/* m0c_blake2s_compress and m0c_blake2s_copy are local symbols of the release unit (no public
 * header; only update and final call them). Their prototypes here document the contracts.
 *
 * One BLAKE2s compression (RFC 7693 F) with t = t1:t0 and f0, f1 = 0:
 * h[i] ^= v[i] ^ v[i+8] after ten rounds. f0 must be 0 (nonfinal block) or
 * 0xffffffff (final block): the code XORs any value into v14, but only these two are proved.
 * h[32] and block[64] are word aligned, accessible and disjoint; block includes
 * zero padding. Entry SP is 4-byte aligned, with 136 accessible bytes below it
 * disjoint from both buffers. Ordinary little-endian RAM, immutable code, no
 * external writers or faults. Updates only h and its stack frame; preserves
 * block, SP and r4-r11; clobbers LR/APSR. Clears its 100 local bytes (the message
 * block copy, working state v1..v7, the h pointer and one padding word) and returns
 * r0-r3 and r12 zero;
 * the 36 saved bytes are the caller's registers and stay. h is the result, not cleared.
 */
void m0c_blake2s_compress(uint32_t h[8], const uint8_t block[64], uint32_t t0, uint32_t t1,
                          uint32_t f0);
/* Unkeyed BLAKE2s-256 streaming: context/input/output disjoint; arbitrary
 * byte-aligned input/output; context word aligned (normal C alignment is 8).
 * Stack: init 4 bytes; update and final 160 (24 + compress 136; the copy path 44).
 * Caller keeps the cumulative length below 2^64 bytes; no dynamic overflow check. Final
 * consumes the context. No updates/final afterward without init. Empty updates permit
 * NULL input. Context alignment is normal C.
 * Clearing: update and final return with r0-r3 zero on every path (proved), and each
 * compression zeroes its block copy and working state before returning (by construction;
 * proved only for compress itself, not stated by any release claim). The context (h, buf,
 * count, used) is caller memory and is NOT cleared by update or final; the caller wipes
 * it. init handles only public constants.
 */
/* Internal bounded copy (src/blake2s_copy.S): disjoint accessible n-byte buffers,
 * 1<=n<=64, arbitrary alignment. 20-byte stack frame (saved registers only). Preserves
 * r4-r11/SP. Reads/writes stay inside the requested ranges; no byte-value-dependent
 * branches or addresses. May return copied message data in r3 (and r0-r2 are scratch):
 * the helper clears nothing, its caller m0c_blake2s_update zeroes r0-r3 at exit.
 */
void m0c_blake2s_copy(uint8_t *dst, const uint8_t *src, size_t n);
void m0c_blake2s_init(m0c_blake2s_ctx *c);
void m0c_blake2s_update(m0c_blake2s_ctx *c, const uint8_t *p, size_t n);
void m0c_blake2s_final(m0c_blake2s_ctx *c, uint8_t out[32]);
#endif
