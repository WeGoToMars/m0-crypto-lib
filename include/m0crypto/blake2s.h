/*
 * m0-crypto: unkeyed BLAKE2s-256 (RFC 7693), incremental API.
 * SPDX-License-Identifier: MIT
 *
 * Verified in Lean 4 against the release machine code:
 * - Correct: init, any number of updates and final write the RFC 7693 digest
 *   of all the bytes passed to update, for any lengths and alignment.
 * - Constant time: the instructions executed and the memory addresses
 *   accessed depend only on addresses and on the lengths passed since init,
 *   never on the message or the hash state.
 * - Memory: reads only *c, its input, its own code and its stack, and writes
 *   only *c, out (final) and its stack, within the stack size listed below.
 * - Clean-up: before it returns, the function erases every temporary value it
 *   computed from the message or the hash state, so none is left on the stack.
 *   The hash state and up to 64 message bytes stay in *c: if the message is
 *   secret, wipe *c yourself when you no longer need it. If an interrupt
 *   arrives during the call, the processor saves some working values on the
 *   stack, and this erasing does not cover those copies.
 * - Interrupts: allowed during a call, with the same result. Reserve 36 bytes
 *   of stack beyond the listed size for each interrupt that can be active at
 *   once on the same stack (one interrupt can interrupt another), plus what
 *   your handlers push on that stack. Handlers must restore every register
 *   and flag (a normal C handler does) and must not write the call's buffers
 *   or stack.
 *
 * Exact conditions and proofs: https://github.com/WeGoToMars/m0-crypto-proofs
 */
#ifndef M0CRYPTO_BLAKE2S_H
#define M0CRYPTO_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 112-byte streaming state. Declare it as an ordinary variable and the
 * compiler aligns it:
 *     m0c_blake2s_ctx ctx;
 *     m0c_blake2s_init(&ctx);
 * Storage you provide yourself must be at least 4-byte aligned. Holds the
 * chain value and up to 64 buffered input bytes; wipe after use if the input
 * is secret.
 */
typedef struct {
    uint32_t h[8];
    uint64_t count; /* compressed bytes so far (excludes buf), RFC 7693 t */
    uint8_t buf[64];
    size_t used;
} m0c_blake2s_ctx;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && \
      __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(m0c_blake2s_ctx) == 112, "ARM32 context layout changed");
#endif

/*
 * Initializes *c for a fresh unkeyed BLAKE2s-256 stream.
 *
 * Buffers: c must be 4-byte aligned.
 * Stack:   4 bytes.
 */
void m0c_blake2s_init(m0c_blake2s_ctx *c);

/*
 * Absorbs n bytes from p into *c (initialized by init and any prior updates).
 *
 * Buffers: p may have any alignment and must not overlap *c. When n == 0, p
 *          is not accessed: it may be NULL, but must not point into *c.
 * Stack:   160 bytes.
 * Caution: Total bytes absorbed across a stream must stay below 2^64 (no
 *          overflow check).
 */
void m0c_blake2s_update(m0c_blake2s_ctx *c, const uint8_t *p, size_t n);

/*
 * Writes the 32-byte BLAKE2s-256 digest of the absorbed bytes to out and
 * consumes *c.
 *
 * Buffers: out may have any alignment and must not overlap *c.
 * Stack:   160 bytes.
 * Caution: Do not pass *c to update or final again without re-running init.
 *          Wipe *c if the hashed input was secret.
 */
void m0c_blake2s_final(m0c_blake2s_ctx *c, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
