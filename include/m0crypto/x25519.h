/*
 * m0-crypto: X25519 (RFC 7748 section 5).
 * SPDX-License-Identifier: MIT
 *
 * Verified in Lean 4 against the release machine code:
 * - Correct: out matches RFC 7748 X25519 for any alignment and any overlap of
 *   the three buffers.
 * - Constant time: the instructions executed and the memory addresses
 *   accessed depend only on addresses, never on the scalar or the point.
 * - Memory: reads only scalar, point, its own code and its stack, and writes
 *   only out and its stack, within the stack size listed below.
 * - Clean-up: before it returns, the function erases every temporary value it
 *   computed from the scalar or the point, so none is left on the stack. Your
 *   own buffers are not touched beyond out: wipe the scalar yourself when you
 *   no longer need it. If an interrupt arrives during the call, the processor
 *   saves some working values on the stack, and this erasing does not cover
 *   those copies.
 * - Interrupts: allowed during a call, with the same result. Reserve 36 bytes
 *   of stack beyond the listed size for each interrupt that can be active at
 *   once on the same stack (one interrupt can interrupt another), plus what
 *   your handlers push on that stack. Handlers must restore every register
 *   and flag (a normal C handler does) and must not write the call's buffers
 *   or stack.
 *
 * Exact conditions and proofs: https://github.com/WeGoToMars/m0-crypto-proofs
 */
#ifndef M0CRYPTO_X25519_H
#define M0CRYPTO_X25519_H

#include <stdint.h>

#ifndef M0C_OK
#define M0C_OK 0   /* success; defined by every status-returning header */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Computes out = X25519(scalar, point) per RFC 7748 section 5: clamps the
 * scalar and ignores bit 255 of the point.
 *
 * Returns: M0C_OK (0) unconditionally.
 * Buffers: Any alignment. out, scalar and point may overlap in any way.
 * Stack:   516 bytes.
 * Caution: Does not reject low-order points or an all-zero shared secret;
 *          protocols that require rejection must check out in constant time.
 */
int m0c_x25519(uint8_t out[32], const uint8_t scalar[32],
               const uint8_t point[32]);

#ifdef __cplusplus
}
#endif

#endif
