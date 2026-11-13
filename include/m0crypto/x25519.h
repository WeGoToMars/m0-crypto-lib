/*
 * m0-crypto: X25519 (RFC 7748 section 5).
 * SPDX-License-Identifier: MIT
 */
#ifndef M0CRYPTO_X25519_H
#define M0CRYPTO_X25519_H

#include <stdint.h>

#include "m0crypto/status.h"   /* M0C_OK */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * out = X25519(scalar, point), the function of RFC 7748 section 5: the scalar is
 * clamped and bit 255 of the u-coordinate is masked inside the call. Always returns
 * M0C_OK. The argument order and return type match wolfSSL's low-level curve25519().
 *
 * - The three buffers may have any alignment and may overlap in any way: both inputs
 *   are read completely before out is written.
 * - No check for a low-order point or an all-zero result. A protocol that needs it ORs
 *   the 32 output bytes in constant time.
 * - Stack: 516 bytes below the entry SP.
 * - Clearing: returns with r0-r3 and r12 zero, and zeroes the 480 bytes of stack below
 *   its saved registers (its frame and the stack its internal routines used).
 * - Proved in proofs/ (docs/REVIEW.md section 9) against the Lean model of these exact
 *   bytes: the result, the clearing above, the stack bound, the read regions, and a
 *   trace that depends only on the addresses and LR, not on the scalar or point.
 *   The proofs cover uninterrupted calls.
 */
int m0c_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

#ifdef __cplusplus
}
#endif

#endif
