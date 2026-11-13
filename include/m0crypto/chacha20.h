/*
 * m0-crypto: ChaCha20 stream cipher (RFC 8439 section 2.4).
 * SPDX-License-Identifier: MIT
 */
#ifndef M0CRYPTO_CHACHA20_H
#define M0CRYPTO_CHACHA20_H

#include <stddef.h>
#include <stdint.h>
#include "m0crypto/status.h"   /* M0C_OK */

#ifdef __cplusplus
extern "C" {
#endif

#define M0C_ERR_COUNTER (-1)

/*
 * out = in XOR ChaCha20 keystream(key, nonce, counter, counter + 1, ...).
 * Encryption and decryption are the same operation.
 *
 * - len bytes are processed. When len == 0, the function returns M0C_OK without modifying out.
 * - Buffers may have any alignment. Exact in-place operation (out == in) and fully disjoint buffers are supported. Partially overlapping buffers are not supported.
 * - The block counter is 32 bits (RFC 8439). If processing would require incrementing the counter past 0xFFFFFFFF, the function returns M0C_ERR_COUNTER without writing to out.
 * - Nonce uniqueness per key is the caller's responsibility.
 * - Timing (proved in the ARMv6-M model, see proofs/): the executed instructions
 *   and memory access addresses depend only on the pointer arguments, len, counter,
 *   the stack pointer, and the code and return addresses. They never depend on
 *   key, nonce, or payload bytes. Validation checks depend only on counter and len.
 * - Read bounds (proved): reads stay strictly within in, key, nonce, the code,
 *   and the 176-byte stack frame plus the two stack arguments.
 * - The stack frame holding key-derived working state is cleared before return.
 */
int m0c_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif
