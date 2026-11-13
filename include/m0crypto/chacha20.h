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
 * - Stack (proved): 176 bytes below the entry SP.
 * - Clearing (proved): when the call returns M0C_OK and len != 0, the 140 bytes
 *   [SP-176, SP-36) holding key-derived working state are zero on return. The 36
 *   saved bytes above them hold the caller's registers.
 * - Preconditions of the proofs (ChaCha20Xor.Pre in proofs/). SP is the stack pointer at
 *   entry. "code" is the 3,030-byte .text of the linked m0crypto_chacha20poly1305 object.
 *   "A disjoint from B" means both address ranges end at or below 2^32 and do not
 *   overlap. An empty range [p, p) still must not start strictly inside the other range.
 *     code start 4-byte aligned; SP 8-byte aligned and SP >= 176;
 *     [SP-176, SP+8) (frame, saved registers, the two stack arguments) disjoint from
 *       the code and from out;
 *     [SP-176, SP) disjoint from in, key and nonce;
 *     out disjoint from the code; in equal to out or disjoint from it;
 *     LR has bit 0 set (Thumb) and the return address lies outside the code.
 */
int m0c_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif
