/*
 * m0-crypto: ChaCha20 stream cipher (RFC 8439 section 2.4).
 * SPDX-License-Identifier: MIT
 */
#ifndef M0CRYPTO_CHACHA20_H
#define M0CRYPTO_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M0C_OK           0
#define M0C_ERR_COUNTER (-1)

/*
 * out = in XOR ChaCha20 keystream(key, nonce, counter, counter + 1, ...).
 * Encryption and decryption are the same operation.
 *
 * - len bytes are processed. When len == 0, the function returns M0C_OK without modifying out.
 * - Buffers may have any alignment. Exact in-place operation (out == in) and fully disjoint buffers are supported. Partially overlapping buffers are not supported.
 * - The block counter is 32 bits (RFC 8439). If processing would require incrementing the counter past 0xFFFFFFFF, the function returns M0C_ERR_COUNTER without writing to out.
 * - Nonce uniqueness per key is the caller's responsibility.
 * - Timing specification (design goal; not formally proved): validation checks depend only on counter and len. For accepted calls, control flow and memory access patterns depend solely on len and buffer alignment (specifically, whether in and out are both 4-byte aligned). Execution time does not vary with key, nonce, counter, or payload values.
 * - The stack frame holding key-derived working state is cleared before return.
 */
int m0c_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif
