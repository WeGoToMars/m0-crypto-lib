/*
 * m0-crypto: ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8), complete-buffer API.
 * SPDX-License-Identifier: MIT
 */
#ifndef M0CRYPTO_CHACHA20POLY1305_H
#define M0CRYPTO_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "m0crypto/chacha20.h"   /* M0C_OK */

#ifdef __cplusplus
extern "C" {
#endif

#define M0C_ERR_AUTH (-2)

/*
 * Encrypts len bytes from in to out and writes the 16-byte authentication tag
 * calculated over aad and the ciphertext. Always returns M0C_OK.
 *
 * Decrypts ciphertext in to out after authenticating aad and in against tag.
 * On success, writes len bytes of plaintext to out and returns M0C_OK.
 * On authentication failure, returns M0C_ERR_AUTH and leaves out unmodified.
 *
 * Common rules:
 * - RFC 8439 construction: 256-bit key, 96-bit nonce, 128-bit tag. The one-time
 *   Poly1305 key uses block counter 0; the payload starts at counter 1. With a
 *   32-bit size_t, len and aad_len are always within RFC limits.
 * - Buffers may have any alignment. Exact in-place operation (out == in) and fully disjoint
 *   buffers are supported. Partially overlapping buffers are not supported. tag, aad, key,
 *   and nonce must not overlap out.
 * - When len == 0, in and out are not accessed. When aad_len == 0, aad is not accessed.
 * - Nonce uniqueness per key is the caller's responsibility.
 * - Timing specification (design goal; not formally proved): control flow and memory
 *   access patterns depend solely on len, aad_len, buffer alignment (specifically, whether
 *   out and in are both 4-byte aligned), and, for decryption, the final authentication verdict.
 *   Execution time does not vary with key, nonce, tag, or payload data.
 * - Stack frames holding key-derived working state (one-time key, Poly1305 state, keystream,
 *   and expected tag) are cleared before return.
 */
int m0c_chacha20poly1305_encrypt(uint8_t *out, uint8_t tag[16],
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32], const uint8_t nonce[12]);

int m0c_chacha20poly1305_decrypt(uint8_t *out, const uint8_t tag[16],
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32], const uint8_t nonce[12]);

#ifdef __cplusplus
}
#endif

#endif
