/*
 * m0-crypto: ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).
 * SPDX-License-Identifier: MIT
 *
 * Verified in Lean 4 against the release machine code:
 * - Correct: ciphertext and tag match RFC 8439 for every length, alignment
 *   and allowed buffer overlap. Decryption writes out only if the tag matches.
 * - Constant time: the instructions executed and the memory addresses
 *   accessed depend only on addresses, the lengths and, for decryption,
 *   whether the tag matched. They never depend on the key, nonce, tag, AAD or
 *   data.
 * - Memory: reads only the buffers passed to it, its own code and its stack,
 *   and writes only out, tag (encryption) and its stack, within the stack
 *   size listed below.
 * - Clean-up: before it returns, the function erases every temporary value it
 *   computed from the key, nonce, tag, AAD or data, so none is left on the
 *   stack, apart from whether decryption succeeded, which the return value
 *   reports anyway. Your own buffers are not touched beyond out and tag: wipe
 *   the key yourself when you no longer need it. If an interrupt arrives during
 *   the call, the processor saves some working values on the stack, and this
 *   erasing does not cover those copies.
 * - Interrupts: allowed during a call, with the same result. Reserve 36 bytes
 *   of stack beyond the listed size for each interrupt that can be active at
 *   once on the same stack (one interrupt can interrupt another), plus what
 *   your handlers push on that stack. Handlers must restore every register
 *   and flag (a normal C handler does) and must not write the call's buffers
 *   or stack.
 *
 * Exact conditions and proofs: https://github.com/WeGoToMars/m0-crypto-proofs
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
 * over aad and the ciphertext to tag (RFC 8439 section 2.8: block 0 generates
 * the Poly1305 key, payload starts at counter 1).
 *
 * Returns: M0C_OK (0) unconditionally.
 * Buffers: Any alignment. out must equal in or not overlap it, and must not
 *          overlap any other buffer. tag must not overlap any other buffer.
 *          When len or aad_len is 0, that buffer is not accessed: it may be
 *          NULL, but must not point into the middle of another buffer.
 * Stack:   320 bytes.
 * Caution: Nonce uniqueness per key is the caller's responsibility.
 */
int m0c_chacha20poly1305_encrypt(uint8_t *out, uint8_t tag[16],
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]);

/*
 * Authenticates aad and len ciphertext bytes at in against tag, then decrypts
 * in to out (RFC 8439 section 2.8).
 *
 * Returns: M0C_OK (0) on authentic input, or M0C_ERR_AUTH (-2) without
 *          modifying out (including when out == in) if authentication fails.
 * Buffers: Any alignment. out must equal in or not overlap it, and must not
 *          overlap tag, aad, key or nonce. When len or aad_len is 0, that
 *          buffer is not accessed: it may be NULL, but must not point into
 *          the middle of another buffer.
 * Stack:   320 bytes.
 */
int m0c_chacha20poly1305_decrypt(uint8_t *out, const uint8_t tag[16],
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]);

#ifdef __cplusplus
}
#endif

#endif
