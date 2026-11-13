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
 *   buffers are supported. Partially overlapping buffers are not supported. tag and aad
 *   must not overlap out (see the preconditions below for the exact conditions).
 * - When len == 0, in and out are not accessed. When aad_len == 0, aad is not accessed.
 * - Nonce uniqueness per key is the caller's responsibility.
 * - Timing (proved in the ARMv6-M model, see proofs/): the executed instructions
 *   and memory access addresses depend only on the pointer and length arguments,
 *   the stack pointer, the code and return addresses, and (for decryption) whether
 *   the tag verifies. They never depend on key, nonce, tag, AAD, or payload bytes.
 * - Stack bounds (proved): stack usage stays within 320 bytes below the entry SP
 *   at every instruction.
 * - Clearing (proved): on return the 96 bytes [SP-136, SP-40) of the function's own
 *   frame (Poly1305 context, one-time key, lengths and expected tag) are zero, and r1-r3 are zero.
 * - Clearing (tested in tests/test_aead.c): the frames of the internal ChaCha20 and
 *   Poly1305 calls below SP-144 and r12 are zero after the call.
 * - Preconditions of the proofs (Aead.APre in proofs/). SP is the stack pointer at
 *   entry. "code" is the 3,030-byte .text of the linked m0crypto_chacha20poly1305 object.
 *   "A disjoint from B" means both address ranges end at or below 2^32 and do not
 *   overlap. An empty range [p, p) still must not start strictly inside the other range.
 *     code start 4-byte aligned; SP 8-byte aligned, SP >= 320 and SP + 16 <= 2^32;
 *     [SP-320, SP+16) (stack window and the four stack arguments) disjoint from the
 *       code, out and tag;
 *     [SP-320, SP) disjoint from in, aad, key and nonce;
 *     out and tag each disjoint from the code; aad and tag each disjoint from out;
 *     in equal to out or disjoint from it;
 *     LR has bit 0 set (Thumb) and the return address lies outside the code.
 *   key and nonce may overlap out, aad, tag and the code. in and aad may overlap the
 *   code.
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
