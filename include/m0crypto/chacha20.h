/*
 * m0-crypto: ChaCha20 stream cipher (RFC 8439 section 2.4).
 * SPDX-License-Identifier: MIT
 *
 * Verified in Lean 4 against the release machine code:
 * - Correct: the output matches RFC 8439 for every length, alignment and
 *   allowed buffer overlap.
 * - Constant time: the instructions executed and the memory addresses
 *   accessed depend only on addresses, len and counter, never on the key,
 *   nonce or data.
 * - Memory: reads only its input buffers, its own code and its stack, and
 *   writes only out and its stack, within the stack size listed below.
 * - Clean-up: before it returns, the function erases every temporary value it
 *   computed from the key, nonce or data, so none is left on the stack. Your
 *   own buffers are not touched beyond out: wipe the key yourself when you no
 *   longer need it. If an interrupt arrives during the call, the processor
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
#ifndef M0CRYPTO_CHACHA20_H
#define M0CRYPTO_CHACHA20_H

#include <stddef.h>
#include <stdint.h>
#ifndef M0C_OK
#define M0C_OK 0   /* success; defined by every status-returning header */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define M0C_ERR_COUNTER (-1)

/*
 * XORs len bytes from in with the ChaCha20 keystream starting at block counter
 * (counter, counter + 1, ...) and writes the result to out. Encryption and
 * decryption are identical.
 *
 * Returns: M0C_OK (0), or M0C_ERR_COUNTER (-1) without modifying out if
 *          processing len bytes would require a block counter past 0xFFFFFFFF.
 * Buffers: Any alignment. out must equal in or not overlap it, and must not
 *          overlap key or nonce. When len == 0, in and out are not accessed:
 *          they may be NULL, but must not point into the middle of another
 *          buffer.
 * Stack:   176 bytes.
 * Caution: Nonce uniqueness per key is the caller's responsibility.
 */
int m0c_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[32], const uint8_t nonce[12],
                     uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif
