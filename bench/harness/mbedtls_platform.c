/* SPDX-License-Identifier: MIT
 * Platform pieces Mbed TLS 4.3.0 needs on a bare-metal Cortex-M0+, shared by both
 * comparison images.
 *
 * setup_mbed runs once, untimed, before the timed calls (armv6m.py and the board image):
 * Mbed TLS's bare-metal allocator over mbed_heap, then psa_crypto_init. Mbed TLS takes
 * its ChaCha20 cipher context and its big numbers from that heap; armv6m.py reports the
 * high-water mark of mbed_heap during each call as the call's heap use.
 *
 * mbedtls_psa_external_get_random is the callback MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 * requires. The images have no entropy source: this deterministic stand-in returns the
 * same bytes on every call, so repeated runs execute the same instructions. Only the
 * X25519 operations draw from it (Mbed TLS randomises the ladder's projective
 * coordinates). Not a random-number generator. */
#include <psa/crypto.h>
#include <mbedtls/memory_buffer_alloc.h>

#define MBED_HEAP_BYTES 4096
__attribute__((aligned(8))) unsigned char mbed_heap[MBED_HEAP_BYTES];

void setup_mbed(void) {
    mbedtls_memory_buffer_alloc_init(mbed_heap, sizeof mbed_heap);
    (void)psa_crypto_init();
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context, uint8_t *output, size_t output_size,
    size_t *output_length)
{
    (void)context;
    for (size_t i = 0; i < output_size; i++) output[i] = (uint8_t)(0x5a ^ (i * 0x3b));
    *output_length = output_size;
    return PSA_SUCCESS;
}
