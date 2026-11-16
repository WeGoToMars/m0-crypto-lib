/* SPDX-License-Identifier: MIT
 * TF-PSA-Crypto (Mbed TLS 4.3.0) settings shared by both benchmark configurations:
 * the PSA core on a bare-metal Cortex-M0+ without an operating system. Each
 * primitive's configuration enables only the PSA_WANT_* features its operations need. */
#ifndef M0C_BENCH_MBEDTLS_COMMON_H
#define M0C_BENCH_MBEDTLS_COMMON_H

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PLATFORM_C
/* No libc: no time, file system, stdio or exit. */
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
/* The image has no entropy source; the harness supplies mbedtls_psa_external_get_random. */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
/* Key material in preallocated slots instead of the heap; each wrapper holds one key. */
#define MBEDTLS_PSA_STATIC_KEY_SLOTS
#define MBEDTLS_PSA_KEY_SLOT_COUNT 1
/* Caller buffers are ordinary RAM, not memory shared with another party:
 * the PSA core does not copy them. */
#define MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
/* Mbed TLS's bare-metal allocator over a static buffer (mbedtls/memory_buffer_alloc.h):
 * the PSA ChaCha20 cipher context and the elliptic-curve big numbers live on the heap. */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
/* The allocator stops on a corrupted heap: trap instead of calling exit. */
#define MBEDTLS_PLATFORM_EXIT_MACRO(status) __builtin_trap()
/* Upstream option for targets whose 64-bit division would be a linked software routine:
 * bignum uses its own division instead of __aeabi_uldivmod. */
#define MBEDTLS_NO_UDBL_DIVISION
/* Upstream default: Mbed TLS's Thumb-1 multiply-accumulate assembly in bignum. */
#define MBEDTLS_HAVE_ASM

#endif
