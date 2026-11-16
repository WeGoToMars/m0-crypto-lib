/* SPDX-License-Identifier: MIT
 * TF-PSA-Crypto configuration of the ChaCha20-Poly1305 comparison image. */
#ifndef M0C_BENCH_MBEDTLS_CONFIG_H
#define M0C_BENCH_MBEDTLS_CONFIG_H
#include "crypto_config_common.h"

#define PSA_WANT_KEY_TYPE_CHACHA20      1
#define PSA_WANT_ALG_STREAM_CIPHER      1
#define PSA_WANT_ALG_CHACHA20_POLY1305  1

#endif
