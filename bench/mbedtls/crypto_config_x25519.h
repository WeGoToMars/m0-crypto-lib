/* SPDX-License-Identifier: MIT
 * TF-PSA-Crypto configuration of the X25519 comparison image. */
#ifndef M0C_BENCH_MBEDTLS_CONFIG_H
#define M0C_BENCH_MBEDTLS_CONFIG_H
#include "crypto_config_common.h"

#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1

#endif
