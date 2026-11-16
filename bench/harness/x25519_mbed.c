/* SPDX-License-Identifier: MIT
 * Mbed TLS 4.3.0 X25519 through its public PSA API: key import, the operation and key
 * destruction in every wrapper. The allocator and psa_crypto_init are set up once,
 * untimed (setup_mbed in mbedtls_platform.c). */
#include <psa/crypto.h>
#include "job.h"

CALLER_STATE(mbed_shared, sizeof(psa_key_attributes_t));
CALLER_STATE(mbed_public, sizeof(psa_key_attributes_t));

static psa_status_t import(const Job *j, psa_key_id_t *key) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    return psa_import_key(&attributes, j->key, 32, key);
}

void run_mbed_shared(Job *j) {
    psa_key_id_t key = PSA_KEY_ID_NULL;
    size_t n = 0;
    psa_status_t s = import(j, &key);
    if (s == PSA_SUCCESS) s = psa_raw_key_agreement(PSA_ALG_ECDH, key, j->in, 32, j->out, 32, &n);
    psa_destroy_key(key);
    j->status = s;
}

void run_mbed_public(Job *j) {
    psa_key_id_t key = PSA_KEY_ID_NULL;
    size_t n = 0;
    psa_status_t s = import(j, &key);
    if (s == PSA_SUCCESS) s = psa_export_public_key(key, j->out, 32, &n);
    psa_destroy_key(key);
    j->status = s;
}
