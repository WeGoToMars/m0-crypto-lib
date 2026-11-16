/* SPDX-License-Identifier: MIT
 * Mbed TLS 4.3.0 through its public PSA API: one complete-buffer operation per wrapper,
 * key import and destruction included. psa_crypto_init runs once, untimed (setup_mbed in
 * mbedtls_platform.c).
 * The AEAD wrappers use the multipart API, whose finish and verify calls take a separate
 * tag buffer like every other comparator; the one-shot psa_aead_encrypt writes the tag
 * after the ciphertext. */
#include <string.h>
#include <psa/crypto.h>
#include "job.h"

CALLER_STATE(mbed_chacha, sizeof(psa_key_attributes_t) + sizeof(psa_cipher_operation_t));
CALLER_STATE(mbed_encrypt, sizeof(psa_key_attributes_t) + sizeof(psa_aead_operation_t));
CALLER_STATE(mbed_decrypt, sizeof(psa_key_attributes_t) + sizeof(psa_aead_operation_t));

static psa_status_t import(const Job *j, psa_key_usage_t usage, psa_algorithm_t alg,
                           psa_key_id_t *key) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    return psa_import_key(&attributes, j->key, 32, key);
}

/* PSA's ChaCha20 stream cipher starts at block counter 0 (12-byte nonce). */
void run_mbed_chacha(Job *j) {
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    size_t n = 0, m = 0;
    psa_status_t s = import(j, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_STREAM_CIPHER, &key);
    if (s == PSA_SUCCESS) s = psa_cipher_encrypt_setup(&op, key, PSA_ALG_STREAM_CIPHER);
    if (s == PSA_SUCCESS) s = psa_cipher_set_iv(&op, j->nonce, 12);
    if (s == PSA_SUCCESS) s = psa_cipher_update(&op, j->in, j->len, j->out, j->len, &n);
    if (s == PSA_SUCCESS) s = psa_cipher_finish(&op, j->out + n, j->len - n, &m);
    psa_cipher_abort(&op);
    psa_destroy_key(key);
    j->status = s;
}

void run_mbed_encrypt(Job *j) {
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    size_t n = 0, m = 0, tag_length = 0;
    psa_status_t s = import(j, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_CHACHA20_POLY1305, &key);
    if (s == PSA_SUCCESS) s = psa_aead_encrypt_setup(&op, key, PSA_ALG_CHACHA20_POLY1305);
    if (s == PSA_SUCCESS) s = psa_aead_set_nonce(&op, j->nonce, 12);
    if (s == PSA_SUCCESS) s = psa_aead_update_ad(&op, j->aad, j->aad_len);
    if (s == PSA_SUCCESS) s = psa_aead_update(&op, j->in, j->len, j->out, j->len, &n);
    if (s == PSA_SUCCESS)
        s = psa_aead_finish(&op, j->out + n, j->len - n, &m, j->tag, 16, &tag_length);
    psa_aead_abort(&op);
    psa_destroy_key(key);
    j->status = s;
}

/* The multipart API releases plaintext before psa_aead_verify checks the tag: on
 * failure the caller must discard it, so the wrapper clears the output. */
void run_mbed_decrypt(Job *j) {
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    size_t n = 0, m = 0;
    psa_status_t s = import(j, PSA_KEY_USAGE_DECRYPT, PSA_ALG_CHACHA20_POLY1305, &key);
    if (s == PSA_SUCCESS) s = psa_aead_decrypt_setup(&op, key, PSA_ALG_CHACHA20_POLY1305);
    if (s == PSA_SUCCESS) s = psa_aead_set_nonce(&op, j->nonce, 12);
    if (s == PSA_SUCCESS) s = psa_aead_update_ad(&op, j->aad, j->aad_len);
    if (s == PSA_SUCCESS) s = psa_aead_update(&op, j->in, j->len, j->out, j->len, &n);
    if (s == PSA_SUCCESS) s = psa_aead_verify(&op, j->out + n, j->len - n, &m, j->tag, 16);
    if (s != PSA_SUCCESS) memset(j->out, 0, j->len);
    psa_aead_abort(&op);
    psa_destroy_key(key);
    j->status = s;
}
