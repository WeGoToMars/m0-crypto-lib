/* SPDX-License-Identifier: MIT
 * One X25519 scalar multiplication per wrapper. key is the 32-byte scalar, in the
 * 32-byte peer u-coordinate (ignored by the public-key wrappers), out the 32-byte
 * result. All setup is included. */
#include "job.h"
#include "m0crypto/x25519.h"
#include <wolfssl/wolfcrypt/curve25519.h>
#include "monocypher.h"
#include "crypto/ecx.h"

CALLER_STATE(wolf_shared, 2 * sizeof(curve25519_key));

static const uint8_t base_point[32] = {9};

void run_m0c_shared(Job *j) { j->status = m0c_x25519(j->out, j->key, j->in); }
void run_m0c_public(Job *j) { j->status = m0c_x25519(j->out, j->key, base_point); }

/* Thomas Pornin's x25519-cm0: void x25519(void *dst, const void *src, const void *scalar). */
void x25519(void *dst, const void *src, const void *scalar);
void run_pornin_shared(Job *j) { x25519(j->out, j->in, j->key); j->status = 0; }
void run_pornin_public(Job *j) { x25519(j->out, base_point, j->key); j->status = 0; }

/* wolfSSL public API: key objects, little-endian import and export. */
void run_wolf_shared(Job *j) {
    curve25519_key private_key, public_key;
    word32 length = 32;
    int r = wc_curve25519_init(&private_key);
    if (!r) r = wc_curve25519_init(&public_key);
    if (!r) r = wc_curve25519_import_private_ex(j->key, 32, &private_key, EC25519_LITTLE_ENDIAN);
    if (!r) r = wc_curve25519_import_public_ex(j->in, 32, &public_key, EC25519_LITTLE_ENDIAN);
    if (!r) r = wc_curve25519_shared_secret_ex(&private_key, &public_key, j->out, &length,
                                               EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&private_key);
    wc_curve25519_free(&public_key);
    j->status = r;
}
void run_wolf_public(Job *j) { j->status = wc_curve25519_make_pub(32, j->out, 32, j->key); }

void run_mono_shared(Job *j) { crypto_x25519(j->out, j->key, j->in); j->status = 0; }
void run_mono_public(Job *j) { crypto_x25519_public_key(j->out, j->key); j->status = 0; }

/* OpenSSL's portable crypto/ec/curve25519.c (no EVP dispatch). The public key uses the
 * ladder on the base point, like every other comparator: ossl_x25519_public_from_private
 * multiplies on the Edwards curve with a 30 KB precomputed table that no build option
 * removes, and leaving it unreferenced lets --gc-sections drop the table. */
void run_ossl_shared(Job *j) { j->status = ossl_x25519(j->out, j->key, j->in) ? 0 : -1; }
void run_ossl_public(Job *j) { j->status = ossl_x25519(j->out, j->key, base_point) ? 0 : -1; }
