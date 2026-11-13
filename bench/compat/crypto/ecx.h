/* Benchmark build: the declarations curve25519.c needs from include/crypto/ecx.h. */
#ifndef M0C_COMPAT_ECX_H
#define M0C_COMPAT_ECX_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32
int ossl_x25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
                const uint8_t peer_public_value[32]);
void ossl_x25519_public_from_private(uint8_t out_public_value[32],
                                     const uint8_t private_key[32]);
#endif
