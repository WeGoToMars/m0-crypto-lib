#include <stddef.h>
#include <stdint.h>
void ref_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]);
void ref_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                      const uint8_t nonce[12], uint32_t counter);
