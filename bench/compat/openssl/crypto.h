#include <stddef.h>
#include <openssl/e_os2.h> /* as the real crypto.h; blake2_impl.h relies on it */
void OPENSSL_cleanse(void *p, size_t n);
int CRYPTO_memcmp(const void *a, const void *b, size_t len);
