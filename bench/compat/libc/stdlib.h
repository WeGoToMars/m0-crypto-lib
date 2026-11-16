/* Freestanding stub: wolfSSL types.h references malloc/free; ChaCha never calls them.
 * Mbed TLS's platform layer refers to calloc/free when MBEDTLS_PLATFORM_MEMORY is off. */
#ifndef M0C_STUB_STDLIB_H
#define M0C_STUB_STDLIB_H
#include <stddef.h>
void *malloc(size_t n);
void *calloc(size_t n, size_t size);
void free(void *p);
void *realloc(void *p, size_t n);
#endif
