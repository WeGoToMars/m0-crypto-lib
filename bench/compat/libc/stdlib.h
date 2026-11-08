/* Freestanding stub: wolfSSL types.h references malloc/free; ChaCha never calls them. */
#ifndef M0C_STUB_STDLIB_H
#define M0C_STUB_STDLIB_H
#include <stddef.h>
void *malloc(size_t n);
void free(void *p);
void *realloc(void *p, size_t n);
#endif
