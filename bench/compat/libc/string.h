/* Freestanding stub: declarations only; definitions come from the test harness. */
#ifndef M0C_STUB_STRING_H
#define M0C_STUB_STRING_H
#include <stddef.h>
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strncpy(char *d, const char *s, size_t n);
int strncmp(const char *a, const char *b, size_t n);
char *strstr(const char *h, const char *n);
char *strncat(char *d, const char *s, size_t n);
#endif
