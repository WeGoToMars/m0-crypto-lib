/*
 * Freestanding C runtime pieces for the benchmark image (not part of the library).
 * memcpy has a word path for co-aligned buffers so that wolfSSL's key setup is not
 * penalised by a byte-only copy; ChaCha block processing in either implementation
 * does not call memcpy (checked by the link map / disassembly).
 */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = d;
    const uint8_t *ss = s;
    if ((((uintptr_t)dd | (uintptr_t)ss) & 3) == 0) {
        while (n >= 4) {
            *(uint32_t *)dd = *(const uint32_t *)ss;
            dd += 4; ss += 4; n -= 4;
        }
    }
    while (n--) *dd++ = *ss++;
    return d;
}
/* volatile so that clearing is never optimised away; word path for aligned buffers
 * (wolfSSL clears its Poly1305/AEAD state through memclr). */
void *memset(void *d, int c, size_t n) {
    volatile uint8_t *dd = d;
    if (((uintptr_t)dd & 3) == 0) {
        uint32_t w = (uint8_t)c * 0x01010101u;
        while (n >= 4) {
            *(volatile uint32_t *)dd = w;
            dd += 4; n -= 4;
        }
    }
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
void __aeabi_memclr(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr4(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr8(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memset(void *d, size_t n, int c) { memset(d, c, n); }
void __aeabi_memset4(void *d, size_t n, int c) { memset(d, c, n); }
void __aeabi_memcpy(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy4(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy8(void *d, const void *s, size_t n) { memcpy(d, s, n); }

void OPENSSL_cleanse(void *p, size_t n) { memset(p, 0, n); }
int memcmp(const void *a, const void *b, size_t n) {
 const unsigned char *x=a,*y=b;
 for (size_t i=0;i<n;i++) if(x[i]!=y[i]) return x[i]<y[i]?-1:1;
 return 0;
}
