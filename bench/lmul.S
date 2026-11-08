/*
 * uint64_t __aeabi_lmul(uint64_t a, uint64_t b): low 64 bits of a * b (RTABI).
 * Benchmark image only. wolfSSL's 32-bit Poly1305 (POLY130532) calls this for every
 * 32x32->64 product; an embedded build would normally take it from libgcc or
 * compiler-rt, which are not installed for thumbv6m here. This version builds the
 * 32x32->64 core from four 16x16 MULS, the same technique m0c's Poly1305 uses, so
 * the comparison does not hand wolfSSL a slow helper. Named wolf_* so that the
 * sram placement moves it with wolfSSL's code.
 * a = r1:r0, b = r3:r2, result r1:r0. About 30 cycles including the call return.
 */
    .syntax unified
    .thumb
    .text
    .p2align 2
    .global __aeabi_lmul
    .type __aeabi_lmul, %function
    .thumb_func
__aeabi_lmul:
    push {r4-r6, lr}
    muls r1, r2, r1             /* ahi * blo (low 32 bits) */
    muls r3, r0, r3             /* bhi * alo (low 32 bits) */
    adds r6, r1, r3             /* cross terms, mod 2^32 */
    uxth r1, r0                 /* aL */
    lsrs r0, r0, #16            /* aH */
    uxth r3, r2                 /* bL */
    lsrs r2, r2, #16            /* bH */
    movs r4, r1
    muls r4, r3, r4             /* aL bL */
    movs r5, r0
    muls r5, r2, r5             /* aH bH */
    muls r1, r2, r1             /* aL bH */
    muls r0, r3, r0             /* aH bL */
    lsls r2, r1, #16
    lsrs r1, r1, #16
    adds r4, r2
    adcs r5, r1
    lsls r2, r0, #16
    lsrs r0, r0, #16
    adds r4, r2
    adcs r5, r0
    adds r1, r5, r6
    movs r0, r4
    pop  {r4-r6, pc}
    .size __aeabi_lmul, . - __aeabi_lmul
