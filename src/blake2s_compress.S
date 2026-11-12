/* SPDX-License-Identifier: MIT
 * BLAKE2s compression (RFC 7693, section 3.2), ten unrolled rounds, in-place h update.
 * Contract: blake2s_internal.h. Single entry, no external calls, 136-byte frame.
 * Clearing: before returning, the 100 local bytes (message copy, v1..v7, h pointer,
 * padding) are overwritten with zeros by five fixed five-word STM batches, and
 * r0-r3 and r12 are zero on return (r4-r11 are restored from the saved area). The
 * 36 saved bytes hold the caller's register values and are not cleared. The h
 * array is the result and is not cleared.
 *
 * The message block is copied to the frame once, so every message load is
 * SP-relative and no low register holds a message pointer. Working state v0..v15:
 *   r8                   v0
 *   [sp, #V(1)..V(7)]    v1..v7 (slot V(0) is alignment padding, never accessed)
 *   r2, r5, r6, r7       row c: v8, v9, v10, v11
 *   r9-r12               row d (v12..v15)
 *   [sp, #M(0)..M(15)]   message words m0..m15
 *   [sp, #H_PTR]         h pointer for the feed-forward
 * Round registers: r0/r1/r3 = a/b/d of the current G, its c is updated in place in
 * its row-c register, r4 = message word or rotation count.
 * Rotations: 16, 12, 8 and 7 by RORS with the count in r4. IV words are PC-relative
 * literal loads (LDR [pc]); no ADR, REV or data loads through a code pointer.
 * Control flow and addresses depend on nothing but the code; no table lookups.
 */
.syntax unified
.thumb
#ifdef M0C_UNIT
    .text                       /* one section: in-unit calls need no relocation */
#else
    .section .text.m0c_blake2s_compress,"ax",%progbits
#endif

#define V(i)        (4*(i))
#define M(i)        (32+4*(i))
#define H_PTR       96
#define LOCALS      100         /* 100 + 36 saved = 136, keeps SP 8-byte aligned */
#define SAVED       36          /* r4-r11, lr */
#define F0_ARG      (LOCALS+SAVED)
#define A_HIGH_WORD 0           /* row-a word held in r8 */

/* Move v[a] (a in row a) into r0, or r0 back into v[a]. */
.macro LOAD_A a
    .if \a == A_HIGH_WORD
    mov r0, r8
    .else
    ldr r0, [sp, #V(\a)]
    .endif
.endm
.macro STORE_A a
    .if \a == A_HIGH_WORD
    mov r8, r0
    .else
    str r0, [sp, #V(\a)]
    .endif
.endm

/* One G on (a, b, c, d) with message words m[x], m[y]; creg/dreg hold v[c]/v[d].
 * have_a: v[a] is already in r0. keep_a: leave v[a] in r0, do not store it.
 */
.macro B2_G a,b,creg,dreg,x,y,have_a=0,keep_a=0
    .if !\have_a
    LOAD_A \a
    .endif
    ldr r1, [sp, #V(\b)]
    mov r3, \dreg
    ldr r4, [sp, #M(\x)]
    adds r0, r0, r1
    adds r0, r0, r4
    eors r3, r0
    movs r4, #16
    rors r3, r4
    adds \creg, \creg, r3
    eors r1, \creg
    movs r4, #12
    rors r1, r4
    ldr r4, [sp, #M(\y)]
    adds r0, r0, r1
    adds r0, r0, r4
    eors r3, r0
    movs r4, #8
    rors r3, r4
    adds \creg, \creg, r3
    eors r1, \creg
    movs r4, #7
    rors r1, r4
    .if !\keep_a
    STORE_A \a
    .endif
    str r1, [sp, #V(\b)]
    mov \dreg, r3
.endm

/* One round with schedule s0..s15. The four Gs of each half-round touch disjoint
 * words, so they may run in any order. The order below lets v3 pass from the
 * last column G to the first diagonal G, and v2 from the last diagonal G to the
 * first column G of the next round, in r0.
 */
.macro B2_ROUND s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,first=0
    B2_G 2,6,r6,r11,\s4,\s5,(!\first)
    B2_G 0,4,r2,r9,\s0,\s1
    B2_G 1,5,r5,r10,\s2,\s3
    B2_G 3,7,r7,r12,\s6,\s7,0,1
    B2_G 3,4,r5,r11,\s14,\s15,1
    B2_G 0,5,r6,r12,\s8,\s9
    B2_G 1,6,r7,r9,\s10,\s11
    B2_G 2,7,r2,r10,\s12,\s13,0,1
.endm

/* Feed-forward helpers for h4..h7: r0-r3 hold four h words, r6 is scratch. */
.macro FF_LOAD_XOR dst, slot
    ldr r6, [sp, #V(\slot)]
    eors \dst, r6
.endm
.macro FF_REG_XOR dst, reg
    mov r6, \reg
    eors \dst, r6
.endm
/* Copy four words from r1 to r4 (both advance); clobbers r0, r2, r3, r6. */
.macro COPY4
    ldm r1!, {r0,r2,r3,r6}
    stm r4!, {r0,r2,r3,r6}
.endm

.p2align 2
.global m0c_blake2s_compress
.type m0c_blake2s_compress,%function
.thumb_func
m0c_blake2s_compress:
.Lm0c_blake2s_compress:         /* local alias for in-unit calls */
    push {r4-r7,lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4-r7}
    sub sp, #LOCALS
    /* r0 = h, r1 = block, r2 = t0, r3 = t1, [sp, #F0_ARG] = f0 */
    str r0, [sp, #H_PTR]
    ldr r0, .Lb2_iv4
    eors r0, r2
    mov r9, r0                  /* v12 = IV4 ^ t0 */
    ldr r5, .Lb2_iv5
    eors r5, r3
    mov r10, r5                 /* v13 = IV5 ^ t1 */
    ldr r0, [sp, #F0_ARG]
    ldr r6, .Lb2_iv6
    eors r6, r0
    mov r11, r6                 /* v14 = IV6 ^ f0 */
    ldr r0, .Lb2_iv7
    mov r12, r0                 /* v15 = IV7 */
    add r4, sp, #M(0)
    COPY4
    COPY4
    COPY4
    COPY4                       /* m0..m15 */
    ldr r1, [sp, #H_PTR]
    ldm r1!, {r0,r2,r3,r6}      /* h0..h3 */
    mov r8, r0                  /* v0 = h0 */
    add r4, sp, #V(1)
    stm r4!, {r2,r3,r6}         /* v1..v3 = h1..h3 */
    COPY4                       /* v4..v7 = h4..h7 */
    ldr r2, .Lb2_iv0               /* v8..v11 = IV0..IV3 */
    ldr r5, .Lb2_iv1
    ldr r6, .Lb2_iv2
    ldr r7, .Lb2_iv3
    b .Lb2_rounds
.p2align 2
.Lb2_iv0: .word 0x6a09e667
.Lb2_iv1: .word 0xbb67ae85
.Lb2_iv2: .word 0x3c6ef372
.Lb2_iv3: .word 0xa54ff53a
.Lb2_iv4: .word 0x510e527f
.Lb2_iv5: .word 0x9b05688c
.Lb2_iv6: .word 0x1f83d9ab
.Lb2_iv7: .word 0x5be0cd19
.Lb2_rounds:
    B2_ROUND 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1
    B2_ROUND 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3
    B2_ROUND 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4
    B2_ROUND 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8
    B2_ROUND 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13
    B2_ROUND 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9
    B2_ROUND 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11
    B2_ROUND 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10
    B2_ROUND 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5
    B2_ROUND 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0

    /* Rows a and c: x_i = v_i ^ v_(i+8). v2 is still in r0 from the last G. */
    eors r0, r6                 /* x2 */
    mov r6, r8
    eors r2, r6                 /* x0 */
    ldr r6, [sp, #V(1)]
    eors r5, r6                 /* x1 */
    ldr r6, [sp, #V(3)]
    eors r7, r6                 /* x3 */
    ldr r4, [sp, #H_PTR]
    ldr r1, [r4, #0]
    eors r1, r2                 /* h0 ^ x0 */
    ldr r2, [r4, #4]
    eors r2, r5                 /* h1 ^ x1 */
    ldr r3, [r4, #8]
    eors r3, r0                 /* h2 ^ x2 */
    ldr r5, [r4, #12]
    eors r5, r7                 /* h3 ^ x3 */
    stm r4!, {r1,r2,r3,r5}
    ldm r4!, {r0-r3}            /* h4..h7 */
    FF_LOAD_XOR r0, 4
    FF_REG_XOR r0, r9
    FF_LOAD_XOR r1, 5
    FF_REG_XOR r1, r10
    FF_LOAD_XOR r2, 6
    FF_REG_XOR r2, r11
    FF_LOAD_XOR r3, 7
    FF_REG_XOR r3, r12
    subs r4, #16
    stm r4!, {r0-r3}

    /* Clear all LOCALS bytes (25 words) in LOCALS/20 fixed five-word batches.
     * r5 is reloaded by the epilogue; r0-r3 and r12 leave zero. */
.if LOCALS % 20 != 0
.error "LOCALS must be a multiple of 20: the clear stores five words per STM"
.endif
    movs r0, #0
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r4, #0
    add r5, sp, #0
    .rept LOCALS/20
    stm r5!, {r0-r4}
    .endr
    mov r12, r0

    add sp, #LOCALS
    pop {r4-r7}
    mov r8, r4
    mov r9, r5
    mov r10, r6
    mov r11, r7
    pop {r4-r7,pc}
.size m0c_blake2s_compress,.-m0c_blake2s_compress
.purgem LOAD_A
.purgem STORE_A
.purgem B2_G
.purgem B2_ROUND
.purgem FF_LOAD_XOR
.purgem FF_REG_XOR
.purgem COPY4
#undef V
#undef M
#undef H_PTR
#undef LOCALS
#undef SAVED
#undef F0_ARG
#undef A_HIGH_WORD
