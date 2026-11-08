/*
 * m0-crypto: ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8) and its Poly1305 core
 * (section 2.5) for ARMv6-M, register-resident Poly1305 accumulator.
 * SPDX-License-Identifier: MIT
 *
 * Public (include/m0crypto/chacha20poly1305.h):
 *   int m0c_chacha20poly1305_encrypt(out, tag, in, len, aad, aad_len, key, nonce)
 *   int m0c_chacha20poly1305_decrypt(out, tag, in, len, aad, aad_len, key, nonce)
 * Internal, global only so the test image can reach them (no public header):
 *   void m0c_poly1305_init(uint32_t ctx[16], const uint8_t key[32]);  key 4-byte aligned
 *   void m0c_poly1305_blocks(uint32_t ctx[16], const uint8_t *m, size_t nblocks,
 *                            uint32_t padbit);
 *   void m0c_poly1305_finish(uint32_t ctx[16], uint8_t tag[16]);
 *
 * Poly1305 arithmetic: radix 2^32, h = h0..h4 (h4 small), r = r0..r3 clamped,
 * s_j = r_j + (r_j >> 2) = 5 r_j / 4 (exact, since r1..r3 are multiples of 4).
 * Per block (the 32-bit-limb formulation used by OpenSSL's poly1305.c):
 *   h += m + padbit * 2^128
 *   d0 = h0 r0 + h1 s3 + h2 s2 + h3 s1
 *   d1 = h0 r1 + h1 r0 + h2 s3 + h3 s2 + h4 s1
 *   d2 = h0 r2 + h1 r1 + h2 r0 + h3 s3 + h4 s2
 *   d3 = h0 r3 + h1 r2 + h2 r1 + h3 r0 + h4 s3
 *   carry d0 -> d1 -> d2 -> d3 -> h4 = hi(d3) + h4 r0, then fold bits >= 2^130 by 5.
 * MULS gives only the low 32 bits, so each 32x29-bit product is built from four
 * 16x16 products (MAC macro). Bounds: r_j < 2^28, s_j < 2^29, h4 <= 6 at the
 * multiply. More precise bounds, discharged for the release bytes by the Lean proofs
 * (PolyBlocks.blocks_correct keeps h < 5*2^128, i.e. h4 <= 4):
 * - r_j <= 2^28-1; s_j <= 5*(2^26-1). h0..h3 <= 2^32-1.
 * - Before message addition h4 <= 4; carry and padbit <= 1 each give h4 <= 6.
 * - aL,aH,bL < 2^16 and bH < 2^13: all four MULS products < 2^32.
 * - Each wide product < 5*2^58 (< 2^61). Four such products, a narrow
 *   h4*s (< 2^31), and incoming carry (< 2^31) sum to
 *   < 20*2^58+2^32 < 2^63 < 2^64. Starting with d0 (no incoming
 *   carry/narrow term), this inductively preserves carry hi(d_j) < 2^31.
 * - d3's four wide factors are r, not s, so d3 < 2^62+2^32 and hi(d3) <= 2^30.
 *   hi(d3)+h4*r0 <= 10*2^28 < 2^32; c=5*floor(that/4) <= 50*2^26 < 2^32.
 *   The fold adds c to 128 bits and its carry to (that & 3), restoring h4 <= 4.
 * The low/high ADC chains are exact integer column sums, not truncated products.
 *
 * Timing contract (design property, not yet proved or measured): control flow and
 * memory addresses depend only on len, aad_len, the pointer values and, for decrypt,
 * the public accept/reject verdict; never on key, nonce, tag or data values.
 * Poly1305 selects word loads only for a public 4-byte-aligned message pointer;
 * unaligned pointers use byte loads. Both paths add the same message words.
 * MULS is assumed fixed-latency, as on the reference Cortex-M0+.
 */
#ifndef M0C_UNIT
#error "assemble src/m0crypto.S (one relocation-free unit), not this file"
#endif
    .syntax unified
    .thumb

/* Poly1305 context: 16 words. */
#define P_H0    0
#define P_H1    4
#define P_H2    8
#define P_H3    12
#define P_H4    16
#define P_R0    20
#define P_R1    24
#define P_R2    28
#define P_R3    32
#define P_S1    36
#define P_S2    40
#define P_S3    44
#define P_PAD   48          /* 48..63: s, the second key half */

/* dst = little-endian word at base+off (any alignment); clobbers tmp. off <= 28. */
.macro LDLE dst, tmp, base, off
    ldrb \dst, [\base, #\off]
    ldrb \tmp, [\base, #\off+1]
    lsls \tmp, \tmp, #8
    orrs \dst, \tmp
    ldrb \tmp, [\base, #\off+2]
    lsls \tmp, \tmp, #16
    orrs \dst, \tmp
    ldrb \tmp, [\base, #\off+3]
    lsls \tmp, \tmp, #24
    orrs \dst, \tmp
.endm


/* Store val little-endian at base+off (any alignment); destroys val. */
.macro STLE val, base, off
    strb \val, [\base, #\off]
    lsrs \val, \val, #8
    strb \val, [\base, #\off+1]
    lsrs \val, \val, #8
    strb \val, [\base, #\off+2]
    lsrs \val, \val, #8
    strb \val, [\base, #\off+3]
.endm

/*
 * (r1:r0) += a * b, a = high register hreg (32 bits), b = ctx word at rb (< 2^29).
 * a = aH 2^16 + aL, b = bH 2^16 + bL: a b = aL bL + aH bH 2^32 + (aL bH + aH bL) 2^16.
 * Each partial product is < 2^32. The caller guarantees the column sum is < 2^64,
 * so no carry leaves r1. Clobbers r2-r6; r7 = ctx.
 */
.macro MAC hreg, rb
    mov  r5, \hreg
    lsrs r6, r5, #16            /* aH */
    uxth r5, r5                 /* aL */
    ldrh r3, [r7, #\rb]         /* bL */
    ldrh r4, [r7, #\rb+2]       /* bH */
    movs r2, r5
    muls r2, r4, r2             /* aL bH */
    muls r4, r6, r4             /* aH bH */
    muls r6, r3, r6             /* aH bL */
    muls r3, r5, r3             /* aL bL */
    adds r0, r3
    adcs r1, r4
    lsls r3, r2, #16
    lsrs r2, r2, #16
    adds r0, r3
    adcs r1, r2
    lsls r3, r6, #16
    lsrs r6, r6, #16
    adds r0, r3
    adcs r1, r6
.endm

/* (r1:r0) += h4 * (ctx word at sb); lr = h4 <= 6, h4 * s < 2^31.
 * Clobbers r2, r3. */
.macro NARROW sb
    mov  r2, lr
    ldr  r3, [r7, #\sb]
    muls r2, r3, r2
    movs r3, #0
    adds r0, r2
    adcs r1, r3
.endm

    .text

/* void m0c_poly1305_init(uint32_t ctx[16], const uint8_t key[32])
 * Internal: key must be 4-byte aligned (the AEAD passes its stack block). Straight-line. */
    .p2align 2
    .global m0c_poly1305_init
    .type m0c_poly1305_init, %function
    .thumb_func
m0c_poly1305_init:
.Lm0c_poly1305_init:
    push {r4, r5, lr}
    ldr  r4, =0x0fffffff
    ldr  r2, [r1, #0]
    ands r2, r4
    str  r2, [r0, #P_R0]
    ldr  r4, =0x0ffffffc
    .irp i, 1, 2, 3
    ldr  r2, [r1, #4*\i]
    ands r2, r4
    str  r2, [r0, #P_R0+4*\i]
    lsrs r5, r2, #2
    adds r5, r2
    str  r5, [r0, #P_S1+4*(\i-1)]
    .endr
    .irp i, 0, 1, 2, 3
    ldr  r2, [r1, #16+4*\i]
    str  r2, [r0, #P_PAD+4*\i]
    .endr
    movs r2, #0
    str  r2, [r0, #P_H0]
    str  r2, [r0, #P_H1]
    str  r2, [r0, #P_H2]
    str  r2, [r0, #P_H3]
    str  r2, [r0, #P_H4]
    movs r1, #0
    movs r3, #0
    pop  {r4, r5, pc}
    .ltorg
    .size m0c_poly1305_init, . - m0c_poly1305_init

/* void m0c_poly1305_blocks(uint32_t ctx[16], const uint8_t *m, size_t nblocks,
 *                          uint32_t padbit)   padbit is 0 or 1 */
#define PB_FRAME 28                 /* T0..T3, message pointer, block count, zeroed padding */
    .p2align 2
    .global m0c_poly1305_blocks
    .type m0c_poly1305_blocks, %function
    .thumb_func
m0c_poly1305_blocks:
.Lm0c_poly1305_blocks:
    push {r4-r7, lr}
    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11
    push {r4-r7}
    sub  sp, #PB_FRAME              /* 20 + 16 + 28 = 64: sp stays 8-byte aligned */
    cmp  r2, #0
    bne  1f
    b    .Lpb_return
1:  movs r7, r0
    str  r1, [sp, #16]
    str  r2, [sp, #20]
    mov  r12, r3                   /* public padbit */
    ldr  r4, [r7, #P_H0]
    ldr  r5, [r7, #P_H1]
    ldr  r6, [r7, #P_H2]
    ldr  r0, [r7, #P_H3]
    mov  r8, r4
    mov  r9, r5
    mov  r10, r6
    mov  r11, r0
    ldr  r0, [r7, #P_H4]
    mov  lr, r0                    /* leaf routine; return address saved on stack */

.Lpb_block:
    /* h += m + padbit 2^128 */
    ldr  r6, [sp, #16]
    movs r4, #3
    tst  r6, r4
    bne  .Lpb_unaligned
    ldmia r6!, {r0-r3}             /* public alignment; no over-read */
    b    .Lpb_message
.Lpb_unaligned:
    LDLE r0, r4, r6, 0
    LDLE r1, r4, r6, 4
    LDLE r2, r4, r6, 8
    LDLE r3, r4, r6, 12
    adds r6, #16
.Lpb_message:
    str  r6, [sp, #16]
    mov  r4, r8
    adds r0, r4
    mov  r4, r9
    adcs r1, r4
    mov  r4, r10
    adcs r2, r4
    mov  r4, r11
    adcs r3, r4
    mov  r4, lr
    mov  r5, r12                    /* MOV (high register form) keeps the carry */
    adcs r4, r5
    mov  r8, r0
    mov  r9, r1
    mov  r10, r2
    mov  r11, r3
    mov  lr, r4

    /* d0 */
    movs r0, #0
    movs r1, #0
    MAC  r8, P_R0
    MAC  r9, P_S3
    MAC  r10, P_S2
    MAC  r11, P_S1
    str  r0, [sp, #0]
    movs r0, r1                     /* carry hi(d0) into d1 */
    movs r1, #0
    /* d1 */
    MAC  r8, P_R1
    MAC  r9, P_R0
    MAC  r10, P_S3
    MAC  r11, P_S2
    NARROW P_S1
    str  r0, [sp, #4]
    movs r0, r1
    movs r1, #0
    /* d2 */
    MAC  r8, P_R2
    MAC  r9, P_R1
    MAC  r10, P_R0
    MAC  r11, P_S3
    NARROW P_S2
    str  r0, [sp, #8]
    movs r0, r1
    movs r1, #0
    /* d3 */
    MAC  r8, P_R3
    MAC  r9, P_R2
    MAC  r10, P_R1
    MAC  r11, P_R0
    NARROW P_S3
    str  r0, [sp, #12]
    /* h4 = hi(d3) + h4 r0 */
    mov  r2, lr
    ldr  r3, [r7, #P_R0]
    muls r2, r3, r2
    adds r4, r1, r2
    /* c = (h4 >> 2) + (h4 & ~3) = 5 (h4 >> 2); h4 &= 3; h += c */
    lsrs r5, r4, #2
    movs r2, #3
    ands r2, r4
    subs r4, r4, r2
    adds r5, r4
    movs r6, #0
    ldr  r0, [sp, #0]
    adds r0, r5
    ldr  r1, [sp, #4]
    adcs r1, r6
    ldr  r3, [sp, #8]
    adcs r3, r6
    ldr  r4, [sp, #12]
    adcs r4, r6
    adcs r2, r6
    mov  r8, r0
    mov  r9, r1
    mov  r10, r3
    mov  r11, r4
    mov  lr, r2

    ldr  r0, [sp, #20]
    subs r0, #1
    str  r0, [sp, #20]
    beq  .Lpb_done
    b    .Lpb_block
.Lpb_done:
    /* Publish all five h words only at the call boundary. */
    mov  r0, r8
    mov  r1, r9
    mov  r2, r10
    mov  r3, r11
    str  r0, [r7, #P_H0]
    str  r1, [r7, #P_H1]
    str  r2, [r7, #P_H2]
    str  r3, [r7, #P_H3]
    mov  r0, lr
    str  r0, [r7, #P_H4]
    movs r0, #0
    mov  lr, r0
    str  r0, [sp, #0]
    str  r0, [sp, #4]
    str  r0, [sp, #8]
    str  r0, [sp, #12]
    str  r0, [sp, #16]
    str  r0, [sp, #20]
    str  r0, [sp, #24]
    mov  r12, r0
    movs r1, #0
    movs r2, #0
    movs r3, #0
.Lpb_return:
    add  sp, #PB_FRAME
    pop  {r4-r7}
    mov  r8, r4
    mov  r9, r5
    mov  r10, r6
    mov  r11, r7
    pop  {r4-r7, pc}
    .size m0c_poly1305_blocks, . - m0c_poly1305_blocks

/* void m0c_poly1305_finish(uint32_t ctx[16], uint8_t tag[16])
 * tag = (h mod p + s) mod 2^128. On entry h < 2^130 + 2^128 < 2p, so one
 * conditional subtraction of p suffices; mod 2^128, h - p = h + 5. */
    .p2align 2
    .global m0c_poly1305_finish
    .type m0c_poly1305_finish, %function
    .thumb_func
m0c_poly1305_finish:
.Lm0c_poly1305_finish:
    push {r4-r7, lr}
    movs r7, r0
    mov  r12, r1
    movs r6, #0
    /* carry out of bit 130 of h + 5 */
    ldr  r0, [r7, #P_H0]
    adds r0, #5
    ldr  r0, [r7, #P_H1]
    adcs r0, r6
    ldr  r0, [r7, #P_H2]
    adcs r0, r6
    ldr  r0, [r7, #P_H3]
    adcs r0, r6
    ldr  r0, [r7, #P_H4]
    adcs r0, r6
    lsrs r0, r0, #2                 /* 1 if h >= p, else 0 */
    rsbs r0, r0, #0                 /* mask */
    movs r1, #5
    ands r1, r0
    /* (h + 5 [h >= p]) mod 2^128 */
    ldr  r2, [r7, #P_H0]
    adds r2, r1
    ldr  r3, [r7, #P_H1]
    adcs r3, r6
    ldr  r4, [r7, #P_H2]
    adcs r4, r6
    ldr  r5, [r7, #P_H3]
    adcs r5, r6
    /* + s */
    ldr  r0, [r7, #P_PAD+0]
    adds r2, r0
    ldr  r0, [r7, #P_PAD+4]
    adcs r3, r0
    ldr  r0, [r7, #P_PAD+8]
    adcs r4, r0
    ldr  r0, [r7, #P_PAD+12]
    adcs r5, r0
    mov  r1, r12
    STLE r2, r1, 0
    STLE r3, r1, 4
    STLE r4, r1, 8
    STLE r5, r1, 12
    movs r0, #0
    movs r1, #0
    movs r2, #0
    movs r3, #0
    mov  r12, r0
    pop  {r4-r7, pc}
    .size m0c_poly1305_finish, . - m0c_poly1305_finish

/*
 * AEAD frame, offsets from sp after the prologue.
 *   int f(uint8_t *out, uint8_t tag[16], const uint8_t *in, size_t len,
 *         const uint8_t *aad, size_t aad_len, const uint8_t key[32],
 *         const uint8_t nonce[12])
 */
#define OA_NONCE    0               /* outgoing stack arguments of m0c_chacha20_xor */
#define OA_CTR      4
#define CTX         8               /* Poly1305 context, 64 bytes */
#define BLK         72              /* 32 bytes: one-time key, padding, lengths, tag */
#define S_OUT       104
#define S_TAG       108
#define S_IN        112
#define S_LEN       116
#define AFRAME      124             /* 20 saved + 124 = 144: sp stays 8-byte aligned */
#define ASAVED      20
#define A_AAD       (AFRAME + ASAVED + 0)
#define A_AADLEN    (AFRAME + ASAVED + 4)
#define A_KEY       (AFRAME + ASAVED + 8)
#define A_NONCE     (AFRAME + ASAVED + 12)

/* One-time key = first 32 bytes of block 0. Generate the full aligned block
 * in the not-yet-initialised CTX so ChaCha20 can use its fused word output path.
 * Copy the first half to BLK before init overwrites CTX; no extra stack needed. */
.macro AEAD_SETUP
    movs r0, #0
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    str  r0, [sp, #CTX+4*\i]
    .endr
    str  r0, [sp, #OA_CTR]
    ldr  r0, [sp, #A_NONCE]
    str  r0, [sp, #OA_NONCE]
    add  r0, sp, #CTX
    movs r1, r0
    movs r2, #64
    ldr  r3, [sp, #A_KEY]
    bl   .Lm0c_chacha20_xor           /* counter 0, 64 bytes: cannot be rejected */
    add  r0, sp, #CTX
    add  r1, sp, #BLK
    .rept 2
    ldmia r0!, {r2-r5}
    stmia r1!, {r2-r5}
    .endr
    add  r0, sp, #CTX
    add  r1, sp, #BLK
    bl   .Lm0c_poly1305_init
.endm

/* MAC r4[0..r5) zero-padded to a multiple of 16 bytes. Clobbers r0-r6. */
.macro MAC_PADDED
    lsrs r2, r5, #4
    beq  1f
    add  r0, sp, #CTX
    movs r1, r4
    movs r3, #1
    bl   .Lm0c_poly1305_blocks
1:  movs r6, #15
    ands r6, r5
    beq  3f
    lsrs r0, r5, #4
    lsls r0, r0, #4
    adds r4, r0                     /* start of the final partial block */
    movs r0, #0
    str  r0, [sp, #BLK+0]
    str  r0, [sp, #BLK+4]
    str  r0, [sp, #BLK+8]
    str  r0, [sp, #BLK+12]
    add  r1, sp, #BLK
    movs r2, #0
2:  ldrb r0, [r4, r2]
    strb r0, [r1, r2]
    adds r2, #1
    cmp  r2, r6
    bne  2b
    add  r0, sp, #CTX
    movs r2, #1
    movs r3, #1
    bl   .Lm0c_poly1305_blocks
3:
.endm

/* MAC le64(aad_len) || le64(len). */
.macro MAC_LENGTHS
    ldr  r0, [sp, #A_AADLEN]
    str  r0, [sp, #BLK+0]
    ldr  r0, [sp, #S_LEN]
    str  r0, [sp, #BLK+8]
    movs r0, #0
    str  r0, [sp, #BLK+4]
    str  r0, [sp, #BLK+12]
    add  r0, sp, #CTX
    add  r1, sp, #BLK
    movs r2, #1
    movs r3, #1
    bl   .Lm0c_poly1305_blocks
.endm

/* Zero CTX and BLK (24 words). Clobbers r0-r2. */
.macro CLEAR_FRAME
    add  r1, sp, #CTX
    movs r2, #24
    movs r0, #0
4:  str  r0, [r1]
    adds r1, #4
    subs r2, #1
    bne  4b
.endm

.macro SAVE_ARGS
    str  r0, [sp, #S_OUT]
    str  r1, [sp, #S_TAG]
    str  r2, [sp, #S_IN]
    str  r3, [sp, #S_LEN]
.endm

/* out = ChaCha20(key, nonce, counter 1..) XOR in. len < 2^32 needs at most 2^26
 * blocks, so counter 1 never overflows and the call cannot be rejected. */
.macro CRYPT
    movs r0, #1
    str  r0, [sp, #OA_CTR]
    ldr  r0, [sp, #S_OUT]
    ldr  r1, [sp, #S_IN]
    ldr  r2, [sp, #S_LEN]
    ldr  r3, [sp, #A_KEY]
    bl   .Lm0c_chacha20_xor
.endm

    .p2align 2
    .global m0c_chacha20poly1305_encrypt
    .type m0c_chacha20poly1305_encrypt, %function
    .thumb_func
m0c_chacha20poly1305_encrypt:
    push {r4-r7, lr}
    sub  sp, #AFRAME
    SAVE_ARGS
    AEAD_SETUP
    CRYPT
    ldr  r4, [sp, #A_AAD]
    ldr  r5, [sp, #A_AADLEN]
    MAC_PADDED
    ldr  r4, [sp, #S_OUT]           /* MAC the ciphertext as written */
    ldr  r5, [sp, #S_LEN]
    MAC_PADDED
    MAC_LENGTHS
    add  r0, sp, #CTX
    ldr  r1, [sp, #S_TAG]
    bl   .Lm0c_poly1305_finish
    CLEAR_FRAME
    movs r0, #0                     /* M0C_OK */
    movs r1, #0
    movs r2, #0
    movs r3, #0
    add  sp, #AFRAME
    pop  {r4-r7, pc}
    .size m0c_chacha20poly1305_encrypt, . - m0c_chacha20poly1305_encrypt

    .p2align 2
    .global m0c_chacha20poly1305_decrypt
    .type m0c_chacha20poly1305_decrypt, %function
    .thumb_func
m0c_chacha20poly1305_decrypt:
    push {r4-r7, lr}
    sub  sp, #AFRAME
    SAVE_ARGS
    AEAD_SETUP
    ldr  r4, [sp, #A_AAD]
    ldr  r5, [sp, #A_AADLEN]
    MAC_PADDED
    ldr  r4, [sp, #S_IN]            /* MAC the received ciphertext */
    ldr  r5, [sp, #S_LEN]
    MAC_PADDED
    MAC_LENGTHS
    add  r0, sp, #CTX
    add  r1, sp, #BLK
    bl   .Lm0c_poly1305_finish        /* expected tag -> BLK[0..15] */
    /* Constant-time compare: OR of all byte differences. */
    ldr  r1, [sp, #S_TAG]
    add  r2, sp, #BLK
    movs r3, #0
    movs r4, #0
5:  ldrb r0, [r1, r4]
    ldrb r5, [r2, r4]
    eors r0, r5
    orrs r3, r0
    adds r4, #1
    cmp  r4, #16
    bne  5b
    movs r5, #0                     /* expected_tag[15]: do not leave it for CRYPT to save */
    movs r0, #0                     /* last byte difference */
    cmp  r3, #0                     /* the verdict is public */
    bne  .Ldec_reject
    CRYPT                           /* only an authenticated ciphertext is decrypted */
    movs r4, #0                     /* M0C_OK */
    b    .Ldec_out
.Ldec_reject:
    movs r4, #2
    rsbs r4, r4, #0                 /* M0C_ERR_AUTH = -2; out is not written */
.Ldec_out:
    CLEAR_FRAME
    movs r0, r4
    movs r1, #0
    movs r2, #0
    movs r3, #0
    add  sp, #AFRAME
    pop  {r4-r7, pc}
    .size m0c_chacha20poly1305_decrypt, . - m0c_chacha20poly1305_decrypt
