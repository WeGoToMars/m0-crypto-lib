/*
 * m0-crypto: ChaCha20 (RFC 8439 section 2.4) for ARMv6-M, register-resident round schedule.
 * SPDX-License-Identifier: MIT
 *
 * int m0c_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
 *                      const uint8_t key[32], const uint8_t nonce[12],
 *                      uint32_t counter);
 *
 * Contract: include/m0crypto/chacha20.h. AAPCS: r0-r3 = out, in, len, key;
 * [sp] = nonce, [sp+4] = counter. r4-r11 are saved and restored.
 *
 * Validation depends only on counter and len. Under the proved ARMv6-M model
 * (see proofs/), executed instructions and memory addresses depend only on the
 * pointer arguments, len, counter, the stack pointer, and the code and return
 * addresses; never on key, nonce or payload bytes. Peak stack use: 36 bytes
 * saved registers + 140 bytes frame.
 */
    .syntax unified
    .thumb

#include "chacha20_round.inc"

/* Frame layout, offsets from sp after the prologue. */
#define X           0       /* working state / keystream x[0..15] */
#define J           64      /* input state j[0..15] */
#define LEN         128     /* bytes still to process */
#define OUTP        132     /* each slot has one meaning for the whole call */
#define INP         136
#define FRAME       140     /* FRAME + SAVED keeps sp 8-byte aligned */
#define SAVED       36      /* r4-r11, lr */
#define ARG_NONCE   (FRAME + SAVED)
#define ARG_COUNTER (FRAME + SAVED + 4)

/* r0 = little-endian word at base+off (any alignment); clobbers r1. */
.macro LOAD_LE32 base, off
    ldrb r0, [\base, #\off]
    ldrb r1, [\base, #\off+1]
    lsls r1, r1, #8
    orrs r0, r1
    ldrb r1, [\base, #\off+2]
    lsls r1, r1, #16
    orrs r0, r1
    ldrb r1, [\base, #\off+3]
    lsls r1, r1, #24
    orrs r0, r1
.endm

    .text
    .p2align 2
    .global m0c_chacha20_xor
    .type m0c_chacha20_xor, %function
    .thumb_func
m0c_chacha20_xor:
.Lm0c_chacha20_xor:                 /* local alias: in-unit calls need no relocation */
    push {r4-r7, lr}
    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11
    push {r4-r7}
    sub  sp, #FRAME

    /* len == 0: nothing to do (the frame holds no secrets yet). */
    cmp  r2, #0
    bne  1f
    b    .Lreturn_ok
1:
    /* Reject a counter overflow before writing anything:
     * counter + (len - 1) / 64 must not carry out of 32 bits. */
    ldr  r4, [sp, #ARG_COUNTER]
    subs r5, r2, #1
    lsrs r5, r5, #6
    adds r5, r4, r5
    bcc  2f
    b    .Lerr_counter
2:
    str  r0, [sp, #OUTP]
    str  r1, [sp, #INP]
    str  r2, [sp, #LEN]

    /* j[0..3] = "expand 32-byte k" */
    ldr  r0, =0x61707865
    str  r0, [sp, #J+0]
    ldr  r0, =0x3320646e
    str  r0, [sp, #J+4]
    ldr  r0, =0x79622d32
    str  r0, [sp, #J+8]
    ldr  r0, =0x6b206574
    str  r0, [sp, #J+12]
    b    4f
    .ltorg                  /* literal pool for the constants (never executed) */
4:
    /* j[4..11] = key */
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7
    LOAD_LE32 r3, 4*\i
    str  r0, [sp, #J+16+4*\i]
    .endr
    /* j[12] = counter */
    str  r4, [sp, #J+48]
    /* j[13..15] = nonce */
    ldr  r3, [sp, #ARG_NONCE]
    .irp i, 0, 1, 2
    LOAD_LE32 r3, 4*\i
    str  r0, [sp, #J+52+4*\i]
    .endr

.Lblock:
    /* Copy the a/b/c rows in groups; keep the d row off the stack. */
    add  r4, sp, #J
    add  r5, sp, #X
    .rept 3
    ldmia r4!, {r0-r3}
    stmia r5!, {r0-r3}
    .endr
    ldmia r4!, {r0-r3}
    mov  r8, r0
    mov  r9, r1
    mov  r10, r2
    mov  r11, r3
    ldr  r0, [sp, #X+8]      /* a = x[2] at the double-round boundary */
    movs r4, #16
    movs r5, #20
    movs r6, #24
    movs r7, #25
    movs r1, #10
    mov  r12, r1
.Lround:
    DOUBLE_ROUND_REG_D
    mov  r1, r12
    subs r1, #1
    mov  r12, r1
    beq  .Lrounds_done
    b    .Lround
.Lrounds_done:
    /* Recover the public pointers and length for the output path. */
    ldr  r2, [sp, #INP]
    ldr  r3, [sp, #OUTP]
    ldr  r4, [sp, #LEN]
    /* Materialise the register-resident state for feed-forward. */
    str  r0, [sp, #X+8]
    mov  r0, r8
    str  r0, [sp, #X+48]
    mov  r0, r9
    str  r0, [sp, #X+52]
    mov  r0, r10
    str  r0, [sp, #X+56]
    mov  r0, r11
    str  r0, [sp, #X+60]

    cmp  r4, #64
    blo  .Lbytes            /* final partial block: r4 = byte count */
    movs r4, #64
    movs r0, r2
    orrs r0, r3
    lsls r0, r0, #30
    bne  .Lbytes            /* unaligned in or out: byte path for 64 bytes */
    /* Full block, in and out both word-aligned. */
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ldr  r0, [sp, #X+4*\i]
    ldr  r1, [sp, #J+4*\i]
    adds r0, r0, r1
    ldr  r1, [r2, #4*\i]
    eors r0, r1
    str  r0, [r3, #4*\i]
    .endr
    b    .Lnext
.Lbytes:
    /* Byte path also handles partial blocks; form the keystream on stack. */
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ldr  r0, [sp, #X+4*\i]
    ldr  r1, [sp, #J+4*\i]
    adds r0, r0, r1
    str  r0, [sp, #X+4*\i]
    .endr
    /* out[i] = in[i] ^ keystream[i] for i < r4 (1 <= r4 <= 64). */
    add  r5, sp, #X
    movs r0, #0
3:
    ldrb r1, [r2, r0]
    ldrb r6, [r5, r0]
    eors r1, r6
    strb r1, [r3, r0]
    adds r0, #1
    cmp  r0, r4
    blo  3b
.Lnext:
    ldr  r4, [sp, #LEN]
    cmp  r4, #64
    bls  .Ldone
    subs r4, #64
    str  r4, [sp, #LEN]
    adds r2, #64
    str  r2, [sp, #INP]
    adds r3, #64
    str  r3, [sp, #OUTP]
    ldr  r0, [sp, #J+48]
    adds r0, #1
    str  r0, [sp, #J+48]
    b    .Lblock

.Ldone:
    /* Clear all 35 frame words in seven fixed five-word batches. */
    movs r0, #0
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r4, #0
    add  r5, sp, #0
    .rept 7
    stmia r5!, {r0-r4}
    .endr
    mov  r12, r0
.Lclear_end:
.Lreturn_ok:
    movs r0, #0
.Lreturn:
    add  sp, #FRAME
    pop  {r4-r7}
    mov  r8, r4
    mov  r9, r5
    mov  r10, r6
    mov  r11, r7
    pop  {r4-r7, pc}

.Lerr_counter:
    movs r0, #0
    mvns r0, r0             /* M0C_ERR_COUNTER = -1 */
    b    .Lreturn

    .size m0c_chacha20_xor, . - m0c_chacha20_xor

/* Keep following kernels at their existing link offsets: flash fetch costs depend
 * on placement on the reference chip. The padding is never executed. */
.Lchacha20_code_end:
    .p2align 2, 0
    .space 2 * (FRAME / 4 + 5) - (.Lclear_end - .Ldone) - (. - .Lchacha20_code_end), 0
