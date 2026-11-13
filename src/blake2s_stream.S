/* SPDX-License-Identifier: MIT
 * Unkeyed BLAKE2s-256 streaming (RFC 7693) over m0c_blake2s_compress and
 * m0c_blake2s_copy: m0c_blake2s_init, m0c_blake2s_update, m0c_blake2s_final.
 * Contract and context layout: blake2s_internal.h (its _Static_asserts pin the
 * CTX_* offsets below). Assemble only inside a unit that defines M0C_UNIT, after
 * blake2s_compress.S and blake2s_copy.S: calls target their local labels, so the
 * unit has no relocations.
 *
 * Proof-oriented shape:
 * - Public control state (used, p, n) lives in callee-saved r5-r7 for a whole call.
 *   ctx->used is loaded once, at entry, before any store, and stored once at exit.
 *   No value that steers a branch or an address is reloaded after a store through
 *   h, buf or out.
 * - count is loaded, incremented and stored around each compression; it is data
 *   for compress (t), never a branch condition or an address.
 * - Calls are one level deep (compress and copy are leaves), and each call site
 *   passes f0 in the caller's [sp, #0] slot.
 * - Branches depend only on n, used and the low two bits of p and out.
 * - Instruction encodings: only those of the ChaCha20-Poly1305 release unit (no ADR,
 *   REV, BX); IV words are PC-relative literals.
 * Frames: init 4 bytes; update and final 24 bytes plus the callee's frame
 * (compress 136 including its 36 saved bytes, copy 20).
 * Clearing: compress clears its own 100 local bytes and returns r0-r3 and r12 zero.
 * update and final zero r0-r3 at their single exit, so both return with r0-r3 = 0 on
 * every path (r4-r7 are restored from the stack; r12 is zero after a compression,
 * otherwise untouched). The copy helper may return copied data in r3 (and the inline
 * byte loop leaves a byte there); update's exit clears it. The frames of update, final
 * and copy hold only saved registers and public values. The context (h, buf, count,
 * used) is caller memory and is not cleared; final consumes it.
 */
#ifndef M0C_UNIT
#error "assemble src/m0crypto_blake2s.S (one relocation-free unit), not this file"
#endif
.syntax unified
.thumb

#define CTX_H        0          /* uint32_t h[8] */
#define CTX_COUNT    32         /* uint64_t count: bytes compressed so far, pending excluded (RFC t) */
#define CTX_BUF      40         /* uint8_t buf[64], word aligned */
#define CTX_USED     104        /* size_t used: bytes pending in buf, 0..64 */
#define BLOCK_BYTES  64
#define DIGEST_BYTES 32
#define COPY_MIN     8          /* shorter pieces use the inline byte loop */
#define F0_SLOT      0          /* [sp, #0]: compress's stacked f0 argument */
#define FRAME_PAD    4          /* push of 5 words + 4 keeps SP 8-byte aligned */

.if CTX_H != 0 || CTX_COUNT != CTX_H + 32
.error "init stores h then count with consecutive STMs"
.endif

/* Nonfinal block at r1 (ctx in r4): count += 64; compress(h, r1, count, f0 = 0).
 * Clobbers r0-r3, r12, LR and APSR; r4-r11 preserved by compress. */
.macro NONFINAL_BLOCK
    ldr r2, [r4, #CTX_COUNT]
    ldr r3, [r4, #CTX_COUNT+4]
    movs r0, #0
    adds r2, #BLOCK_BYTES
    adcs r3, r0
    str r2, [r4, #CTX_COUNT]
    str r3, [r4, #CTX_COUNT+4]
    str r0, [sp, #F0_SLOT]
    adds r0, r4, #CTX_H
    bl .Lm0c_blake2s_compress
.endm

/* void m0c_blake2s_init(m0c_blake2s_ctx *c): h = IV ^ param, count = 0, used = 0. */
.p2align 2
.global m0c_blake2s_init
.type m0c_blake2s_init,%function
.thumb_func
m0c_blake2s_init:
.Lm0c_blake2s_init:
    push {lr}
    ldr r1, .Lb2i_h0
    ldr r2, .Lb2i_h1
    ldr r3, .Lb2i_h2
    stm r0!, {r1-r3}            /* h0..h2 */
    ldr r1, .Lb2i_h3
    ldr r2, .Lb2i_h4
    ldr r3, .Lb2i_h5
    stm r0!, {r1-r3}            /* h3..h5 */
    ldr r1, .Lb2i_h6
    ldr r2, .Lb2i_h7
    movs r3, #0
    stm r0!, {r1-r3}            /* h6, h7, count low word; r0 = c + CTX_COUNT + 4 */
    str r3, [r0, #0]            /* count high word */
    str r3, [r0, #CTX_USED - CTX_COUNT - 4]
    pop {pc}
.p2align 2
.Lb2i_h0: .word 0x6a09e667 ^ 0x01010020 /* IV0 ^ (digest 32, key 0, fanout 1, depth 1) */
.Lb2i_h1: .word 0xbb67ae85
.Lb2i_h2: .word 0x3c6ef372
.Lb2i_h3: .word 0xa54ff53a
.Lb2i_h4: .word 0x510e527f
.Lb2i_h5: .word 0x9b05688c
.Lb2i_h6: .word 0x1f83d9ab
.Lb2i_h7: .word 0x5be0cd19
.size m0c_blake2s_init,.-m0c_blake2s_init

/* void m0c_blake2s_update(m0c_blake2s_ctx *c, const uint8_t *p, size_t n).
 * r4 = c, r5 = p, r6 = n (bytes left), r7 = used. The last block stays pending
 * until final, so a full buffer is compressed only when more input follows, and
 * direct blocks from p only while more than 64 bytes remain. */
.p2align 2
.global m0c_blake2s_update
.type m0c_blake2s_update,%function
.thumb_func
m0c_blake2s_update:
.Lm0c_blake2s_update:
    push {r4-r7,lr}
    sub sp, #FRAME_PAD
    movs r4, r0
    movs r5, r1
    movs r6, r2
    ldr r7, [r4, #CTX_USED]     /* the only load of used: entry, before any store */
    cmp r6, #0
    beq .Lb2u_out
.Lb2u_loop:                     /* n > 0, used <= 64 */
    cmp r7, #BLOCK_BYTES
    bne .Lb2u_direct_test
    movs r1, #CTX_BUF
    adds r1, r1, r4
    NONFINAL_BLOCK              /* full buffer, more input follows */
    movs r7, #0
.Lb2u_direct_test:              /* direct blocks need used = 0, n > 64, p aligned */
    cmp r7, #0
    bne .Lb2u_buffer
    cmp r6, #BLOCK_BYTES
    bls .Lb2u_buffer
    lsls r0, r5, #30
    bne .Lb2u_buffer
.Lb2u_direct:
    movs r1, r5
    NONFINAL_BLOCK
    adds r5, #BLOCK_BYTES
    subs r6, #BLOCK_BYTES
    cmp r6, #BLOCK_BYTES
    bhi .Lb2u_direct
.Lb2u_buffer:                   /* n > 0, used < 64: take = min(64 - used, n) */
    movs r2, #BLOCK_BYTES
    subs r2, r2, r7
    cmp r2, r6
    bls .Lb2u_have_take
    movs r2, r6
.Lb2u_have_take:
    movs r0, #CTX_BUF
    adds r0, r0, r4
    adds r0, r0, r7             /* dst = buf + used */
    movs r1, r5                 /* src = p */
    adds r7, r7, r2             /* advance the state before the copy */
    adds r5, r5, r2
    subs r6, r6, r2
    cmp r2, #COPY_MIN
    blo .Lb2u_bytes
    bl .Lm0c_blake2s_copy
    b .Lb2u_next
.Lb2u_bytes:                    /* 1 <= take < COPY_MIN */
    ldrb r3, [r1]
    strb r3, [r0]
    adds r1, #1
    adds r0, #1
    subs r2, #1
    bne .Lb2u_bytes
.Lb2u_next:
    cmp r6, #0
    bne .Lb2u_loop
.Lb2u_out:
    str r7, [r4, #CTX_USED]     /* the only store of used */
    movs r0, #0                 /* no message byte or digest word left in r0-r3 */
    movs r1, #0
    movs r2, #0
    movs r3, #0
    add sp, #FRAME_PAD
    pop {r4-r7,pc}
.size m0c_blake2s_update,.-m0c_blake2s_update

/* void m0c_blake2s_final(m0c_blake2s_ctx *c, uint8_t out[32]).
 * r4 = c, r5 = out, r6 = padding index (starts at used). Compresses the pending
 * block, zero padded, with t = count + used and f0 = 0xffffffff, then writes h
 * in little-endian order. ctx->count and ctx->used are left stale: final consumes
 * the context. */
.p2align 2
.global m0c_blake2s_final
.type m0c_blake2s_final,%function
.thumb_func
m0c_blake2s_final:
.Lm0c_blake2s_final:
    push {r4-r7,lr}
    sub sp, #FRAME_PAD
    movs r4, r0
    movs r5, r1
    ldr r6, [r4, #CTX_USED]     /* the only load of used: entry, before any store */
    ldr r2, [r4, #CTX_COUNT]
    ldr r3, [r4, #CTX_COUNT+4]
    movs r0, #0
    adds r2, r2, r6
    adcs r3, r0                 /* r3:r2 = t = count + used */
    movs r1, #CTX_BUF
    adds r1, r1, r4             /* r1 = buf, kept for compress */
.Lb2f_pad_bytes:                /* zero buf[used..] up to a word boundary */
    lsls r7, r6, #30
    beq .Lb2f_pad_words
    strb r0, [r1, r6]
    adds r6, #1
    b .Lb2f_pad_bytes
.Lb2f_pad_words:                /* then whole words up to 64 */
    cmp r6, #BLOCK_BYTES
    beq .Lb2f_compress
    str r0, [r1, r6]
    adds r6, #4
    b .Lb2f_pad_words
.Lb2f_compress:
    mvns r0, r0
    str r0, [sp, #F0_SLOT]      /* f0 = 0xffffffff */
    adds r0, r4, #CTX_H
    bl .Lm0c_blake2s_compress
    lsls r0, r5, #30            /* digest: word stores only for an aligned out */
    bne .Lb2f_out_bytes
    ldm r4!, {r0-r3}
    stm r5!, {r0-r3}
    ldm r4!, {r0-r3}
    stm r5!, {r0-r3}
    b .Lb2f_return
.Lb2f_out_bytes:
    movs r6, #0
.Lb2f_out_byte:
    ldrb r0, [r4, r6]
    strb r0, [r5, r6]
    adds r6, #1
    cmp r6, #DIGEST_BYTES
    bne .Lb2f_out_byte
.Lb2f_return:
    movs r0, #0                 /* no digest word or byte left in r0-r3 */
    movs r1, #0
    movs r2, #0
    movs r3, #0
    add sp, #FRAME_PAD
    pop {r4-r7,pc}
.size m0c_blake2s_final,.-m0c_blake2s_final

.purgem NONFINAL_BLOCK
#undef CTX_H
#undef CTX_COUNT
#undef CTX_BUF
#undef CTX_USED
#undef BLOCK_BYTES
#undef DIGEST_BYTES
#undef COPY_MIN
#undef F0_SLOT
#undef FRAME_PAD
