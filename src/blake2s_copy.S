/* SPDX-License-Identifier: MIT
 * Internal void m0c_blake2s_copy(uint8_t *dst,const uint8_t *src,size_t n), the BLAKE2s
 * buffering copy. A local symbol of the release unit, called only by m0c_blake2s_update.
 * Disjoint accessible n-byte ranges, 1<=n<=64 (the only caller passes n>=8), any
 * byte alignment. Exactly n bytes written, reads stay within the source range.
 * AAPCS: preserves r4-r11/SP, clobbers r0-r3/APSR; 20-byte stack frame (r4-r7, lr),
 * disjoint from buffers; entry SP is 8-byte aligned. Returns with POP {pc}. Ordinary RAM, no
 * faults/concurrent writers assumed.
 * Branches/addresses depend on pointers and length, never copied byte values.
 * Word loads are used only when source and destination are both 4-byte aligned
 * and wholly inside the requested ranges. A source that is unaligned once the
 * destination is aligned is read at fixed offsets within each 4-byte group, with
 * byte/halfword/byte loads (odd address, .Lb2c_pack_byte) or two halfword loads
 * (address 2 mod 4, .Lb2c_pack_half), packed into one aligned word store. No address is rounded down.
 * No calls. Clearing: the helper may return copied message data in r0-r3 (r3 holds the
 * last copied word or byte); it clears nothing, its caller (m0c_blake2s_update) zeroes
 * r0-r3 at exit. Its 20-byte frame holds only saved registers. Lean: Blake2sCopy*.
 */
.syntax unified
.thumb
#ifdef M0C_UNIT
    .text
#else
    .section .text.m0c_blake2s_copy,"ax",%progbits
#endif
.p2align 2
.type m0c_blake2s_copy,%function
.thumb_func
m0c_blake2s_copy:
.Lm0c_blake2s_copy:             /* local alias for in-unit calls */
    push {r4-r7,lr}
    movs r4, #3
.Lb2c_align_dst:
    tst r0, r4
    beq .Lb2c_select
    ldrb r3, [r1]
    strb r3, [r0]
    adds r1, #1
    adds r0, #1
    subs r2, #1
    beq .Lb2c_done
    b .Lb2c_align_dst
.Lb2c_select:
    cmp r2, #4
    blo .Lb2c_bytes
    tst r1, r4
    bne .Lb2c_unaligned
.Lb2c_words16:
    cmp r2, #16
    blo .Lb2c_words4
    ldm r1!, {r3-r6}
    stm r0!, {r3-r6}
    subs r2, #16
    b .Lb2c_words16
.Lb2c_words4:
    cmp r2, #4
    blo .Lb2c_bytes
    ldr r3, [r1]
    str r3, [r0]
    adds r1, #4
    adds r0, #4
    subs r2, #4
    b .Lb2c_words4

/* Destination aligned, source not, at least one word: r5 = whole words,
 * r2 = tail bytes. Each word is read only from its own four source bytes. */
.Lb2c_unaligned:
    lsrs r5, r2, #2
    ands r2, r4
    movs r3, #1
    tst r1, r3
    beq .Lb2c_pack_half
.Lb2c_pack_byte:                    /* source address odd: byte, halfword, byte */
    ldrb r3, [r1]
    adds r7, r1, #1             /* source + 1 is halfword aligned */
    ldrh r6, [r7]
    lsls r6, r6, #8
    orrs r3, r6
    ldrb r6, [r1, #3]
    lsls r6, r6, #24
    orrs r3, r6
    stm r0!, {r3}
    adds r1, #4
    subs r5, #1
    bne .Lb2c_pack_byte
    b .Lb2c_bytes
.Lb2c_pack_half:                    /* source address 2 mod 4: two halfword loads */
    ldrh r3, [r1]
    ldrh r6, [r1, #2]
    lsls r6, r6, #16
    orrs r3, r6
    stm r0!, {r3}
    adds r1, #4
    subs r5, #1
    bne .Lb2c_pack_half
.Lb2c_bytes:
    cmp r2, #0
    beq .Lb2c_done
.Lb2c_byte_loop:
    ldrb r3, [r1]
    strb r3, [r0]
    adds r1, #1
    adds r0, #1
    subs r2, #1
    bne .Lb2c_byte_loop
.Lb2c_done:
    pop {r4-r7,pc}
.size m0c_blake2s_copy,.-m0c_blake2s_copy
