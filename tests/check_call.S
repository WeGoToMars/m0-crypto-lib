/*
 * int check_call(out, in, len, key, nonce, counter, uint32_t result[2])
 * Calls m0c_chacha20_xor with sentinel values in r4-r11, then reports in
 * result[0] a bitmask of callee-saved registers (bit n = r(n)) or SP that changed
 * (bit 13), in result[1] the peak stack bytes used below the call-site SP, and in
 * result[2] the number of nonzero words left in the callee's 140-byte frame
 * [SP-176, SP-36) after return (the region m0c_chacha20_xor must clear).
 * Test image only.
 */
    .syntax unified
    .thumb
    .text
    .thumb_func
    .global check_call
check_call:
    push {r4-r7, lr}
    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11
    push {r4-r7}                 /* 36 bytes saved; stack args at [sp, #36..44] */
    sub  sp, #12                 /* outgoing args; keeps 8-byte alignment (48 total) */
    ldr  r4, [sp, #48]           /* nonce */
    ldr  r5, [sp, #52]           /* counter */
    str  r4, [sp]
    str  r5, [sp, #4]
    /* paint 512 bytes below the call-site SP */
    mov  r4, sp
    movs r5, #128
    ldr  r6, =0xa5a5a5a5
1:  subs r4, #4
    str  r6, [r4]
    subs r5, #1
    bne  1b
    /* remember the call-site SP */
    ldr  r4, =saved_sp
    mov  r5, sp
    str  r5, [r4]
    /* sentinels */
    ldr  r4, =0x88888888
    mov  r8, r4
    ldr  r4, =0x99999999
    mov  r9, r4
    ldr  r4, =0xaaaaaaaa
    mov  r10, r4
    ldr  r4, =0xbbbbbbbb
    mov  r11, r4
    ldr  r4, =0x44444444
    ldr  r5, =0x55555555
    ldr  r6, =0x66666666
    ldr  r7, =0x77777777
    bl   m0c_chacha20_xor
    /* r0 = return value; build the changed-register mask in r1 */
    movs r1, #0
    ldr  r2, =0x44444444
    cmp  r4, r2
    beq  2f
    adds r1, #0x10
2:  ldr  r2, =0x55555555
    cmp  r5, r2
    beq  3f
    adds r1, #0x20
3:  ldr  r2, =0x66666666
    cmp  r6, r2
    beq  4f
    adds r1, #0x40
4:  ldr  r2, =0x77777777
    cmp  r7, r2
    beq  5f
    adds r1, #0x80
5:  mov  r3, r8
    ldr  r2, =0x88888888
    cmp  r3, r2
    beq  6f
    movs r2, #1
    lsls r2, r2, #8
    adds r1, r1, r2
6:  mov  r3, r9
    ldr  r2, =0x99999999
    cmp  r3, r2
    beq  7f
    movs r2, #1
    lsls r2, r2, #9
    adds r1, r1, r2
7:  mov  r3, r10
    ldr  r2, =0xaaaaaaaa
    cmp  r3, r2
    beq  8f
    movs r2, #1
    lsls r2, r2, #10
    adds r1, r1, r2
8:  mov  r3, r11
    ldr  r2, =0xbbbbbbbb
    cmp  r3, r2
    beq  9f
    movs r2, #1
    lsls r2, r2, #11
    adds r1, r1, r2
9:  ldr  r2, =saved_sp
    ldr  r2, [r2]
    mov  r3, sp
    cmp  r2, r3
    beq  10f
    movs r2, #1
    lsls r2, r2, #13
    adds r1, r1, r2
10: /* peak stack: lowest painted word that changed */
    mov  r2, sp
    movs r3, #128
    ldr  r6, =0xa5a5a5a5
    movs r5, #0                  /* deepest offset seen */
    movs r4, #0                  /* current offset */
11: adds r4, #4
    subs r2, #4
    ldr  r7, [r2]
    cmp  r7, r6
    beq  12f
    movs r5, r4
12: subs r3, #1
    bne  11b
    /* residue: nonzero words in the callee frame [sp-176, sp-36) */
    mov  r2, sp
    subs r2, #176
    movs r3, #35
    movs r6, #0
13: ldr  r7, [r2]
    cmp  r7, #0
    beq  14f
    adds r6, #1
14: adds r2, #4
    subs r3, #1
    bne  13b
    ldr  r2, [sp, #56]           /* result pointer */
    str  r1, [r2]
    str  r5, [r2, #4]
    str  r6, [r2, #8]
    add  sp, #12
    pop  {r4-r7}
    mov  r8, r4
    mov  r9, r5
    mov  r10, r6
    mov  r11, r7
    pop  {r4-r7, pc}
    .ltorg

    .bss
    .p2align 2
saved_sp:
    .space 4
