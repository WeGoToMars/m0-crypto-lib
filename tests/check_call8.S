/*
 * int check_call8(int (*fn)(...), const uint32_t args[8], uint32_t result[2])
 * Calls fn(args[0], ..., args[7]) (args[4..7] on the stack, AAPCS) with sentinel
 * values in r4-r11 and 512 painted bytes (0xa5) below the call-site SP. Returns fn's
 * return value. result[0] = bitmask of changed callee-saved registers (bit n = r(n))
 * or SP (bit 13); result[1] = peak stack bytes used below the call-site SP.
 * stack_snapshot[128] receives the 512 bytes below the call-site SP after return
 * (word i is at SP - 512 + 4 i), so the caller can check that frames were cleared.
 * cc8_volatile[5] receives r1, r2, r3, r12 and lr as fn left them on return, so the
 * caller can check documented register clearing. They are saved into this
 * function's own frame (above the call-site SP), so the snapshot is not disturbed.
 * Test image only.
 */
    .syntax unified
    .thumb
    .bss
    .p2align 2
    .global stack_snapshot
stack_snapshot:
    .space 512
cc8_sp:
    .space 4
cc8_fn:
    .space 4
    .global cc8_volatile
cc8_volatile:
    .space 20
    .text
    .thumb_func
    .global check_call8
check_call8:
    push {r4-r7, lr}
    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11
    push {r4-r7}                 /* 36 bytes saved */
    sub  sp, #28                 /* 16 B outgoing args, result ptr, 2 spare: 64 total */
    str  r2, [sp, #16]           /* result pointer */
    ldr  r4, =cc8_fn
    str  r0, [r4]
    ldr  r4, [r1, #16]
    str  r4, [sp, #0]
    ldr  r4, [r1, #20]
    str  r4, [sp, #4]
    ldr  r4, [r1, #24]
    str  r4, [sp, #8]
    ldr  r4, [r1, #28]
    str  r4, [sp, #12]
    /* paint 512 bytes below the call-site SP */
    mov  r4, sp
    movs r5, #128
    ldr  r6, =0xa5a5a5a5
1:  subs r4, #4
    str  r6, [r4]
    subs r5, #1
    bne  1b
    ldr  r4, =cc8_sp
    mov  r5, sp
    str  r5, [r4]
    /* register arguments, then sentinels */
    ldr  r0, [r1, #0]
    ldr  r2, [r1, #8]
    ldr  r3, [r1, #12]
    ldr  r1, [r1, #4]
    ldr  r4, =0x88888888
    mov  r8, r4
    ldr  r4, =0x99999999
    mov  r9, r4
    ldr  r4, =0xaaaaaaaa
    mov  r10, r4
    ldr  r4, =0xbbbbbbbb
    mov  r11, r4
    ldr  r4, =cc8_fn
    ldr  r4, [r4]
    mov  r12, r4
    ldr  r4, =0x44444444
    ldr  r5, =0x55555555
    ldr  r6, =0x66666666
    ldr  r7, =0x77777777
    blx  r12
    /* outgoing-argument slots are free now: keep fn's volatile registers there */
    str  r1, [sp, #0]
    str  r2, [sp, #4]
    str  r3, [sp, #8]
    mov  r1, r12
    str  r1, [sp, #12]
    mov  r1, lr
    str  r1, [sp, #20]
    /* r0 = return value (kept); changed-register mask in r1 */
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
9:  ldr  r2, =cc8_sp
    ldr  r2, [r2]
    mov  r3, sp
    cmp  r2, r3
    beq  10f
    movs r2, #1
    lsls r2, r2, #13
    adds r1, r1, r2
10: /* peak stack: deepest painted word that changed */
    mov  r2, sp
    movs r3, #128
    ldr  r6, =0xa5a5a5a5
    movs r5, #0
    movs r4, #0
11: adds r4, #4
    subs r2, #4
    ldr  r7, [r2]
    cmp  r7, r6
    beq  12f
    movs r5, r4
12: subs r3, #1
    bne  11b
    /* snapshot [sp-512, sp) */
    mov  r2, sp
    subs r2, #255
    subs r2, #255
    subs r2, #2
    ldr  r3, =stack_snapshot
    movs r6, #128
13: ldr  r7, [r2]
    str  r7, [r3]
    adds r2, #4
    adds r3, #4
    subs r6, #1
    bne  13b
    ldr  r2, [sp, #16]
    str  r1, [r2]
    str  r5, [r2, #4]
    ldr  r3, =cc8_volatile
    ldr  r2, [sp, #0]
    str  r2, [r3, #0]
    ldr  r2, [sp, #4]
    str  r2, [r3, #4]
    ldr  r2, [sp, #8]
    str  r2, [r3, #8]
    ldr  r2, [sp, #12]
    str  r2, [r3, #12]
    ldr  r2, [sp, #20]
    str  r2, [r3, #16]
    add  sp, #28
    pop  {r4-r7}
    mov  r8, r4
    mov  r9, r5
    mov  r10, r6
    mov  r11, r7
    pop  {r4-r7, pc}
    .ltorg
