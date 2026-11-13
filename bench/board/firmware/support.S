/*
 * Board benchmark helpers (image only, not library code). Same method as the dev repo's
 * bench_support.S (SysTick, CLKSOURCE = processor clock, restarted from the top before
 * each measurement), generalised to a call with three register arguments so that the
 * released library entry points are timed directly, with no C wrapper in the interval:
 *
 * uint32_t time_call3(void *fn, a, b, c)
 *   Returns SysTick ticks elapsed across `blx fn` with r0=a, r1=b, r2=c. The interval
 *   starts after the first CVR read that follows a reload and ends at the CVR read after
 *   the return; the argument moves and the `blx` are inside it. The fixed cost is
 *   measured by timing bench_noop (`bx lr`) with the same arguments; the driver
 *   subtracts it. A wrap (COUNTFLAG) returns 0xFFFFFFFF.
 *
 * uint32_t stack_call3(void *fn, a, b, c)
 *   Paints PAINT bytes below the call-site SP, calls fn(a, b, c) and returns the offset
 *   in bytes of the deepest changed word below the call-site SP (0 if none changed).
 *   The call-site SP is the callee's entry SP, so for a library entry point this is the
 *   bytes the call uses below its entry SP, at 4-byte granularity.
 */
    .syntax unified
    .thumb

#define SYST_CVR 0xE000E018
#define PAINT    2048

    .text
    .p2align 2
    .global time_call3
    .type time_call3, %function
    .thumb_func
time_call3:
    push {r4-r7, lr}
    mov  r6, r0
    mov  r7, r1
    mov  r4, r2
    mov  r5, r3
    ldr  r0, =SYST_CVR
    str  r0, [r0]                /* any write: CVR = 0, COUNTFLAG cleared, reload next tick */
1:  ldr  r1, [r0]                /* start, once reloaded from RVR */
    cmp  r1, #0
    beq  1b
    push {r1}
    mov  r0, r7
    mov  r1, r4
    mov  r2, r5
    blx  r6
    ldr  r3, =SYST_CVR
    ldr  r0, [r3]                /* end */
    pop  {r1}
    subs r0, r1, r0              /* down-counter: start - end */
    subs r3, #8                  /* SYST_CSR = SYST_CVR - 8 */
    ldr  r1, [r3]
    lsrs r1, r1, #17             /* COUNTFLAG (bit 16) -> C */
    bcc  2f
    movs r0, #0
    mvns r0, r0                  /* TIME_OVERFLOW */
2:  pop  {r4-r7, pc}
    .size time_call3, . - time_call3

    .global bench_noop
    .type bench_noop, %function
    .thumb_func
bench_noop:
    bx   lr
    .size bench_noop, . - bench_noop

    .global stack_call3
    .type stack_call3, %function
    .thumb_func
stack_call3:
    push {r4-r7, lr}
    sub  sp, #12                 /* 32 bytes in all: 8-byte alignment at the call */
    str  r1, [sp]
    str  r2, [sp, #4]
    str  r3, [sp, #8]
    mov  r6, r0
    mov  r4, sp
    ldr  r5, =PAINT/4
    ldr  r2, =0xa5a5a5a5
1:  subs r4, #4
    str  r2, [r4]
    subs r5, #1
    bne  1b
    ldr  r0, [sp]
    ldr  r1, [sp, #4]
    ldr  r2, [sp, #8]
    blx  r6
    mov  r2, sp
    ldr  r3, =PAINT/4
    ldr  r6, =0xa5a5a5a5
    movs r5, #0                  /* deepest offset seen */
    movs r4, #0                  /* current offset */
2:  adds r4, #4
    subs r2, #4
    ldr  r7, [r2]
    cmp  r7, r6
    beq  3f
    movs r5, r4
3:  subs r3, #1
    bne  2b
    movs r0, r5
    add  sp, #12
    pop  {r4-r7, pc}
    .size stack_call3, . - stack_call3
    .ltorg
