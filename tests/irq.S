/*
 * SysTick handler of the interrupt test images (tests/test_irq_*.c). Test image only.
 *
 * On every SysTick exception it passes its exception frame to irq_note (tests/irq.c), which
 * records where the exception landed and returns a pattern word. It then overwrites the
 * IRQ_CLOBBER bytes below the exception frame, that is below the interrupted SP minus the
 * 32 stacked bytes, with words that change on every exception, so that code that relied on
 * memory below its SP would see garbage. Last it clears the SysTick count and then a pending
 * SysTick, so the next exception comes SYST_RVR + 1 ticks after the count is cleared. The hardware
 * stacks r0-r3, r12, LR, PC and xPSR; the handler changes no other register.
 */
#define IRQ_CLOBBER 256
    .syntax unified
    .thumb
    .text
    .thumb_func
    .global systick_handler
systick_handler:
    mov  r0, sp                 /* exception frame */
    push {r0, lr}
    bl   irq_note               /* r0 = first pattern word */
    pop  {r1, r2}               /* r1 = exception frame, r2 = EXC_RETURN */
    ldr  r3, =(IRQ_CLOBBER / 4)
1:  subs r1, #4
    str  r0, [r1]
    adds r0, r0, r3
    rors r0, r3
    subs r3, #1
    bne  1b
    ldr  r0, =0xE000E018        /* SYST_CVR: any write clears the count */
    str  r0, [r0]
    ldr  r0, =0xE000ED04        /* ICSR: PENDSTCLR, after the count is cleared, so that */
    ldr  r1, =0x02000000        /* no wrap during the handler stays pending */
    str  r1, [r0]
    bx   r2
    .ltorg

/* uint32_t irq_probe(void): returns SYST_CVR, for irq_init's timing of a call. */
    .thumb_func
    .global irq_probe
irq_probe:
    ldr  r0, =0xE000E018
    ldr  r0, [r0]
    bx   lr
    .ltorg
