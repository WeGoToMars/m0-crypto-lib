/*
 * Minimal Cortex-M0 test startup with semihosting exit. Test image only.
 * With -DNO_SEMIHOST, semihost_write0 is a no-op and semihost_exit parks the core in
 * a loop (no BKPT), so an image can run without a debugger and leave results in RAM.
 * With -DUART_OUT (bench images behind a bootloader), interrupts are masked, SP and
 * VTOR are set from this image's vector table, and output/exit go to uart_write0 and
 * uart_exit (bench/firmware/bench_uart.c).
 */
    .syntax unified
    .thumb
    .section .vectors, "a"
vector_table:
    .word _estack
    .word reset_handler          /* .thumb_func symbols already carry the Thumb bit */
    .word fault_handler          /* NMI */
    .word fault_handler          /* HardFault */

    .text
    .thumb_func
    .global reset_handler
reset_handler:
#ifdef UART_OUT
    cpsid i                     /* a bootloader may leave interrupts configured */
    ldr  r0, =_estack
    mov  sp, r0
    ldr  r0, =0xE000ED08        /* SCB->VTOR */
    ldr  r1, =vector_table
    str  r1, [r0]
#endif
    /* copy .data, zero .bss */
    ldr  r0, =_sdata
    ldr  r1, =_edata
    ldr  r2, =_etext
1:  cmp  r0, r1
    bhs  2f
    ldr  r3, [r2]
    str  r3, [r0]
    adds r0, #4
    adds r2, #4
    b    1b
2:  ldr  r0, =_sbss
    ldr  r1, =_ebss
    movs r3, #0
3:  cmp  r0, r1
    bhs  4f
    str  r3, [r0]
    adds r0, #4
    b    3b
4:
#ifdef UART_OUT
    bl   uart_init
#endif
    bl   main
    bl   semihost_exit
5:  b    5b

    .thumb_func
fault_handler:
    movs r0, #99
    bl   semihost_exit
6:  b    6b

/* void semihost_write0(const char *s) */
    .thumb_func
    .global semihost_write0
semihost_write0:
#ifdef UART_OUT
    ldr  r3, =uart_write0    /* tail call; B range is only 2 KiB */
    bx   r3
#endif
#ifndef NO_SEMIHOST
    movs r1, r0
    movs r0, #0x04          /* SYS_WRITE0 */
    bkpt 0xab
#endif
    bx   lr

/* void semihost_exit(int code): SYS_EXIT_EXTENDED with ADP_Stopped_ApplicationExit */
    .thumb_func
    .global semihost_exit
semihost_exit:
#ifdef UART_OUT
    ldr  r3, =uart_exit
    bx   r3
#endif
#ifdef NO_SEMIHOST
    .global semihost_parked
semihost_parked:            /* halt here with a debugger; r0 = exit code (99 = fault) */
    b    semihost_parked
#endif
    sub  sp, #8
    ldr  r1, =0x20026
    str  r1, [sp]
    str  r0, [sp, #4]
    mov  r1, sp
    movs r0, #0x20
    bkpt 0xab
7:  b    7b
    .ltorg
