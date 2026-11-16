MEMORY {
    FLASH (rx) : ORIGIN = 0, LENGTH = 256K
    /* armv6m.py places the call's buffers below 0x20205200 and the stack at the top of
     * RAM; static data (Mbed TLS's PSA state and heap only) sits between them. */
    STATIC (rw) : ORIGIN = 0x20205200, LENGTH = 0x2000
}

SECTIONS {
    .text : { *(.text*) *(.rodata*) } > FLASH
    .data : { *(.data*) } > STATIC
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > STATIC
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
