
MEMORY {
    FLASH (rx) : ORIGIN = 0, LENGTH = 256K
    RAM (rw) : ORIGIN = 0x20200000, LENGTH = 32K
}

SECTIONS {
    .text : { *(.text*) *(.rodata*) } > FLASH
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
