/*
 * Placement "sram": the released library object (m0crypto_*.o, its .text only) is
 * copied to SRAM at reset (as part of .data) and executes from there. The harness,
 * timing code, vector table and test tables stay in flash.
 */
ENTRY(reset_handler)
SECTIONS
{
    .text : {
        KEEP(*(.vectors))
        *(EXCLUDE_FILE(*m0crypto_*.o) .text .text.*)
        *(EXCLUDE_FILE(*m0crypto_*.o) .rodata .rodata.*)
    } > FLASH
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
    . = ALIGN(4);
    _etext = .;
    .data : AT(_etext) {
        _sdata = .;
        _sramcode = .;
        *m0crypto_*.o(.text .text.* .rodata .rodata.*)
        . = ALIGN(4);
        _eramcode = .;
        *(.data .data.*)
        . = ALIGN(4);
        _edata = .;
    } > RAM
    .bss (NOLOAD) : { _sbss = .; *(.bss .bss.* COMMON) . = ALIGN(4); _ebss = .; } > RAM
    _estack = ORIGIN(RAM) + LENGTH(RAM);
    ASSERT(_ebss + 4096 <= _estack, "less than 4 KiB left for the stack")
}
