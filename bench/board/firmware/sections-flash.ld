/* Placement "flash": all code and constants execute/read from flash. */
ENTRY(reset_handler)
SECTIONS
{
    .text : { KEEP(*(.vectors)) *(.text .text.*) *(.rodata .rodata.*) } > FLASH
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
    . = ALIGN(4);
    _etext = .;
    .data : AT(_etext) { _sdata = .; *(.data .data.*) . = ALIGN(4); _edata = .; } > RAM
    .bss (NOLOAD) : { _sbss = .; *(.bss .bss.* COMMON) . = ALIGN(4); _ebss = .; } > RAM
    _estack = ORIGIN(RAM) + LENGTH(RAM);
    ASSERT(_ebss + 4096 <= _estack, "less than 4 KiB left for the stack")
}
