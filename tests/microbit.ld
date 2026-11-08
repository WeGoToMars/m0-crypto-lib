/* QEMU "microbit" (nRF51822, Cortex-M0): 256 KiB flash at 0, 16 KiB RAM. Test image only. */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}
ENTRY(reset_handler)
SECTIONS
{
    .text : { KEEP(*(.vectors)) *(.text .text.*) *(.rodata .rodata.*) } > FLASH
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
    . = ALIGN(4);
    _etext = .;
    .data : AT(_etext) { _sdata = .; *(.data .data.*) _edata = .; } > RAM
    .bss (NOLOAD) : { _sbss = .; *(.bss .bss.* COMMON) _ebss = .; } > RAM
    _estack = ORIGIN(RAM) + LENGTH(RAM);
}
