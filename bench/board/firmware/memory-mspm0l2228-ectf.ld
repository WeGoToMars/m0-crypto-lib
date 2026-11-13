/*
 * MSPM0L2228 behind the eCTF 2026 insecure bootloader (v26.0.2): the bootloader owns
 * flash 0x0000-0x5FFF (and app metadata at 0x5000); the application image starts with
 * its vector table at 0x6000. The flash tool accepts at most 104 KiB (APP_PAGES = 104,
 * ectf/hw/ti/__init__.py). Layout from the reference design firmware/firmware.ld
 * (ectfmitre/2026-ectf-insecure-example).
 *
 * SRAM: one 32 KiB array with three aliases (ECC-checked 0x2000_0000, parity
 * 0x2010_0000, unchecked 0x2020_0000). The reference design and TI's default linker
 * files use the unchecked alias, as does this target.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00006000, LENGTH = 104K
    RAM   (rwx) : ORIGIN = 0x20200000, LENGTH = 32K
}
