/*
 * UART0 output backend for MSPM0L2228 bench images (benchmark-only, not library code).
 *
 * UART0 on PA10 (TX, PINCM25) / PA11 (RX, PINCM26) is the XDS110 backchannel UART on
 * the eCTF board, the same port the bootloader uses. 115200 8N1 from BUSCLK with
 * IBRD 17 / FBRD 23 at 32 MHz, 16x oversampling: the reference design's settings
 * (ti_msp_dl_config.c/.h). Register addresses come from MSPM0L222X.svd with cluster
 * offsets included; key values from DriverLib (UART_PWREN_KEY 0x26, UART_RSTCTL_KEY
 * 0xB1). A first board run with the GPRCM offsets wrong (+0x0 instead of +0x800)
 * HardFaulted on the RSTCTL write.
 *
 * uart_init waits for one received byte before returning, so the host can open the
 * port after the bootloader's `start` handshake without losing output.
 * It then prints one PLATFORM line with the clock and flash-wait configuration
 * as the image found it, because SysTick ticks are only meaningful together with it.
 * Nothing here changes the clock, flash wait states, prefetch or cache.
 */
#include <stdint.h>

#define REG(a) (*(volatile uint32_t *)(a))

#define UART0          0x40108000u
#define UART_PWREN     (UART0 + 0x0800)  /* GPRCM cluster at +0x800 */
#define UART_RSTCTL    (UART0 + 0x0804)
#define UART_CLKDIV    (UART0 + 0x1000)
#define UART_CLKSEL    (UART0 + 0x1008)
#define UART_CTL0      (UART0 + 0x1100)
#define UART_LCRH      (UART0 + 0x1104)
#define UART_STAT      (UART0 + 0x1108)
#define UART_IBRD      (UART0 + 0x1110)
#define UART_FBRD      (UART0 + 0x1114)
#define UART_TXDATA    (UART0 + 0x1120)
#define UART_RXDATA    (UART0 + 0x1124)
#define STAT_RXFE      (1u << 2)
#define STAT_BUSY      (1u << 0)
#define STAT_TXFF      (1u << 7)

#define IOMUX_PINCM(n) (0x40428000u + 0x4u + 4u * ((n) - 1u))
#define PINCM_PC       0x00000080u
#define PINCM_INENA    0x00040000u
#define PF_UART0       0x00000002u

#define SYSCTL_SYSOSCCFG 0x400B0100u  /* SYSCTL 0x400AF000 + SOCLOCK cluster 0x1000 + 0x100 */
#define SYSCTL_MCLKCFG   0x400B0104u
#define SYSCTL_CLKSTATUS 0x400B0204u
#define CPUSS_CTL        0x40401300u
#define SCB_CPUID        0xE000ED00u

static void uart_putc(char c) {
    while (REG(UART_STAT) & STAT_TXFF) {
    }
    REG(UART_TXDATA) = (uint8_t)c;
}

void uart_write0(const char *s) {
    for (; *s; s++) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s);
    }
}

static void uart_hex(uint32_t v) {
    char b[11];
    b[0] = '0';
    b[1] = 'x';
    for (int i = 0; i < 8; i++) {
        uint32_t d = (v >> (28 - 4 * i)) & 0xf;
        b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    b[10] = 0;
    uart_write0(b);
}

void uart_init(void) {
    REG(UART_RSTCTL) = 0xB1000003u;            /* KEY | RESETSTKYCLR | RESETASSERT */
    REG(UART_PWREN) = 0x26000001u;             /* KEY | ENABLE */
    for (volatile int i = 0; i < 32; i++) {    /* power-up settle (DriverLib waits 16) */
    }
    REG(IOMUX_PINCM(25)) = PINCM_PC | PF_UART0;               /* PA10 = UART0_TX */
    REG(IOMUX_PINCM(26)) = PINCM_INENA | PINCM_PC | PF_UART0; /* PA11 = UART0_RX */
    REG(UART_CTL0) = 0;                        /* disabled while configuring */
    REG(UART_CLKSEL) = 0x8u;                   /* BUSCLK */
    REG(UART_CLKDIV) = 0;                      /* divide by 1 */
    REG(UART_IBRD) = 17;
    REG(UART_FBRD) = 23;
    REG(UART_LCRH) = 0x30u;                    /* 8N1; LCRH write latches IBRD/FBRD */
    REG(UART_CTL0) = (1u << 4) | (1u << 3) | 1u; /* TXE | RXE | ENABLE, 16x oversampling */

    while (REG(UART_STAT) & STAT_RXFE) {       /* host: send any byte to begin */
    }
    (void)REG(UART_RXDATA);

    uart_write0("\n\nPLATFORM,mspm0l2228-ectf,CPUID=");
    uart_hex(REG(SCB_CPUID));
    uart_write0(",MCLKCFG=");
    uart_hex(REG(SYSCTL_MCLKCFG));
    uart_write0(",SYSOSCCFG=");
    uart_hex(REG(SYSCTL_SYSOSCCFG));
    uart_write0(",CLKSTATUS=");
    uart_hex(REG(SYSCTL_CLKSTATUS));
    uart_write0(",CPUSS_CTL=");
    uart_hex(REG(CPUSS_CTL));
    uart_write0("\n");
}

/* Called from semihost_exit in UART builds: report, drain the FIFO, park. */
void uart_exit(int code) {
    uart_write0("EXIT ");
    uart_hex((uint32_t)code);
    uart_write0("\n");
    while (REG(UART_STAT) & STAT_BUSY) {
    }
    for (;;) {
    }
}
