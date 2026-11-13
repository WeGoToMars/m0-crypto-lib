/* SPDX-License-Identifier: MIT
 * Shared helpers of the board benchmark images (benchmark-only, not library code). */
#ifndef M0C_BOARD_COMMON_H
#define M0C_BOARD_COMMON_H
#include <stddef.h>
#include <stdint.h>

void semihost_write0(const char *s);   /* UART0 in these images (startup.S, UART_OUT) */
uint32_t time_call3(void *fn, const void *a, const void *b, const void *c);
uint32_t stack_call3(void *fn, const void *a, const void *b, const void *c);
void bench_noop(void);

#define SYST_CSR (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018u)

#define TIME_OVERFLOW 0xFFFFFFFFu
#define REPS 5

/* Output: decimal without division (no compiler runtime in the image). */
void put_s(const char *s);
void put_u(uint32_t v);
void put_hex8(uint32_t v);
void put_bytes_hex(const uint8_t *p, unsigned n);
void put_comma(void);

/* Test messages: family 0 zeros, 1 0xff, 2 xorshift A, 3 xorshift B, 4 counting pattern
 * mod 251. Mirrors fill() in gen_vectors.py. */
void fill_message(uint8_t *p, unsigned family, unsigned n);
int bytes_equal(const uint8_t *a, const uint8_t *b, unsigned n);

/* Start SysTick: reload 0xFFFFFF, processor clock, no interrupt. */
void timer_start(void);
/* Smallest of 16 time_call3(bench_noop, ...) results: the fixed cost to subtract. */
uint32_t timer_overhead(void);

/* Record of one exactly-timed series of REPS runs. */
struct series {
    uint32_t t[REPS];
    uint32_t min, max;
    int invalid;
};
void series_add(struct series *s, unsigned i, uint32_t raw, uint32_t overhead);
void series_finish(struct series *s);
/* ",min,max" followed by nothing; with all=1 also ",t0,t1,..." */
void put_series(const struct series *s, int all);
#endif
