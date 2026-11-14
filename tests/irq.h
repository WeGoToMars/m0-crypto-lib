/* Interrupt test harness (tests/irq.c, tests/irq.S). Test image only. */
#ifndef M0C_TEST_IRQ_H
#define M0C_TEST_IRQ_H
#include <stddef.h>
#include <stdint.h>

void semihost_write0(const char *s);
int check_call8(void *fn, const uint32_t args[8], uint32_t result[2]);
extern uint32_t cc8_volatile[5];

void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int memeq(const void *a, const void *b, size_t n);
void put_hex(uint32_t v);
void put_dec(uint32_t v);
void check(int ok, const char *what, uint32_t a, uint32_t b);
int report(void);   /* prints the totals and RESULT; returns the failure count */

/* Linker-defined (tools/test_qemu.sh): the start and end of the asset's .text, and for each
 * function F of the asset irq_end_F, the end of F (its symbol plus its size). */
extern const char irq_text_lo[], irq_text_hi[];

/* Measures the SysTick ticks from arming to the entry of a called function and from its return
 * to the end of check_call8 (for a function that changes no stack word). Call once before
 * irq_cover. */
void irq_init(void);

/* Exceptions are classified for the function under test: its entry, its end and the bytes its
 * own prologue puts on the stack. */
void irq_target(const char *name, const void *fn, const void *end, uint32_t frame);

/* Calls fn(args) through check_call8 once without interrupts and then many times with SysTick
 * exceptions. Before each call, setup() restores the inputs; after it, the bytes out[0..len),
 * the return value, r1-r3, r12 and the restored r4-r11 and SP must equal those of the
 * uninterrupted call. The interrupted calls are:
 *   - one exception at every instruction of the call (all != 0), or one at each of the first
 *     IRQ_HEAD and last IRQ_TAIL instructions (all == 0; the return is found by bisection);
 *   - for each period in periods[0..n), an exception every period ticks. */
void irq_cover(const char *what, void *fn, const uint32_t args[8], void (*setup)(void),
               const void *out, size_t len, int all, const uint32_t *periods, size_t n);

/* Prints, for the function set with irq_target, the exceptions taken in its calls since then:
 * in its prologue (SP above its full frame, before the body), its body, its internal calls and
 * its epilogue (SP above its full frame after the body, or at its return instruction), the
 * number of distinct PCs of the asset they landed at, and how often a period was lengthened
 * because QEMU took an exception before the interrupted code ran an instruction. */
void irq_summary(void);
#endif
