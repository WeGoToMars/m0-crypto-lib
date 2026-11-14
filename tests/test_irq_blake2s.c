/* Interrupt test of m0c_blake2s_init, m0c_blake2s_update and m0c_blake2s_final (QEMU microbit
 * with -icount). Test image only. Every call is compared with the same call without interrupts
 * while SysTick exceptions land at every instruction of it, and periodically, and the handler
 * overwrites the stack below the interrupted SP (tests/irq.c, tests/irq.S). The uninterrupted
 * digests are checked against tests/blake2s_vectors.h. */
#include "irq.h"
#include "m0crypto/blake2s.h"
#include "blake2s_vectors.h"

extern const char irq_end_m0c_blake2s_init[], irq_end_m0c_blake2s_update[],
    irq_end_m0c_blake2s_final[];

static struct {
    uint8_t g0[8];
    m0c_blake2s_ctx c;
    uint8_t g1[8];
    uint8_t out[32];
    uint8_t g2[8];
} io __attribute__((aligned(4)));
static uint8_t in[256];
static m0c_blake2s_ctx start;

static void setup(void) {
    memset(&io, 0x5a, sizeof io);
    memcpy(&io.c, &start, sizeof start);
}
/* start = the context after init and update(in, n) */
static void absorb(size_t n) {
    m0c_blake2s_init(&start);
    m0c_blake2s_update(&start, in, n);
}

static const uint32_t periods[] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                   20, 23, 29, 31, 37, 40, 64, 97, 128, 251};
#define NP (sizeof periods / sizeof periods[0])

int main(void) {
    irq_init();
    for (size_t i = 0; i < sizeof in; i++) in[i] = B2V_PATTERN(i);

    irq_target("m0c_blake2s_init", (const void *)m0c_blake2s_init, irq_end_m0c_blake2s_init, 4);
    {
        memset(&start, 0xc3, sizeof start);
        uint32_t a[8] = {(uint32_t)&io.c, 0, 0, 0, 0, 0, 0, 0};
        irq_cover("init", (void *)m0c_blake2s_init, a, setup, &io, sizeof io, 1, periods, NP);
    }
    irq_summary();

    /* update: two full blocks and a partial one from empty; then a partial block filled
     * and continued; then one byte into an empty buffer */
    static const uint16_t upd[][2] = {{0, 150}, {37, 91}, {64, 64}, {0, 1}};
    irq_target("m0c_blake2s_update", (const void *)m0c_blake2s_update,
               irq_end_m0c_blake2s_update, 24);
    for (size_t k = 0; k < sizeof upd / sizeof upd[0]; k++) {
        size_t pre = upd[k][0], n = upd[k][1];
        absorb(pre);
        uint32_t a[8] = {(uint32_t)&io.c, (uint32_t)(in + pre), n, 0, 0, 0, 0, 0};
        irq_cover("update", (void *)m0c_blake2s_update, a, setup, &io, sizeof io, 1, periods,
                  NP);
        setup();
        m0c_blake2s_update(&io.c, in + pre, n);
        m0c_blake2s_final(&io.c, io.out);
        check(memeq(io.out, b2v_digest[pre + n], 32), "update digest", (uint32_t)pre,
              (uint32_t)n);
    }
    irq_summary();

    static const uint16_t fin[] = {128, 37, 0};
    irq_target("m0c_blake2s_final", (const void *)m0c_blake2s_final, irq_end_m0c_blake2s_final,
               24);
    for (size_t k = 0; k < sizeof fin / sizeof fin[0]; k++) {
        absorb(fin[k]);
        uint32_t a[8] = {(uint32_t)&io.c, (uint32_t)io.out, 0, 0, 0, 0, 0, 0};
        irq_cover("final", (void *)m0c_blake2s_final, a, setup, &io, sizeof io, 1, periods, NP);
        setup();
        m0c_blake2s_final(&io.c, io.out);
        check(memeq(io.out, b2v_digest[fin[k]], 32), "final digest", fin[k], 0);
    }
    irq_summary();
    return report();
}
