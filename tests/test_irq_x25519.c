/* Interrupt test of m0c_x25519 (QEMU microbit with -icount). Test image only.
 * The RFC 7748 section 5.2 vector is computed without interrupts and checked, then with SysTick
 * exceptions at each of the first and last instructions of the call and periodically, while the
 * handler overwrites the stack below the interrupted SP (tests/irq.c, tests/irq.S); every result
 * must equal the uninterrupted one. Also with out equal to point. */
#include "irq.h"
#include "m0crypto/x25519.h"

extern const char irq_end_m0c_x25519[];

/* RFC 7748 section 5.2, first vector */
static const uint8_t rfc_scalar[32] = {0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
    0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4};
static const uint8_t rfc_point[32] = {0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
    0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c};
static const uint8_t rfc_shared[32] = {0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
    0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52};

static struct {
    uint8_t g0[8];
    uint8_t out[32];
    uint8_t g1[8];
} io __attribute__((aligned(4)));
static int inplace;

static void setup(void) {
    memset(&io, 0x5a, sizeof io);
    if (inplace) memcpy(io.out, rfc_point, 32);
}

static const uint32_t periods[] = {61, 251, 1021, 4093};
#define NP (sizeof periods / sizeof periods[0])

int main(void) {
    irq_init();
    setup();
    int r = m0c_x25519(io.out, rfc_scalar, rfc_point);
    check(r == 0 && memeq(io.out, rfc_shared, 32), "x25519 vector", 0, (uint32_t)r);

    irq_target("m0c_x25519", (const void *)m0c_x25519, irq_end_m0c_x25519, 368);
    for (inplace = 0; inplace < 2; inplace++) {
        uint32_t a[8] = {(uint32_t)io.out, (uint32_t)rfc_scalar,
                         inplace ? (uint32_t)io.out : (uint32_t)rfc_point, 0, 0, 0, 0, 0};
        irq_cover("x25519", (void *)m0c_x25519, a, setup, &io, sizeof io, 0, periods,
                  inplace ? 1 : NP);
    }
    irq_summary();
    return report();
}
