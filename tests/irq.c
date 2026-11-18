/* Interrupt test harness: classifies SysTick exceptions and compares interrupted calls with an
 * uninterrupted one. See tests/irq.h and tests/irq.S. Test image only. */
#include "irq.h"

void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
void *memset(void *d, int c, size_t n) {
    uint8_t *dd = d;
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
void __aeabi_memclr(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr4(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr8(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memcpy(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy4(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy8(void *d, const void *s, size_t n) { memcpy(d, s, n); }

int memeq(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}
void put_hex(uint32_t v) {
    char b[11] = "0x00000000";
    for (int i = 0; i < 8; i++) b[9 - i] = "0123456789abcdef"[(v >> (4 * i)) & 15];
    semihost_write0(b);
}
void put_dec(uint32_t v) {   /* no division: ARMv6-M has none and the image has no libgcc */
    static const uint32_t pow10[] = {1000000000, 100000000, 10000000, 1000000, 100000, 10000,
                                     1000, 100, 10, 1};
    char b[11], *p = b;
    for (int i = 0; i < 10; i++) {
        char d = '0';
        while (v >= pow10[i]) { v -= pow10[i]; d++; }
        if (d != '0' || p != b || i == 9) *p++ = d;
    }
    *p = 0;
    semihost_write0(b);
}
static uint32_t failures, checks;
void check(int ok, const char *what, uint32_t a, uint32_t b) {
    checks++;
    if (!ok) {
        failures++;
        semihost_write0("FAIL ");
        semihost_write0(what);
        semihost_write0(" ");
        put_hex(a);
        semihost_write0(" ");
        put_hex(b);
        semihost_write0("\n");
    }
}

#define SYST_CSR (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018)
#define ICSR (*(volatile uint32_t *)0xE000ED04)
#define PENDSTCLR 0x02000000u
#define TICKS_MAX 0x00ffffffu
#define IRQ_HEAD 24
#define IRQ_TAIL 64

extern uint32_t cc8_sp;       /* check_call8: SP at the call of the function under test */
uint32_t irq_probe(void);     /* tests/irq.S: returns SYST_CVR */

static struct {
    const char *name;
    uint32_t lo, hi, frame;
    uint32_t prologue, body, calls, epilogue;
} t;
static volatile int active, in_body, entered;
static volatile uint32_t period;
static uint32_t seed = 0x6d30632d, pre, post, stalls, last[9];
#define TEXT_MAX 8192
static uint8_t seen[TEXT_MAX / 16];

static int is_return(uint32_t pc) {
    uint16_t op = *(const uint16_t *)pc;
    return (op & 0xff00u) == 0xbd00u || op == 0x4770u;   /* pop {..., pc} or bx lr */
}

/* Called by systick_handler with its exception frame (r0-r3, r12, LR, PC, xPSR); returns
 * the first word of the pattern the handler writes below the frame. */
uint32_t irq_note(const uint32_t *frame) {
    seed = seed * 1664525u + 1013904223u;
    /* QEMU can take the next exception before the interrupted code runs an instruction: the
     * stacked registers and SP then equal those of the previous exception. Lengthen the next
     * period once so the call makes progress. */
    int same = last[8] == (uint32_t)frame;
    for (int i = 0; i < 8; i++) {
        same &= last[i] == frame[i];
        last[i] = frame[i];
    }
    last[8] = (uint32_t)frame;
    stalls += (uint32_t)same;
    SYST_RVR = same ? period + 16 : period;
    uint32_t pc = frame[6];
    uint32_t sp = (uint32_t)frame + 32 + ((frame[7] >> 9) & 1) * 4;
    uint32_t lo = (uint32_t)irq_text_lo, hi = (uint32_t)irq_text_hi;
    if (!active) return seed;
    if (pc < lo || pc >= hi) {
        if (entered && sp >= cc8_sp) SYST_CSR = 0;   /* the call has returned */
        return seed;
    }
    entered = 1;
    uint32_t h = (pc - lo) / 2;
    if (h < TEXT_MAX / 2) seen[h / 8] |= (uint8_t)(1u << (h % 8));
    if (pc >= t.lo && pc < t.hi) {
        if (in_body && is_return(pc)) {
            t.epilogue++;
        } else if (cc8_sp - sp < t.frame) {
            if (in_body) t.epilogue++; else t.prologue++;
        } else {
            t.body++;
            in_body = 1;
        }
    } else {
        t.calls++;
    }
    return seed;
}

void irq_target(const char *name, const void *fn, const void *end, uint32_t frame) {
    t.name = name;
    t.lo = (uint32_t)fn & ~1u;
    t.hi = (uint32_t)end & ~1u;
    t.frame = frame;
    t.prologue = t.body = t.calls = t.epilogue = stalls = 0;
    memset(seen, 0, sizeof seen);
}

/* SysTick counts processor clocks from TICKS_MAX down without exceptions. */
static void count(void) {
    SYST_CSR = 0;
    SYST_RVR = TICKS_MAX;
    SYST_CVR = 0;
    SYST_CSR = 5;
}
/* First exception after first + 1 ticks, then one every period + 1 ticks after the handler,
 * until one lands after the call has returned. */
static void arm(uint32_t first, uint32_t every, int late) {
    SYST_CSR = 0;
    period = every;
    SYST_RVR = first;
    SYST_CVR = 0;
    ICSR = PENDSTCLR;
    in_body = late;
    entered = 0;
    last[8] = 0;
    active = 1;
    SYST_CSR = 7;
}
static void stop(void) {
    SYST_CSR = 0;
    ICSR = PENDSTCLR;
    active = 0;
}

void irq_init(void) {
    uint32_t args[8] = {0}, res[2];
    count();
    uint32_t c = (uint32_t)check_call8((void *)irq_probe, args, res);
    uint32_t after = SYST_CVR;
    stop();
    pre = TICKS_MAX - c;
    post = c - after;
}

#define OUT_MAX 512
static uint8_t ref[OUT_MAX];
static uint32_t ref_vol[5];
static int ref_r;
static int run(const char *what, void *fn, const uint32_t args[8], void (*setup)(void),
                const void *out, size_t len, uint32_t first, uint32_t every, int late) {
    uint32_t res[2];
    setup();
    arm(first, every, late);
    int r = check_call8(fn, args, res);
    stop();
    check(r == ref_r, what, first, (uint32_t)r);
    check(res[0] == 0, what, first, res[0]);
    check(memeq(out, ref, len), what, first, every);
    check(memeq(cc8_volatile, ref_vol, sizeof ref_vol), what, first, every);
    return entered;
}

void irq_cover(const char *what, void *fn, const uint32_t args[8], void (*setup)(void),
               const void *out, size_t len, int all, const uint32_t *periods, size_t n) {
    uint32_t res[2];
    check(len <= OUT_MAX, "output too long", (uint32_t)len, OUT_MAX);
    if (len > OUT_MAX) return;
    setup();
    count();
    ref_r = check_call8(fn, args, res);
    uint32_t ticks = TICKS_MAX - SYST_CVR;
    stop();
    check(res[0] == 0, what, 0xffffffff, res[0]);
    memcpy(ref, out, len);
    memcpy(ref_vol, cc8_volatile, sizeof ref_vol);
    /* The ticks after the return depend on how many stack words the call changed; the probe
     * changes none, so pre + d + 4 is at or after the return. */
    uint32_t d = ticks - pre - post, mid = pre + d / 2;
    uint32_t lo = pre - 4, hi = pre + d + 4;
    if (!all) {   /* last tick whose exception lands in the asset's code: bisection */
        uint32_t a = mid, b = hi;
        while (b - a > 1) {
            uint32_t m = a + (b - a) / 2;
            if (run(what, fn, args, setup, out, len, m, TICKS_MAX, 1)) a = m; else b = m;
        }
        hi = b + 4;
    }
    for (uint32_t f = lo; f <= hi; f++) {
        if (!all && f == lo + IRQ_HEAD && hi - f > IRQ_TAIL) f = hi - IRQ_TAIL;
        run(what, fn, args, setup, out, len, f, TICKS_MAX, f > mid);
    }
    for (size_t i = 0; i < n; i++)
        run(what, fn, args, setup, out, len, pre - 4, periods[i], 0);
}

void irq_summary(void) {
    uint32_t pcs = 0;
    for (size_t i = 0; i < sizeof seen; i++)
        for (int b = 0; b < 8; b++) pcs += (seen[i] >> b) & 1;
    uint32_t total = t.prologue + t.body + t.calls + t.epilogue;
    semihost_write0("irq ");
    semihost_write0(t.name);
    semihost_write0(": ");
    put_dec(total);
    semihost_write0(" exceptions (prologue ");
    put_dec(t.prologue);
    semihost_write0(", body ");
    put_dec(t.body);
    semihost_write0(", internal calls ");
    put_dec(t.calls);
    semihost_write0(", epilogue ");
    put_dec(t.epilogue);
    semihost_write0(") at ");
    put_dec(pcs);
    semihost_write0(" distinct PCs");
    if (stalls) {
        semihost_write0(", ");
        put_dec(stalls);
        semihost_write0(" periods lengthened after an exception without progress");
    }
    semihost_write0("\n");
    /* seen[] maps TEXT_MAX bytes of code: a longer .text would go uncounted past its end. */
    check((uint32_t)(irq_text_hi - irq_text_lo) <= TEXT_MAX, "code fits the PC map",
          (uint32_t)(irq_text_hi - irq_text_lo), TEXT_MAX);
    check(t.prologue > 0 && t.body > 0 && t.epilogue > 0, "exceptions in prologue, body, epilogue",
          t.prologue, t.epilogue);
}

int report(void) {
    semihost_write0("checks ");
    put_dec(checks);
    semihost_write0(", failures ");
    put_dec(failures);
    semihost_write0("\n");
    semihost_write0(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return (int)failures;
}
