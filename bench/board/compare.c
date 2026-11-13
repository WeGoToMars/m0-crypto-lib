/* SPDX-License-Identifier: MIT
 * MSPM0L2228 board image comparing implementations of one primitive (benchmark-only).
 * It links the objects bench/build.py compiles for the emulator comparison (the
 * run_IMPL_OP wrappers of bench/harness/, every comparator, the shared runtime and the
 * release object), and times each wrapper as bench/count.py counts it: one call with
 * key setup, context initialisation and wrapper overhead included.
 *
 * Inputs are copied to aligned SRAM buffers before each call, as the emulator places
 * them, and the output buffer is filled with 0xa5 first.
 * 1. Gate: every case once; status, output and tag must match the table from
 *    gen_compare.py (reference.py). No timing unless all match.
 * 2. Timing: SysTick on the processor clock, REPS runs per case, each one
 *    time_call3(wrapper, &job) with the fixed call cost subtracted, checked afterwards:
 *      CMP,impl,op,input,len,min,max,t0,t1,t2,t3,t4
 */
#include "common.h"
#include "harness/job.h"

struct cmp_case {
    const char *impl, *op, *input;
    void (*fn)(Job *);
    unsigned len, aad_len, reject, keep;
    const uint8_t *key, *nonce, *aad, *in;
    unsigned in_len;
    const uint8_t *tag_in, *out;
    unsigned out_len;
    const uint8_t *tag_out;
};
#include "cases.h"

#define MAXLEN 4096u
static uint8_t inb[MAXLEN] __attribute__((aligned(8)));
static uint8_t outb[MAXLEN] __attribute__((aligned(8)));
static uint8_t keyb[32] __attribute__((aligned(8)));
static uint8_t nonceb[16] __attribute__((aligned(8)));
static uint8_t aadb[64] __attribute__((aligned(8)));
static uint8_t tagb[16] __attribute__((aligned(8)));
static Job job __attribute__((aligned(8)));

volatile uint32_t bench_status;       /* 0 running, 1 done, 2 gate failed, 3 invalid timing */
static unsigned checks, failures, invalid;
static uint32_t overhead;

static void set(uint8_t *p, uint8_t v, unsigned n) { for (unsigned i = 0; i < n; i++) p[i] = v; }
static void copy(uint8_t *d, const uint8_t *s, unsigned n) { for (unsigned i = 0; i < n; i++) d[i] = s[i]; }

static void prep(const struct cmp_case *c) {
    set(outb, 0xa5, sizeof outb);
    set(tagb, 0xa5, sizeof tagb);
    set(keyb, 0, sizeof keyb);
    set(nonceb, 0, sizeof nonceb);
    if (c->in) copy(inb, c->in, c->in_len);
    if (c->key) copy(keyb, c->key, 32);
    if (c->nonce) copy(nonceb, c->nonce, 12);
    if (c->aad) copy(aadb, c->aad, c->aad_len);
    if (c->tag_in) copy(tagb, c->tag_in, 16);
    job = (Job){outb, inb, c->len, keyb, nonceb, aadb, c->aad_len, tagb, 0x7fffffff};
}

static int result_ok(const struct cmp_case *c) {
    if (c->reject ? job.status == 0 : job.status != 0) return 0;
    if (c->keep) {
        for (unsigned i = 0; i < c->out_len; i++)
            if (outb[i] != 0xa5) return 0;
    } else if (c->out && !bytes_equal(outb, c->out, c->out_len)) {
        return 0;
    }
    if (c->tag_out && !bytes_equal(tagb, c->tag_out, 16)) return 0;
    return 1;
}

static void fail(const char *what, const struct cmp_case *c) {
    failures++;
    if (failures <= 16) {
        put_s("FAIL,"); put_s(what); put_comma(); put_s(c->impl); put_comma(); put_s(c->op);
        put_comma(); put_s(c->input); put_comma(); put_u(c->len); put_s("\n");
    }
}

int main(void) {
    bench_status = 0;
    put_s("m0-crypto comparison board bench, " CMP_PRIMITIVE " (bench/build.py objects)\n");
    for (unsigned i = 0; i < CMP_NCASES; i++) {
        prep(&cmp_cases[i]);
        cmp_cases[i].fn(&job);
        checks++;
        if (!result_ok(&cmp_cases[i])) fail("gate", &cmp_cases[i]);
    }
    put_s(failures ? "GATE: FAIL " : "GATE: PASS "); put_u(checks); put_s(" checks\n");
    if (failures) { bench_status = 2; put_s("RESULT: FAIL\n"); return 1; }
    checks = 0;

    timer_start();
    overhead = timer_overhead();
    put_s("OVERHEAD,"); put_u(overhead); put_s("\n");
    put_s("# CMP,impl,op,input,len,min,max,t0..t4 (ticks, overhead subtracted)\n");
    for (unsigned i = 0; i < CMP_NCASES; i++) {
        const struct cmp_case *c = &cmp_cases[i];
        struct series s;
        s.invalid = 0;
        for (unsigned r = 0; r < REPS; r++) {
            prep(c);
            series_add(&s, r, time_call3((void *)c->fn, &job, 0, 0), overhead);
            checks++;
            if (!result_ok(c)) fail("timed-result", c);
        }
        series_finish(&s);
        if (s.invalid) invalid++;
        put_s("CMP,"); put_s(c->impl); put_comma(); put_s(c->op); put_comma(); put_s(c->input);
        put_comma(); put_u(c->len); put_series(&s, 1); put_s("\n");
    }

    SYST_CSR = 5;
    if (failures) { bench_status = 2; put_s("RESULT: FAIL result during timing\n"); return 1; }
    if (invalid) { bench_status = 3; put_s("RESULT: FAIL timer\n"); return 1; }
    put_s("TIMED_CHECKS,"); put_u(checks); put_s("\n");
    bench_status = 1;
    put_s("RESULT: PASS\n");
    return 0;
}
