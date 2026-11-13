/* SPDX-License-Identifier: MIT
 * MSPM0L2228 board image for the released X25519 asset (m0crypto_x25519.o).
 * Benchmark-only; links the unmodified release object and nothing else of the library.
 *
 * 1. Gate: every vector (RFC 7748 plus edge, low-order, non-canonical and random pairs;
 *    expected results from gen_vectors.py) must match, in the aligned layout and in
 *    the unaligned and in-place layouts used below. No timing unless the gate passes.
 * 2. Stack: stack high-water mark of one call, called directly.
 * 3. Timing: SysTick on the processor clock; each case is REPS runs of one
 *    m0c_x25519 call timed directly (time_call3, fixed call cost subtracted), output
 *    verified after every run. All REPS raw counts are printed, not just min/max:
 *      X25519,index,label,layout,min,max,t0,t1,t2,t3,t4
 *    layouts: a (word-aligned, disjoint), u (k+1, u+2, out+3), ipk (out == scalar),
 *    ipu (out == point).
 */
#include "common.h"
#include "m0crypto/x25519.h"
#include "x25519_vectors.h"

volatile uint32_t bench_status;       /* 0 running, 1 done, 2 gate failed, 3 invalid timing */
static unsigned checks, failures, invalid;
static uint32_t overhead;

static uint8_t kb[48] __attribute__((aligned(8)));
static uint8_t ub[48] __attribute__((aligned(8)));
static uint8_t ob[64] __attribute__((aligned(8)));

enum { L_A, L_U, L_IPK, L_IPU, NLAYOUT };
static const char *const layout_name[NLAYOUT] = {"a", "u", "ipk", "ipu"};

struct place { uint8_t *k, *u, *out; };
static struct place layout(unsigned l) {
    switch (l) {
    case L_U:   return (struct place){kb + 1, ub + 2, ob + 8 + 3};
    case L_IPK: return (struct place){kb, ub, kb};
    case L_IPU: return (struct place){kb, ub, ub};
    default:    return (struct place){kb, ub, ob + 8};
    }
}
static void load(const struct x_vec *v, const struct place *p) {
    for (unsigned i = 0; i < sizeof ob; i++) ob[i] = 0xa5;
    for (unsigned i = 0; i < sizeof kb; i++) { kb[i] = 0x3c; ub[i] = 0x3c; }
    for (unsigned i = 0; i < 32; i++) { p->k[i] = v->k[i]; p->u[i] = v->u[i]; }
}
/* Result in place and, for the disjoint layouts, nothing else of ob written. */
static int result_ok(const struct x_vec *v, const struct place *p, unsigned l) {
    unsigned ok = bytes_equal(p->out, v->out, 32);
    if (l == L_A || l == L_U)
        for (unsigned i = 0; i < sizeof ob; i++)
            if ((i < (unsigned)(p->out - ob) || i >= (unsigned)(p->out - ob) + 32) && ob[i] != 0xa5)
                ok = 0;
    return ok;
}

static void fail(const char *what, unsigned idx, unsigned l) {
    failures++;
    if (failures <= 16) {
        put_s("FAIL,"); put_s(what); put_comma(); put_u(idx); put_comma();
        put_s(layout_name[l]); put_s("\n");
    }
}

int main(void) {
    bench_status = 0;
    put_s("m0-crypto X25519 board bench (released object m0crypto_x25519.o)\n");

    for (unsigned i = 0; i < X_NVEC; i++)
        for (unsigned l = 0; l < NLAYOUT; l++) {
            struct place p = layout(l);
            load(&x_vecs[i], &p);
            int r = m0c_x25519(p.out, p.k, p.u);
            checks++;
            if (r != 0) fail("return", i, l);
            if (!result_ok(&x_vecs[i], &p, l)) fail("result", i, l);
        }
    put_s(failures ? "GATE: FAIL " : "GATE: PASS "); put_u(checks); put_s(" checks\n");
    if (failures) { bench_status = 2; put_s("RESULT: FAIL\n"); return 1; }
    checks = 0;

    /* Stack depth for one call on a few inputs. */
    unsigned worst = 0;
    for (unsigned i = 0; i < 4; i++) {
        struct place p = layout(L_A);
        load(&x_vecs[i], &p);
        uint32_t s = stack_call3((void *)m0c_x25519, p.out, p.k, p.u);
        put_s("STACK,"); put_u(i); put_comma(); put_u(s); put_s("\n");
        if (s > worst) worst = s;
    }
    put_s("STACKMAX,"); put_u(worst); put_s("\n");

    timer_start();
    overhead = timer_overhead();
    put_s("OVERHEAD,"); put_u(overhead); put_s("\n");
    put_s("# X25519,index,label,layout,min,max,t0..t4 (raw ticks, overhead subtracted)\n");

    for (unsigned i = 0; i < X_NVEC; i++) {
        /* Disjoint aligned layout for every vector; the other layouts for a few. */
        for (unsigned l = 0; l < NLAYOUT; l++) {
            if (l != L_A && i >= 3 && i != 8 && i != 22 && i != 30) continue;
            struct place p = layout(l);
            struct series s;
            s.invalid = 0;
            for (unsigned r = 0; r < REPS; r++) {
                load(&x_vecs[i], &p);
                uint32_t raw = time_call3((void *)m0c_x25519, p.out, p.k, p.u);
                series_add(&s, r, raw, overhead);
                checks++;
                if (!result_ok(&x_vecs[i], &p, l)) fail("timed-result", i, l);
            }
            series_finish(&s);
            if (s.invalid) invalid++;
            put_s("X25519,"); put_u(i); put_comma(); put_s(x_vecs[i].label);
            put_comma(); put_s(layout_name[l]); put_series(&s, 1); put_s("\n");
        }
    }

    SYST_CSR = 5;
    if (failures) { bench_status = 2; put_s("RESULT: FAIL result during timing\n"); return 1; }
    if (invalid) { bench_status = 3; put_s("RESULT: FAIL timer\n"); return 1; }
    put_s("TIMED_CHECKS,"); put_u(checks); put_s("\n");
    bench_status = 1;
    put_s("RESULT: PASS\n");
    return 0;
}
