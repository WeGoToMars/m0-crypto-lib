/* SPDX-License-Identifier: MIT
 * MSPM0L2228 board image for the released BLAKE2s asset (m0crypto_blake2s.o).
 * Benchmark-only; links the unmodified release object and nothing else of the library.
 *
 * 1. Gate: every output is compared with a hashlib digest (tables from gen_vectors.py).
 *    No timing is printed unless the whole gate passes.
 * 2. Stack: stack high-water mark of each entry point called directly.
 * 3. Timing (SysTick on the processor clock, REPS runs per row, fixed call cost
 *    subtracted; every timed run's digest is checked afterwards):
 *      INIT,min,max
 *      UPDATE,len,off,min,max        one update call of len bytes at input offset off
 *      FINAL,len,min,max             final after one update of len bytes
 *      TOTAL,len,off,chunk,min,max   init + update(s) + final through a C wrapper;
 *                                    chunk 0 = one update, else updates of chunk bytes
 *      DATAVAR,len,off,family,...    same four measurements for 5 message contents
 *    INIT/UPDATE/FINAL time the library entry point alone (time_call3 calls it directly).
 *    TOTAL includes the wrapper's loop and call setup.
 */
#include "common.h"
#include "m0crypto/blake2s.h"
#include "blake2s_vectors.h"

#define MAXOFF 3u
static uint8_t msg[B2_MAX_LEN + 8] __attribute__((aligned(8)));
static uint8_t out_area[64] __attribute__((aligned(8)));
static m0c_blake2s_ctx ctx __attribute__((aligned(8)));

volatile uint32_t bench_status;       /* 0 running, 1 done, 2 gate failed, 3 invalid timing */
static unsigned checks, failures, invalid;
static uint32_t overhead;

struct job { const uint8_t *in; uint8_t *out; unsigned len, chunk; };

/* The API user's sequence: init, update(s), final. An empty message makes no update call. */
static void run_hash(const struct job *j) {
    m0c_blake2s_init(&ctx);
    if (j->len) {
        if (j->chunk == 0) {
            m0c_blake2s_update(&ctx, j->in, j->len);
        } else {
            for (unsigned i = 0; i < j->len; i += j->chunk) {
                unsigned n = j->len - i < j->chunk ? j->len - i : j->chunk;
                m0c_blake2s_update(&ctx, j->in + i, n);
            }
        }
    }
    m0c_blake2s_final(&ctx, j->out);
}

static void fail(const char *what, unsigned len, unsigned off, unsigned chunk, unsigned fam) {
    failures++;
    if (failures <= 16) {
        put_s("FAIL,"); put_s(what);
        put_comma(); put_u(len); put_comma(); put_u(off);
        put_comma(); put_u(chunk); put_comma(); put_u(fam); put_s("\n");
    }
}

static void prep(unsigned li, unsigned off, unsigned fam) {
    for (unsigned i = 0; i < 4; i++) msg[i] = 0x5a;          /* bytes around the message */
    fill_message(msg + off, fam, b2_lens[li]);
}

static void clear_out(void) { for (unsigned i = 0; i < sizeof out_area; i++) out_area[i] = 0xa5; }
/* The 32 digest bytes at out_area+4+oo equal want and every other byte is still 0xa5. */
static int out_ok(unsigned oo, const uint8_t *want) {
    unsigned ok = bytes_equal(out_area + 4 + oo, want, 32);
    for (unsigned i = 0; i < sizeof out_area; i++)
        if ((i < 4 + oo || i >= 36 + oo) && out_area[i] != 0xa5) ok = 0;
    return ok;
}

/* ---- gate ---- */
static void gate(void) {
    static const unsigned chunks[] = {0, 64, 17, 1};
    for (unsigned li = 0; li < B2_NLENS; li++)
        for (unsigned fam = 0; fam < B2_NFAMILIES; fam++)
            for (unsigned off = 0; off <= MAXOFF; off++) {
                prep(li, off, fam);
                for (unsigned ci = 0; ci < 4; ci++) {
                    unsigned oo = (off + ci) & 1;           /* digest alignment: 0 or 1 */
                    if (chunks[ci] == 1 && b2_lens[li] > 65) continue;
                    struct job j = {msg + off, out_area + 4 + oo, b2_lens[li], chunks[ci]};
                    clear_out();
                    run_hash(&j);
                    checks++;
                    if (!out_ok(oo, b2_expect[li][fam]))
                        fail("digest", b2_lens[li], off, chunks[ci], fam);
                }
            }
    /* RFC 7693 appendix E */
    m0c_blake2s_init(&ctx);
    m0c_blake2s_update(&ctx, (const uint8_t *)"abc", 3);
    clear_out();
    m0c_blake2s_final(&ctx, out_area + 4);
    checks++;
    if (!out_ok(0, b2_abc)) fail("abc", 3, 0, 0, 0);
}

/* ---- stack ---- */
static void stack_report(void) {
    unsigned worst_u = 0, worst_f = 0;
    static const unsigned ulens[] = {1, 63, 64, 65, 128, 4096};
    uint32_t s;
    s = stack_call3((void *)m0c_blake2s_init, &ctx, 0, 0);
    put_s("STACK,init,0,"); put_u(s); put_s("\n");
    fill_message(msg, 2, B2_MAX_LEN);
    for (unsigned i = 0; i < 6; i++) {
        m0c_blake2s_init(&ctx);
        s = stack_call3((void *)m0c_blake2s_update, &ctx, msg, (const void *)(uintptr_t)ulens[i]);
        put_s("STACK,update,"); put_u(ulens[i]); put_comma(); put_u(s); put_s("\n");
        if (s > worst_u) worst_u = s;
        m0c_blake2s_final(&ctx, out_area);
    }
    static const unsigned flens[] = {0, 1, 63, 64, 65, 4096};
    for (unsigned i = 0; i < 6; i++) {
        m0c_blake2s_init(&ctx);
        if (flens[i]) m0c_blake2s_update(&ctx, msg, flens[i]);
        s = stack_call3((void *)m0c_blake2s_final, &ctx, out_area, 0);
        put_s("STACK,final,"); put_u(flens[i]); put_comma(); put_u(s); put_s("\n");
        if (s > worst_f) worst_f = s;
    }
    put_s("STACKMAX,update,"); put_u(worst_u); put_s("\n");
    put_s("STACKMAX,final,"); put_u(worst_f); put_s("\n");
}

/* ---- timing ---- */
static void note(const struct series *s) { if (s->invalid) invalid++; }

static void time_init(struct series *s) {
    for (unsigned r = 0; r < REPS; r++)
        series_add(s, r, time_call3((void *)m0c_blake2s_init, &ctx, 0, 0), overhead);
    series_finish(s); note(s);
}

/* One update of len bytes; the digest is completed and checked after each timed run. */
static void time_update(unsigned li, unsigned off, unsigned fam, struct series *s) {
    for (unsigned r = 0; r < REPS; r++) {
        m0c_blake2s_init(&ctx);
        uint32_t raw = time_call3((void *)m0c_blake2s_update, &ctx, msg + off,
                                  (const void *)(uintptr_t)b2_lens[li]);
        clear_out();
        m0c_blake2s_final(&ctx, out_area + 4);
        series_add(s, r, raw, overhead);
        checks++;
        if (!out_ok(0, b2_expect[li][fam])) fail("update", b2_lens[li], off, 0, fam);
    }
    series_finish(s); note(s);
}

static void time_final(unsigned li, unsigned off, unsigned fam, struct series *s) {
    for (unsigned r = 0; r < REPS; r++) {
        m0c_blake2s_init(&ctx);
        if (b2_lens[li]) m0c_blake2s_update(&ctx, msg + off, b2_lens[li]);
        clear_out();
        uint32_t raw = time_call3((void *)m0c_blake2s_final, &ctx, out_area + 4, 0);
        series_add(s, r, raw, overhead);
        checks++;
        if (!out_ok(0, b2_expect[li][fam])) fail("final", b2_lens[li], off, 0, fam);
    }
    series_finish(s); note(s);
}

static void time_total(unsigned li, unsigned off, unsigned chunk, unsigned fam, struct series *s) {
    struct job j = {msg + off, out_area + 4, b2_lens[li], chunk};
    for (unsigned r = 0; r < REPS; r++) {
        clear_out();
        uint32_t raw = time_call3((void *)run_hash, &j, 0, 0);
        series_add(s, r, raw, overhead);
        checks++;
        if (!out_ok(0, b2_expect[li][fam])) fail("total", b2_lens[li], off, chunk, fam);
    }
    series_finish(s); note(s);
}

static void row_mm(const struct series *s) { put_comma(); put_u(s->min); put_comma(); put_u(s->max); }

int main(void) {
    bench_status = 0;
    put_s("m0-crypto BLAKE2s board bench (released object m0crypto_blake2s.o)\n");
    gate();
    put_s(failures ? "GATE: FAIL " : "GATE: PASS "); put_u(checks); put_s(" checks\n");
    if (failures) { bench_status = 2; put_s("RESULT: FAIL\n"); return 1; }
    checks = 0;

    stack_report();

    timer_start();
    overhead = timer_overhead();
    put_s("OVERHEAD,"); put_u(overhead); put_s("\n");
    put_s("# INIT,min,max | UPDATE,len,off,min,max | FINAL,len,min,max | "
          "TOTAL,len,off,chunk,min,max | DATAVAR,len,off,family,upd_min,upd_max,fin_min,fin_max,"
          "tot0_min,tot0_max,tot17_min,tot17_max\n");

    struct series s;
    s.invalid = 0;
    time_init(&s);
    put_s("INIT"); row_mm(&s); put_s("\n");

    static const unsigned totals[] = {0, 64, 17};
    for (unsigned li = 0; li < B2_NLENS; li++) {
        for (unsigned off = 0; off <= MAXOFF; off++) {
            prep(li, off, 2);
            s.invalid = 0; time_update(li, off, 2, &s);
            put_s("UPDATE,"); put_u(b2_lens[li]); put_comma(); put_u(off); row_mm(&s); put_s("\n");
            for (unsigned ci = 0; ci < 3; ci++) {
                s.invalid = 0; time_total(li, off, totals[ci], 2, &s);
                put_s("TOTAL,"); put_u(b2_lens[li]); put_comma(); put_u(off);
                put_comma(); put_u(totals[ci]); row_mm(&s); put_s("\n");
            }
        }
        prep(li, 0, 2);
        s.invalid = 0; time_final(li, 0, 2, &s);
        put_s("FINAL,"); put_u(b2_lens[li]); row_mm(&s); put_s("\n");
    }

    for (unsigned li = 0; li < B2_NLENS; li++)
        for (unsigned off = 0; off <= 1; off++)
            for (unsigned fam = 0; fam < B2_NFAMILIES; fam++) {
                struct series u, f, t0, t17;
                u.invalid = f.invalid = t0.invalid = t17.invalid = 0;
                prep(li, off, fam);
                time_update(li, off, fam, &u);
                time_final(li, off, fam, &f);
                time_total(li, off, 0, fam, &t0);
                time_total(li, off, 17, fam, &t17);
                put_s("DATAVAR,"); put_u(b2_lens[li]); put_comma(); put_u(off);
                put_comma(); put_u(fam);
                row_mm(&u); row_mm(&f); row_mm(&t0); row_mm(&t17); put_s("\n");
            }

    SYST_CSR = 5;
    if (failures) {
        bench_status = 2; put_s("RESULT: FAIL digest during timing\n"); return 1;
    }
    if (invalid) {
        bench_status = 3; put_s("RESULT: FAIL timer\n"); return 1;
    }
    put_s("TIMED_CHECKS,"); put_u(checks); put_s("\n");
    bench_status = 1;
    put_s("RESULT: PASS\n");
    return 0;
}
