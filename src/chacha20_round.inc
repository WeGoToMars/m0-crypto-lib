/*
 * ChaCha20 round macros shared by the library (src/chacha20.S) and the proof
 * fixture in fixtures/chacha20_dround_v2.S.
 * SPDX-License-Identifier: MIT
 *
 * Convention: state words x[0..15] at [sp, #0..#60]; r4-r7 = 16, 20, 24, 25
 * (RORS counts for <<< 16, 12, 8, 7); r0-r3 and flags are clobbered.
 */
/* Pieces of QUARTERROUND(x[a], x[b], x[c], x[d]) on stack words. */
.macro LOAD3 a, b, c
    ldr  r0, [sp, #4*\a]
    ldr  r1, [sp, #4*\b]
    ldr  r2, [sp, #4*\c]
.endm
.macro STORE3 a, b, c
    str  r0, [sp, #4*\a]
    str  r1, [sp, #4*\b]
    str  r2, [sp, #4*\c]
.endm
.macro CORE
    adds r0, r0, r1     /* a += b          */
    eors r3, r0         /* d ^= a          */
    rors r3, r4         /* d <<<= 16       */
    adds r2, r2, r3     /* c += d          */
    eors r1, r2         /* b ^= c          */
    rors r1, r5         /* b <<<= 12       */
    adds r0, r0, r1     /* a += b          */
    eors r3, r0         /* d ^= a          */
    rors r3, r6         /* d <<<= 8        */
    adds r2, r2, r3     /* c += d          */
    eors r1, r2         /* b ^= c          */
    rors r1, r7         /* b <<<= 7        */
.endm

/* Full quarter round: load a, b, c, d; core; store a, b, c, d. */
.macro QR a, b, c, d
    LOAD3 \a, \b, \c
    ldr  r3, [sp, #4*\d]
    CORE
    STORE3 \a, \b, \c
    str  r3, [sp, #4*\d]
.endm

/* As QR, but x[d] stays in r3 instead of being stored. */
.macro QR_KEEP_D a, b, c, d
    LOAD3 \a, \b, \c
    ldr  r3, [sp, #4*\d]
    CORE
    STORE3 \a, \b, \c
.endm

/* As QR, but x[d] is already in r3 instead of being loaded. */
.macro QR_HAVE_D a, b, c, d
    LOAD3 \a, \b, \c
    CORE
    STORE3 \a, \b, \c
    str  r3, [sp, #4*\d]
.endm

/* Double round, version 2 schedule (x[15] stays in r3 across the boundary).
 * Proved as m0c_chacha20_dround_v2_frag in the proofs repository. */
.macro DOUBLE_ROUND
    /* column round */
    QR 0, 4,  8, 12
    QR 1, 5,  9, 13
    QR 2, 6, 10, 14
    QR_KEEP_D 3, 7, 11, 15
    /* diagonal round */
    QR_HAVE_D 0, 5, 10, 15
    QR 1, 6, 11, 12
    QR 2, 7,  8, 13
    QR 3, 4,  9, 14
.endm

/* Library schedule: d row in r8-r11 throughout all ten double rounds.
 * r0 carries a across each half-round boundary; r12 is the public loop count.
 * The fixture above continues to use the byte-identical DOUBLE_ROUND.
 * At the loop boundary x[2] is in r0 (its stack slot is stale); all other a/b/c
 * words are on stack. r4-r7 retain the four rotation counts.
 */
.macro QR_REG_D a, b, c, dreg, have_a=0, keep_a=0
    .if !\have_a
    ldr  r0, [sp, #4*\a]
    .endif
    ldr  r1, [sp, #4*\b]
    ldr  r2, [sp, #4*\c]
    mov  r3, \dreg
    CORE
    .if !\keep_a
    str  r0, [sp, #4*\a]
    .endif
    str  r1, [sp, #4*\b]
    str  r2, [sp, #4*\c]
    mov  \dreg, r3
.endm

.macro DOUBLE_ROUND_REG_D
    QR_REG_D 2, 6, 10, r10, 1
    QR_REG_D 0, 4,  8, r8
    QR_REG_D 1, 5,  9, r9
    QR_REG_D 3, 7, 11, r11, 0, 1
    QR_REG_D 3, 4,  9, r10, 1
    QR_REG_D 0, 5, 10, r11
    QR_REG_D 1, 6, 11, r8
    QR_REG_D 2, 7,  8, r9, 0, 1
.endm
