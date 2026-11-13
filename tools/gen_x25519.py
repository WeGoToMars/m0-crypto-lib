#!/usr/bin/env python3
"""Generate src/x25519.S, the Cortex-M0+ assembly of the X25519 release asset.

    python3 -I tools/gen_x25519.py [OUT]     (default: src/x25519.S next to this tools/)

src/x25519.S is checked in; proofs/tools/check.sh regenerates it and compares. It is
assembled only inside the release unit src/m0crypto_x25519.S, whose .text bytes the Lean
proofs in proofs/ are bound to: a change to the emitted instructions is a new artifact.

One relocation-free unit with one global entry, m0c_x25519 (RFC 7748, C ABI), and
three internal routines it calls one level deep: m0c_fe_mul, m0c_fe_sqr and
m0c_fe_mulc_add. Addition, subtraction, selection and canonical reduction are
straight-line bodies instantiated inline.

Field elements are 8 little-endian 32-bit words; any value < 2^256 is accepted and
produced (not canonical), p = 2^255 - 19.

Internal ABI of the three routines: r0 = dst, r1 = a, r2 = b; r0-r12 are scratch
(m0c_x25519 saves and restores r4-r11); dst may equal a or b.

Instruction forms are limited to those of the project's Thumb model plus SBCS:
no ASRS, no register shifts except RORS, no BX, no MOV from SP, no LR as data.
"""
import pathlib
import sys


class G:
    def __init__(self):
        self.lines = []
        self.n = 0

    def __call__(self, *ins):
        for i in ins:
            self.lines.append('\t' + i)

    def raw(self, s):
        self.lines.append(s)

    def label(self, name):
        self.lines.append(f'{name}:')

    def local(self, stem):
        self.n += 1
        return f'.L{stem}{self.n}'

    def func(self, name, glob=False):
        self.raw('')
        self.raw('\t.p2align 1')
        if glob:
            self.raw(f'\t.global {name}')
        self.raw(f'\t.type {name}, %function')
        self.raw('\t.thumb_func')
        self.label(name)

    def endfunc(self, name):
        self.raw(f'\t.size {name}, .-{name}')


# ---------------------------------------------------------------------------
# 32/64-bit kernels
# ---------------------------------------------------------------------------

def mul32(g, rl, rh, rb, rt, ru):
    """rl:rh = rl * rb (rb destroyed, rt/ru scratch). 17 cycles."""
    g(f'lsrs {rt}, {rb}, #16', f'lsrs {rh}, {rl}, #16', f'muls {rh}, {rt}',
      f'uxth {rb}, {rb}', f'lsrs {ru}, {rl}, #16', f'uxth {rl}, {rl}',
      f'muls {rt}, {rl}', f'muls {ru}, {rb}', f'muls {rl}, {rb}',
      f'lsrs {rb}, {rt}, #16', f'lsls {rt}, {rt}, #16',
      f'adds {rl}, {rt}', f'adcs {rh}, {rb}',
      f'lsrs {rb}, {ru}, #16', f'lsls {ru}, {ru}, #16',
      f'adds {rl}, {ru}', f'adcs {rh}, {rb}')


def mul64(g, a0, a1, b0, b1, t1, t2, t3, t4, h1, h2):
    """(a0,a1)*(b0,b1) -> (a0,b0,a1,b1) little-endian. 81 cycles."""
    g(f'mov {h1}, {b0}', f'mov {h2}, {b1}',
      f'subs {t1}, {a1}, {a0}', f'sbcs {t3}, {t3}', f'eors {t1}, {t3}', f'subs {t1}, {t3}',
      f'subs {t4}, {b0}, {b1}', f'sbcs {b1}, {b1}', f'eors {t4}, {b1}', f'subs {t4}, {b1}',
      f'eors {t3}, {b1}')
    mul32(g, t1, t2, t4, b0, b1)
    g(f'eors {t1}, {t3}', f'eors {t2}, {t3}', f'mov {t4}, {h1}', f'mov {h1}, {t1}')
    mul32(g, a0, b0, t4, t1, b1)
    g(f'mov {t4}, {h2}', f'mov {h2}, {t2}')
    mul32(g, a1, b1, t4, t1, t2)
    g(f'mov {t1}, {h1}', f'mov {t2}, {h2}', f'lsrs {t4}, {t3}, #1', f'movs {t4}, #0',
      f'adcs {t1}, {a0}', f'adcs {t2}, {b0}', f'adcs {t3}, {t4}',
      f'adds {t1}, {a1}', f'adcs {t2}, {b1}', f'adcs {t3}, {t4}',
      f'adds {b0}, {t1}', f'adcs {a1}, {t2}', f'adcs {b1}, {t3}')


def sqr32(g, rl, rh, rt, ru):
    """rl:rh = rl^2. 10 cycles."""
    g(f'lsrs {rh}, {rl}, #16', f'uxth {rl}, {rl}', f'movs {rt}, {rh}',
      f'muls {rt}, {rl}', f'muls {rh}, {rh}', f'muls {rl}, {rl}',
      f'lsls {ru}, {rt}, #17', f'lsrs {rt}, {rt}, #15',
      f'adds {rl}, {ru}', f'adcs {rh}, {rt}')


def sqr64(g, a0, a1, o1, o3, t1, t2, t3, t4):
    """(a0,a1)^2 -> (a0,o1,a1,o3). 44 cycles."""
    g(f'subs {t1}, {a1}, {a0}', f'sbcs {t2}, {t2}', f'eors {t1}, {t2}', f'subs {t1}, {t2}')
    sqr32(g, t1, t2, t3, t4)
    sqr32(g, a0, o1, t3, t4)
    sqr32(g, a1, o3, t3, t4)
    g(f'subs {t1}, {a0}', f'sbcs {t2}, {o1}', f'sbcs {t3}, {t3}',
      f'adds {o1}, {a1}', f'adcs {a1}, {o3}', f'movs {t4}, #0', f'adcs {o3}, {t4}',
      f'subs {o1}, {t1}', f'sbcs {a1}, {t2}', f'sbcs {o3}, {t3}')


# ---------------------------------------------------------------------------
# 128-bit level. Entry: r1 = pA, r2 = pB (mul). Output 8 words at sp+o.
# Clobbers r0-r8, r10-r12.
# ---------------------------------------------------------------------------

def mul128(g, o, direct=False):
    g('mov r12, r1', 'mov r11, r2', 'ldm r1!, {r4, r6}', 'ldm r2!, {r5, r7}')
    mul64(g, 'r4', 'r6', 'r5', 'r7', 'r0', 'r1', 'r2', 'r3', 'r8', 'r10')
    g(f'add r0, sp, #{o}', 'stm r0!, {r4-r7}',
      'mov r0, r12', 'ldr r4, [r0, #8]', 'ldr r6, [r0, #12]',
      'mov r1, r11', 'ldr r5, [r1, #8]', 'ldr r7, [r1, #12]')
    mul64(g, 'r4', 'r6', 'r5', 'r7', 'r0', 'r1', 'r2', 'r3', 'r8', 'r10')
    g(f'add r0, sp, #{o + 16}', 'stm r0!, {r4-r7}',
      # |A0 - A1|, mask ma = -1 iff A0 < A1
      'mov r7, r12', 'ldm r7!, {r0, r2, r5, r6}',
      'subs r0, r5', 'sbcs r2, r6', 'sbcs r5, r5',
      'eors r0, r5', 'eors r2, r5', 'subs r0, r5', 'sbcs r2, r5',
      # |B0 - B1|, mask mb
      'mov r4, r11', 'ldm r4, {r1, r3, r4, r6}',
      'subs r1, r4', 'sbcs r3, r6', 'sbcs r6, r6',
      'eors r1, r6', 'eors r3, r6', 'subs r1, r6', 'sbcs r3, r6',
      # n = ~(ma ^ mb): -1 when the middle product must be subtracted
      'eors r6, r5', 'mvns r6, r6', 'mov r12, r6')
    mul64(g, 'r0', 'r2', 'r1', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r10')
    g('mov r4, r12')
    combine128(g, o, direct=direct)


def sqr128(g, o, direct=False):
    g('mov r12, r1', 'ldm r1!, {r4, r6}')
    sqr64(g, 'r4', 'r6', 'r5', 'r7', 'r0', 'r1', 'r2', 'r3')
    g(f'add r0, sp, #{o}', 'stm r0!, {r4, r5}', 'mov r8, r6', 'mov r10, r7',
      'mov r1, r12', 'ldr r4, [r1, #8]', 'ldr r6, [r1, #12]')
    sqr64(g, 'r4', 'r6', 'r5', 'r7', 'r0', 'r1', 'r2', 'r3')
    g(f'add r0, sp, #{o + 24}', 'stm r0!, {r6,r7}',
      'mov r7, r12', 'mov r11, r4', 'mov r12, r5', 'ldm r7!, {r0, r2, r5, r6}',
      'subs r0, r5', 'sbcs r2, r6', 'sbcs r5, r5',
      'eors r0, r5', 'eors r2, r5', 'subs r0, r5', 'sbcs r2, r5')
    sqr64(g, 'r0', 'r2', 'r1', 'r3', 'r4', 'r5', 'r6', 'r7')
    combine128(g, o, square=True, direct=direct)


def combine128(g, o, square=False, direct=False):
    """Combine; square retains L2/L3/H0/H1 in r8/r10/r11/r12, sign -1.

    direct=True leaves P2/P3 in r0/r1 for the 256-bit combine instead of
    storing them. P0/P1 and P4..P7 have their normal stack positions.
    """
    if square:
        g('mvns r0, r0','mvns r1, r1','mvns r2, r2','mvns r3, r3',
          f'add r7, sp, #{o}','cmp r0, r0')
    else:
        g('eors r0, r4','eors r1, r4','eors r2, r4','eors r3, r4',
          f'add r7, sp, #{o}','lsrs r5, r4, #1')
    g('ldm r7!, {r5, r6}','adcs r0, r5','adcs r1, r6')
    if square:
        g('mov r5, r8','mov r6, r10','adcs r2, r5','adcs r3, r6','sbcs r4, r4')
    else:
        g('ldm r7!, {r5, r6}','adcs r2, r5','adcs r3, r6','movs r5, #0','adcs r4, r5')
    if square:
        g('mov r5, r11', 'mov r6, r12')
    else:
        g('ldm r7!, {r5, r6}')
    g('adds r0, r5','adcs r1, r6')
    if square:
        g(f'add r7, sp, #{o+24}')
    g('ldm r7!, {r5, r6}','adcs r2, r5','adcs r3, r6','movs r5, #0','adcs r4, r5',
      'subs r7, #24')
    if square:
        g('mov r5, r8','mov r6, r10',f'add r7, sp, #{o+24}','adds r0, r5','adcs r1, r6')
    else:
        g('ldm r7!, {r5, r6}','adds r0, r5','adcs r1, r6')
    if square:
        g('mov r5, r11', 'mov r6, r12')
    else:
        g('ldm r7!, {r5, r6}')
    g('adcs r2, r5','adcs r3, r6',
      'ldm r7!, {r5, r6}','adcs r4, r5','movs r5, #0','adcs r5, r6',
      ('subs r7, #16' if direct else 'subs r7, #24'),
      ('stm r7!, {r2-r5}' if direct else 'stm r7!, {r0-r5}'))


# ---------------------------------------------------------------------------
# 256-bit level: product into sp+0 (16 words), then reduce into dst.
# Frame (bytes): PROD 0..63 (L = 0, H = 32), P 64..95, DA 96, DB 112,
# N 128, DST 132, A 136, B 140; size 144.
# ---------------------------------------------------------------------------
OP, OH, OPP, ODA, ODB, ON, ODST, OA, OB = 0, 32, 64, 96, 112, 128, 132, 136, 140
FRAME = 144


def diff256(g, ptr_off, out_off):
    """|X0 - X1| for X at [sp+ptr_off] -> 4 words at sp+out_off; mask in r0."""
    g(f'ldr r0, [sp, #{ptr_off}]', 'ldm r0!, {r4-r7}', 'ldm r0, {r0-r3}',
      'subs r4, r0', 'sbcs r5, r1', 'sbcs r6, r2', 'sbcs r7, r3', 'sbcs r0, r0',
      'eors r4, r0', 'eors r5, r0', 'eors r6, r0', 'eors r7, r0',
      'subs r4, r0', 'sbcs r5, r0', 'sbcs r6, r0', 'sbcs r7, r0',
      f'add r1, sp, #{out_off}', 'stm r1!, {r4-r7}')


def combine_reduce(g, sq):
    """Fused 256-level Karatsuba combine + reduction mod 2^255-19.

    L = sp+0, H = sp+32, P = sp+64 (8 words each); n at sp+ON (mul) or n = -1 (sqr).
    Y = L + H + (P^n) + (n&1) (9 words, Y8 small). Then
      F38 = H + (Y >> 128), F1 = L + 2^128 (Y mod 2^128), R = F1 + 38 F38.
    F38_0..3 is stored over H0..3; Y8 + carry is folded as 38*s into R_4;
    F1_4..7 terms (Y0..3, parked in r8,r10,r11,r12) join the reduction carry chain.
    """
    def xor_n(nreg):
        if sq:
            g('mvns r0, r0', 'mvns r1, r1', 'mvns r2, r2', 'mvns r3, r3')
        else:
            g(f'ldr {nreg}, [sp, #{ON}]', f'eors r0, {nreg}', f'eors r1, {nreg}', f'eors r2, {nreg}',
              f'eors r3, {nreg}')
    # Phase A: Y0..3 -> r8, r10, r11, r12 ; carry count -> r4
    # The last 128-bit combine keeps P2/P3 in r0/r1; P4..7 are stored.
    g('mov r3, r1', 'mov r2, r0', f'add r7, sp, #{OPP}', 'ldm r7!, {r0,r1}')
    xor_n('r4')
    g('cmp r0, r0' if sq else 'lsrs r4, r4, #1',
      'add r7, sp, #0',
      'ldm r7!, {r5, r6}', 'adcs r0, r5', 'adcs r1, r6',
      'ldm r7!, {r5, r6}', 'adcs r2, r5', 'adcs r3, r6',
      'movs r4, #0', 'adcs r4, r4',
      f'add r7, sp, #{OH}',
      'ldm r7!, {r5, r6}', 'adds r0, r5', 'adcs r1, r6',
      'ldm r7!, {r5, r6}', 'adcs r2, r5', 'adcs r3, r6',
      'movs r5, #0', 'adcs r4, r5',
      'mov r8, r0', 'mov r10, r1', 'mov r11, r2', 'mov r12, r3')
    # Phase B: Y4..7 -> r0..r3, Y8 -> r6
    g(f'add r7, sp, #{OPP + 16}', 'ldm r7!, {r0-r3}')
    if sq:
        g('mvns r0, r0', 'mvns r1, r1', 'mvns r2, r2', 'mvns r3, r3', 'movs r6, #0', 'mvns r6, r6')
    else:
        xor_n('r6')
    g('movs r5, #0', 'adds r0, r4', 'adcs r1, r5', 'adcs r2, r5', 'adcs r3, r5', 'adcs r6, r5',
      f'add r7, sp, #{OP + 16}',
      'ldm r7!, {r4, r5}', 'adds r0, r4', 'adcs r1, r5',
      'ldm r7!, {r4, r5}', 'adcs r2, r4', 'adcs r3, r5',
      'movs r4, #0', 'adcs r6, r4',
      f'add r7, sp, #{OH + 16}',
      'ldm r7!, {r4, r5}', 'adds r0, r4', 'adcs r1, r5',
      'ldm r7!, {r4, r5}', 'adcs r2, r4', 'adcs r3, r5',
      'movs r4, #0', 'adcs r6, r4')
    # Phase C: F38_0..3 = H0..3 + Y4..7 -> sp+OH ; s = Y8 + carry -> r9
    g(f'add r7, sp, #{OH}',
      'ldm r7!, {r4, r5}', 'adds r0, r4', 'adcs r1, r5',
      'ldm r7!, {r4, r5}', 'adcs r2, r4', 'adcs r3, r5',
      'movs r4, #0', 'adcs r6, r4', 'mov r9, r6',
      'subs r7, #16', 'stm r7!, {r0-r3}')
    # Reduction. Top word first: v = L7 + Y3 + 38*H7 ; q = v >> 31 ; base7 = v mod 2^31
    g(f'ldr r4, [sp, #{OH + 28}]', f'ldr r5, [sp, #{OP + 28}]', 'movs r7, #38', 'movs r2, #0',
      'uxth r6, r4', 'lsrs r4, r4, #16', 'muls r6, r7', 'muls r4, r7',
      'lsls r3, r4, #16', 'lsrs r4, r4, #16',
      'adds r5, r6', 'adcs r4, r2', 'adds r5, r3', 'adcs r4, r2',
      'mov r3, r12', 'adds r5, r3', 'adcs r4, r2',
      'lsls r4, r4, #1', 'lsrs r3, r5, #31', 'adds r4, r3',
      'lsls r5, r5, #1', 'lsrs r5, r5, #1', 'mov r12, r5',
      'movs r3, #19', 'muls r4, r3',
      f'ldr r0, [sp, #{ODST}]')
    k = 'r4'
    free = ['r1', 'r3', 'r5', 'r6']
    ys = {4: 'r8', 5: 'r10', 6: 'r11'}
    for i in range(7):
        h, l, t, u = free
        g(f'ldr {h}, [sp, #{OH + 4 * i}]', f'ldr {l}, [sp, #{OP + 4 * i}]',
          f'uxth {t}, {h}', f'lsrs {h}, {h}, #16', f'muls {t}, r7', f'muls {h}, r7')
        if i == 4:
            g(f'mov {u}, r9', f'muls {u}, r7', f'adds {k}, {u}')
        g(f'adds {t}, {k}', f'lsls {u}, {h}, #16', f'lsrs {h}, {h}, #16',
          f'adds {l}, {t}', f'adcs {h}, r2', f'adds {l}, {u}', f'adcs {h}, r2')
        if i in ys:
            g(f'mov {u}, {ys[i]}', f'adds {l}, {u}', f'adcs {h}, r2')
        g(f'str {l}, [r0, #{4 * i}]')
        free = [k, l, t, u]
        k = h
    g('mov r2, r12', f'adds r2, {k}', 'str r2, [r0, #28]')


def emit_fe_mul(g):
    name = 'm0c_fe_mul'
    g.func(name)
    g('push {lr}', f'sub sp, #{FRAME}', f'str r0, [sp, #{ODST}]', f'str r1, [sp, #{OA}]',
      f'str r2, [sp, #{OB}]')
    mul128(g, OP)
    g(f'ldr r1, [sp, #{OA}]')
    g('adds r1, #16', f'ldr r2, [sp, #{OB}]', 'adds r2, #16')
    mul128(g, OH)
    diff256(g, OA, ODA)
    g('mov r8, r0')
    diff256(g, OB, ODB)
    g('mov r1, r8', 'eors r0, r1', 'mvns r0, r0', f'str r0, [sp, #{ON}]',
      f'add r1, sp, #{ODA}', f'add r2, sp, #{ODB}')
    mul128(g, OPP, direct=True)
    combine_reduce(g, False)
    g(f'add sp, #{FRAME}', 'pop {pc}')
    g.endfunc(name)


def emit_fe_sqr(g):
    name = 'm0c_fe_sqr'
    g.func(name)
    g('push {lr}', f'sub sp, #{FRAME}', f'str r0, [sp, #{ODST}]', f'str r1, [sp, #{OA}]')
    sqr128(g, OP)
    g(f'ldr r1, [sp, #{OA}]', 'adds r1, #16')
    sqr128(g, OH)
    diff256(g, OA, ODA)
    g(f'add r1, sp, #{ODA}')
    sqr128(g, OPP, direct=True)
    combine_reduce(g, True)
    g(f'add sp, #{FRAME}', 'pop {pc}')
    g.endfunc(name)


# ---------------------------------------------------------------------------
# add / sub / select: straight-line bodies, instantiated inline at each use.
# Entry: r0 = dst, r1 = a, r2 = b. All of a and b is read before dst is written
# (add, sub), so dst may alias either input.
# ---------------------------------------------------------------------------

def fe_add_body(g):
    g('ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'adds r3, r5', 'adcs r4, r6',
      'mov r8, r3', 'mov r10, r4',
      'ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'adcs r3, r5', 'adcs r4, r6',
      'mov r11, r3', 'mov r12, r4',
      'ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'adcs r3, r5', 'adcs r4, r6',
      'ldm r1!, {r5, r6}', 'ldm r2, {r1, r2}', 'adcs r5, r1', 'adcs r6, r2',
      # q = 2*carry + bit255 ; clear bit 255 ; add 19q
      'movs r7, #0', 'adcs r7, r7', 'lsls r7, r7, #1', 'lsrs r1, r6, #31', 'adds r7, r1',
      'lsls r6, r6, #1', 'lsrs r6, r6, #1', 'movs r1, #19', 'muls r7, r1',
      'mov r1, r8', 'mov r2, r10', 'adds r1, r7', 'movs r7, #0', 'adcs r2, r7',
      'stm r0!, {r1, r2}', 'mov r1, r11', 'mov r2, r12',
      'adcs r1, r7', 'adcs r2, r7', 'adcs r3, r7', 'adcs r4, r7', 'adcs r5, r7', 'adcs r6, r7',
      'stm r0!, {r1-r6}')


def fe_sub_body(g):
    g('ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'subs r3, r5', 'sbcs r4, r6',
      'mov r8, r3', 'mov r10, r4',
      'ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'sbcs r3, r5', 'sbcs r4, r6',
      'mov r11, r3', 'mov r12, r4',
      'ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'sbcs r3, r5', 'sbcs r4, r6',
      'ldm r1!, {r5, r6}', 'ldm r2, {r1, r2}', 'sbcs r5, r1', 'sbcs r6, r2',
      # true = d_lo + 2^255*x, x = bit255 - 2*borrow in [-2, 1].
      # result = d_lo + 2^255 - 19*(1 - x) ; r7 = 1 - x = (1 - bit255) + 2*borrow >= 0
      'sbcs r7, r7', 'lsls r7, r7, #1', 'mvns r1, r6', 'lsrs r1, r1, #31', 'subs r7, r1, r7',
      'movs r1, #1', 'lsls r1, r1, #31', 'orrs r6, r1', 'movs r1, #19', 'muls r7, r1',
      'mov r1, r8', 'mov r2, r10', 'subs r1, r7', 'movs r7, #0', 'sbcs r2, r7',
      'stm r0!, {r1, r2}', 'mov r1, r11', 'mov r2, r12',
      'sbcs r1, r7', 'sbcs r2, r7', 'sbcs r3, r7', 'sbcs r4, r7', 'sbcs r5, r7', 'sbcs r6, r7',
      'stm r0!, {r1-r6}')


def select_words(g):
    """dst = mask ? b : a; r7 is a 0/-1 mask and is left unchanged.

    Reads and writes four word pairs in order: dst may equal a or b, or be disjoint.
    """
    for _ in range(4):
        g('ldm r1!, {r3, r4}', 'ldm r2!, {r5, r6}', 'eors r5, r3', 'eors r6, r4',
          'ands r5, r7', 'ands r6, r7', 'eors r3, r5', 'eors r4, r6', 'stm r0!, {r3, r4}')


def canon_body(g):
    """Canonical reduction in place: r0 = a (8 words, < 2^256) -> a mod p.

    r2 is zero, r3 is 19, r4 is the fold amount; r0 is unchanged.
    """
    g('movs r2, #0', 'movs r3, #19')

    def add_c(c, store):
        g('ldr r1, [r0, #0]', f'adds r1, {c}')
        if store:
            g('str r1, [r0, #0]')
        for i in range(1, 8):
            g(f'ldr r1, [r0, #{4 * i}]', 'adcs r1, r2')
            if store:
                g(f'str r1, [r0, #{4 * i}]')

    g('ldr r1, [r0, #28]', 'lsrs r4, r1, #31', 'lsls r1, r1, #1', 'lsrs r1, r1, #1',
      'str r1, [r0, #28]', 'muls r4, r3')
    add_c('r4', True)
    add_c('r3', False)
    g('lsrs r4, r1, #31', 'muls r4, r3')
    add_c('r4', True)
    g('lsls r1, r1, #1', 'lsrs r1, r1, #1', 'str r1, [r0, #28]')


def emit_fe_mulc_add(g):
    """dst = 121666*a + b; r0 = dst, r1 = a, r2 = b. dst may equal a or b.

    r1/r2 retain a/b, r6 is zero, r7 is 60833, r12 retains dst. The remaining
    four low registers rotate the carry and three word temporaries.
    """
    name = 'm0c_fe_mulc_add'
    g.func(name)
    g('push {lr}', 'mov r12, r0', 'ldr r7, =60833', 'movs r6, #0')

    def word(i, k, regs):
        a, t, u = regs
        g(f'ldr {a}, [r1, #{4*i}]', f'uxth {t}, {a}', f'lsrs {a}, {a}, #16',
          f'muls {t}, r7', f'muls {a}, r7', f'lsls {u}, {a}, #17', f'lsrs {a}, {a}, #15',
          f'adds {t}, {t}', f'adcs {a}, r6', f'adds {t}, {u}', f'adcs {a}, r6',
          f'ldr {u}, [r2, #{4*i}]', f'adds {t}, {u}', f'adcs {a}, r6')
        if k is not None:
            g(f'adds {t}, {k}', f'adcs {a}, r6')
        return t, a

    lo, hi = word(7, None, ('r3', 'r4', 'r5'))
    g(f'lsls {hi}, {hi}, #1', f'lsrs r5, {lo}, #31', f'adds {hi}, r5',
      f'lsls {lo}, {lo}, #1', f'lsrs {lo}, {lo}, #1', 'mov r8, ' + lo,
      'movs r5, #19', f'muls {hi}, r5')
    k = hi
    free = [r for r in ('r0', 'r3', 'r4', 'r5') if r != k]
    for i in range(7):
        a, t, u = free
        lo, hi = word(i, k, free)
        g(f'mov {u}, r12', f'str {lo}, [{u}, #{4*i}]')
        free = [k, t, u]
        k = hi
    g('mov r1, r8', f'adds r1, {k}', 'mov r0, r12', 'str r1, [r0, #28]', 'pop {pc}')
    g.raw('\t.ltorg')
    g.endfunc(name)


# ---------------------------------------------------------------------------
# void m0c_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
#
# RFC 7748 X25519, C ABI, the only global symbol. The three buffers may be
# unaligned and may overlap in any way: both inputs are read completely before
# out is written. The only calls are m0c_fe_mul, m0c_fe_sqr and m0c_fe_mulc_add,
# all one level deep.
#
# Frame: nine field elements, the clamped scalar and three words.
# ---------------------------------------------------------------------------
PERSIST = ['X1', 'X2', 'Z2', 'X3', 'Z3']
S = {n: 32 * i for i, n in enumerate(PERSIST)}
TEMP_BASE = len(PERSIST)
S.update({n: 32 * (TEMP_BASE + i) for n, i in {'A': 0, 'B': 1, 'C': 2, 'D': 3,
                                               'DA': 3, 'CB': 2, 'AA': 0, 'BB': 1, 'E': 0, 'T': 2}.items()})
S.update(SA=S['X2'], SB=S['Z2'])
S_K = 32 * (TEMP_BASE + 4)             # clamped scalar, 8 words
LV_T = S_K + 32                        # ladder bit index, then squaring counter
LV_SWAP, LV_OUT = LV_T + 4, LV_T + 8
LFRAME = LV_T + 12
SAVED = 36                             # r4-r7, lr, then r8-r11
CALLEE_STACK = FRAME + 4               # deepest callee: m0c_fe_mul / m0c_fe_sqr
STACK_BYTES = SAVED + LFRAME + CALLEE_STACK
WIPE_WORDS = (LFRAME + CALLEE_STACK) // 4
assert LFRAME % 4 == 0 and WIPE_WORDS % 5 == 0 and LFRAME + CALLEE_STACK <= 508
LADDER_TOP, LADDER_LAST = 254, 3       # ladder steps for scalar bits 254..3


def validate_layout(ops, live_out):
    """Backward liveness check; an operation may overwrite its last-read input."""
    live = set(live_out)
    for dst, inputs in reversed(ops):
        for other in live - {dst}:
            assert S[dst] != S[other], (dst, other, 'write overlaps live value')
        live.discard(dst)
        live.update(inputs)
        offsets = [S[n] for n in live]
        assert len(offsets) == len(set(offsets)), ('overlapping live inputs', live)


def op(g, fn, d, a, b=None):
    """One field operation on frame slots: d = fn(a, b).

    add, sub and select are instantiated inline; select expects its mask in r7.
    """
    if getattr(g, 'liveness_ops', None) is not None:
        g.liveness_ops.append((d, [x for x in (a, b) if x is not None]))
    g(f'add r0, sp, #{S[d]}', f'add r1, sp, #{S[a]}')
    if b is not None:
        g(f'add r2, sp, #{S[b]}')
    if fn == 'add':
        fe_add_body(g)
    elif fn == 'sub':
        fe_sub_body(g)
    elif fn == 'select':
        select_words(g)
    else:
        assert fn in ('mul', 'sqr', 'mulc_add')
        g(f'bl m0c_fe_{fn}')


def dbl(g, x, z):
    """(x:z) = 2*(x:z), with the RFC 7748 formulas (a24*E + AA = 121666*E + BB)."""
    op(g, 'add', 'A', x, z)
    op(g, 'sub', 'B', x, z)
    op(g, 'sqr', 'AA', 'A')
    op(g, 'sqr', 'BB', 'B')
    op(g, 'mul', x, 'AA', 'BB')
    op(g, 'sub', 'E', 'AA', 'BB')
    op(g, 'mulc_add', 'T', 'E', 'BB')
    op(g, 'mul', z, 'E', 'T')


def load_le32(g, rd, rt, base, off):
    """rd = little-endian word at base + off, by four byte loads (any alignment)."""
    g(f'ldrb {rd}, [{base}, #{off}]')
    for i in (1, 2, 3):
        g(f'ldrb {rt}, [{base}, #{off + i}]', f'lsls {rt}, {rt}, #{8 * i}', f'orrs {rd}, {rt}')


# Inversion by Fermat's little theorem: z^(p-2), p - 2 = 2^255 - 21, with 254
# squarings and 11 multiplications. Each step is one call of m0c_fe_sqr or
# m0c_fe_mul on frame slots, or a counted loop around one m0c_fe_sqr call.
# (operation, destination, operands...). 'Z' is the input, 'DST' the output.
INV_CHAIN = [
    ('sqr', 'T0', 'Z', 1),       # 2
    ('sqr', 'T1', 'T0', 2),      # 8
    ('mul', 'T1', 'Z', 'T1'),    # 9
    ('mul', 'T0', 'T0', 'T1'),   # 11
    ('sqr', 'T2', 'T0', 1),      # 22
    ('mul', 'T1', 'T1', 'T2'),   # 2^5 - 1
    ('sqr', 'T2', 'T1', 5),
    ('mul', 'T1', 'T2', 'T1'),   # 2^10 - 1
    ('sqr', 'T2', 'T1', 10),
    ('mul', 'T2', 'T2', 'T1'),   # 2^20 - 1
    ('sqr', 'T3', 'T2', 20),
    ('mul', 'T2', 'T3', 'T2'),   # 2^40 - 1
    ('sqr', 'T2', 'T2', 10),
    ('mul', 'T1', 'T2', 'T1'),   # 2^50 - 1
    ('sqr', 'T2', 'T1', 50),
    ('mul', 'T2', 'T2', 'T1'),   # 2^100 - 1
    ('sqr', 'T3', 'T2', 100),
    ('mul', 'T2', 'T3', 'T2'),   # 2^200 - 1
    ('sqr', 'T2', 'T2', 50),
    ('mul', 'T1', 'T2', 'T1'),   # 2^250 - 1
    ('sqr', 'T1', 'T1', 5),      # 2^255 - 32
    ('mul', 'DST', 'T1', 'T0'),  # 2^255 - 21
]


def inv_chain_exponent():
    """Exponent computed by INV_CHAIN, checked against p - 2 at generation."""
    e = {'Z': 1}
    for step in INV_CHAIN:
        if step[0] == 'sqr':
            e[step[1]] = e[step[2]] << step[3]
        else:
            e[step[1]] = e[step[2]] + e[step[3]]
    return e['DST']


assert inv_chain_exponent() == 2**255 - 21
assert sum(s[3] for s in INV_CHAIN if s[0] == 'sqr') == 254
assert sum(1 for s in INV_CHAIN if s[0] == 'mul') == 11


def inv_chain(g, z, dst, live_out):
    """Frame slot dst = (slot z)^(p-2); temporaries A..D; counter in LV_T."""
    slot = {'T0': 'A', 'T1': 'B', 'T2': 'C', 'T3': 'D', 'Z': z, 'DST': dst}
    g.liveness_ops = []
    for step in INV_CHAIN:
        d, a = slot[step[1]], slot[step[2]]
        if step[0] == 'mul':
            op(g, 'mul', d, a, slot[step[3]])
            continue
        n = step[3]
        op(g, 'sqr', d, a)
        if n == 2:
            op(g, 'sqr', d, d)
        elif n > 2:
            lab = g.local('sqrn')
            g(f'movs r0, #{n - 1}', f'str r0, [sp, #{LV_T}]')
            g.label(lab)
            op(g, 'sqr', d, d)
            g(f'ldr r0, [sp, #{LV_T}]', 'subs r0, #1', f'str r0, [sp, #{LV_T}]', f'bne {lab}')
    validate_layout(g.liveness_ops, live_out)
    g.liveness_ops = None


def emit_x25519(g):
    name = 'm0c_x25519'
    g.func(name, glob=True)
    g('push {r4-r7, lr}', 'mov r4, r8', 'mov r5, r9', 'mov r6, r10', 'mov r7, r11',
      'push {r4-r7}', f'sub sp, #{LFRAME}', f'str r0, [sp, #{LV_OUT}]')
    # Clamped scalar -> K. Bits 0..2 and 255 clear, bit 254 set.
    for i in range(8):
        load_le32(g, 'r4', 'r3', 'r1', 4 * i)
        if i == 0:
            g('lsrs r4, r4, #3', 'lsls r4, r4, #3')
        if i == 7:
            g('lsls r4, r4, #2', 'lsrs r4, r4, #2', 'movs r3, #1', 'lsls r3, r3, #30',
              'orrs r4, r3')
        g(f'str r4, [sp, #{S_K + 4 * i}]')
    # u with bit 255 masked -> X1 and X3.
    for i in range(8):
        load_le32(g, 'r4', 'r3', 'r2', 4 * i)
        if i == 7:
            g('lsls r4, r4, #1', 'lsrs r4, r4, #1')
        g(f'str r4, [sp, #{S["X1"] + 4 * i}]', f'str r4, [sp, #{S["X3"] + 4 * i}]')
    # RFC 7748 initial state: X2 = 1, Z2 = 0, X3 = u, Z3 = 1, swap = 0.
    assert S['Z2'] == S['X2'] + 32
    g(f'add r3, sp, #{S["X2"]}', 'movs r4, #1', 'movs r5, #0', 'movs r6, #0', 'movs r7, #0',
      'stm r3!, {r4-r7}', 'movs r4, #0', 'stm r3!, {r4-r7}', 'stm r3!, {r4-r7}',
      'stm r3!, {r4-r7}',
      f'add r3, sp, #{S["Z3"]}', 'movs r4, #1', 'stm r3!, {r4-r7}', 'movs r4, #0',
      'stm r3!, {r4-r7}',
      f'str r4, [sp, #{LV_SWAP}]', f'movs r0, #{LADDER_TOP}', f'str r0, [sp, #{LV_T}]')
    # One RFC 7748 ladder step per scalar bit t = 254..3. The conditional swap is
    # applied to the sums and differences (SA/SB) instead of to the four inputs.
    g.liveness_ops = []
    loop = g.local('ladder')
    g.label(loop)
    op(g, 'add', 'A', 'X2', 'Z2')
    op(g, 'sub', 'B', 'X2', 'Z2')
    op(g, 'add', 'C', 'X3', 'Z3')
    op(g, 'sub', 'D', 'X3', 'Z3')
    # k_t = bit t of K; r7 = -(swap ^ k_t); swap = k_t.
    # Word offset 4 * (t >> 5) as (t >> 3) & 28: the mask bounds the index for the
    # constant-time checker (proof-plan remedy B), one instruction more per step.
    g(f'ldr r0, [sp, #{LV_T}]', 'lsrs r1, r0, #3', 'movs r2, #28', 'ands r1, r2',
      f'add r2, sp, #{S_K}',
      'ldr r1, [r2, r1]', 'rors r1, r0', 'movs r2, #1', 'ands r1, r2',
      f'ldr r7, [sp, #{LV_SWAP}]', f'str r1, [sp, #{LV_SWAP}]', 'eors r7, r1',
      'rsbs r7, r7, #0')
    op(g, 'select', 'SA', 'A', 'C')
    op(g, 'select', 'SB', 'B', 'D')
    op(g, 'mul', 'DA', 'D', 'A')
    op(g, 'mul', 'CB', 'C', 'B')
    op(g, 'add', 'X3', 'DA', 'CB')
    op(g, 'sqr', 'X3', 'X3')
    op(g, 'sub', 'Z3', 'DA', 'CB')
    op(g, 'sqr', 'Z3', 'Z3')
    op(g, 'mul', 'Z3', 'X1', 'Z3')
    op(g, 'sqr', 'AA', 'SA')
    op(g, 'sqr', 'BB', 'SB')
    op(g, 'mul', 'X2', 'AA', 'BB')
    op(g, 'sub', 'E', 'AA', 'BB')
    op(g, 'mulc_add', 'T', 'E', 'BB')
    op(g, 'mul', 'Z2', 'E', 'T')
    validate_layout(g.liveness_ops, PERSIST)
    g.liveness_ops = None
    g(f'ldr r0, [sp, #{LV_T}]', 'subs r0, #1', f'str r0, [sp, #{LV_T}]',
      f'cmp r0, #{LADDER_LAST}', f'blt {loop}_end', f'b {loop}')
    g.label(f'{loop}_end')
    # Bits 2..0 are zero: the swap pending from bit 3 is applied once, then each of
    # the remaining LADDER_LAST steps changes (X2:Z2) by a doubling. X3/Z3 are dead.
    g(f'ldr r7, [sp, #{LV_SWAP}]', 'rsbs r7, r7, #0')
    op(g, 'select', 'X2', 'X2', 'X3')
    op(g, 'select', 'Z2', 'Z2', 'Z3')
    # One doubling body in a counted loop (counter in LV_T), not LADDER_LAST copies.
    if LADDER_LAST:
        lab = g.local('dbl')
        g(f'movs r0, #{LADDER_LAST}', f'str r0, [sp, #{LV_T}]')
        g.label(lab)
        g.liveness_ops = []
        dbl(g, 'X2', 'Z2')
        validate_layout(g.liveness_ops, ['X2', 'Z2'])
        g(f'ldr r0, [sp, #{LV_T}]', 'subs r0, #1', f'str r0, [sp, #{LV_T}]',
          f'beq {lab}_end', f'b {lab}')
        g.label(f'{lab}_end')
    g.liveness_ops = None
    # Z2 = Z2^(p-2), X2 = X2 * Z2, canonical, then little-endian bytes to out.
    inv_chain(g, 'Z2', 'Z2', ['X2', 'Z2'])
    op(g, 'mul', 'X2', 'X2', 'Z2')
    g(f'add r0, sp, #{S["X2"]}')
    canon_body(g)
    g(f'ldr r2, [sp, #{LV_OUT}]')
    for i in range(8):
        g(f'ldr r1, [r0, #{4 * i}]', f'strb r1, [r2, #{4 * i}]')
        for j in (1, 2, 3):
            g('lsrs r1, r1, #8', f'strb r1, [r2, #{4 * i + j}]')
    # Zero the frame and the stack the callees used, with straight-line stores.
    # SP is lowered first, so nothing is written below it.
    g(f'sub sp, #{CALLEE_STACK}', 'movs r1, #0', 'movs r2, #0', 'movs r3, #0', 'movs r4, #0',
      'movs r5, #0', 'add r0, sp, #0')
    for _ in range(WIPE_WORDS // 5):
        g('stm r0!, {r1-r5}')
    g(f'add sp, #{CALLEE_STACK + LFRAME}', 'movs r0, #0', 'mov r12, r0',
      'pop {r4-r7}', 'mov r8, r4', 'mov r9, r5', 'mov r10, r6', 'mov r11, r7',
      'pop {r4-r7, pc}')
    g.endfunc(name)


def emit_all():
    g = G()
    g.raw('@ Generated by tools/gen_x25519.py -- do not edit.')
    g.raw('\t.syntax unified')
    g.raw('\t.cpu cortex-m0plus')
    g.raw('\t.thumb')
    # One section, .text of the release unit src/m0crypto_x25519.S: every branch and call
    # is resolved by the assembler, so the unit has no relocations.
    g.raw('\t.text')
    g.raw('\t.p2align 2')
    # The entry comes last and the inversion is late in it, so a later change of
    # the inversion moves no byte of the field routines or of the ladder.
    emit_fe_mul(g)
    emit_fe_sqr(g)
    emit_fe_mulc_add(g)
    emit_x25519(g)
    return '\n'.join(g.lines) + '\n'


if __name__ == '__main__':
    default = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'x25519.S'
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else default
    out.write_text(emit_all())
