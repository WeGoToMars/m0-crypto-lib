#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["unicorn==2.1.4", "capstone==5.0.9", "pyelftools==0.32"]
# ///
"""Modelled cycle counts of the released objects, for comparison with the board logs.

    uv run --no-project bench/board/model.py blake2s > build/board/model-blake2s.txt
    uv run --no-project bench/board/model.py x25519  > build/board/model-x25519.txt

Unicorn executes the .text of build/lib/ASSET/m0crypto_ASSET.o (from tools/build_lib.sh)
and the Cortex-M0+ instruction-cost model of bench/armv6m.py (zero-wait costs from ARM
DDI 0484B, plus one cycle per store transfer for the second figure) assigns cycles. These
are MODEL numbers: no flash wait states, no cache, no prefetcher, no bus contention.

Each row is for one library call, on the same inputs as the board rows. "model" is the
cost of every instruction the call executes, including its return. The board interval
also contains the `blx` and the return of the empty function that calibrates it, so a
board reading corresponds to model minus the 2 cycles of that `bx lr`; `cmp` is the
model with that correction applied (`-2`) and is what to compare with the board.
Output lines:
  MODEL,INIT,zw,store          zw = zero-wait cycles, store = zw + store transfers (both -2)
  MODEL,UPDATE,len,off,zw,store
  MODEL,FINAL,len,zw,store
  MODEL,TOTAL,len,off,chunk,zw,store    sum over the calls of init + update(s) + final
  MODEL,DATAVAR,len,off,family,zw,store sum for a one-update hash of that content
  MODEL,X25519,index,label,zw,store
The digests/results are checked against the same tables the firmware uses.
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "bench"))

import capstone  # noqa: E402
import unicorn  # noqa: E402
from unicorn import arm_const  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402

import armv6m  # noqa: E402
from armv6m import Instruction, instruction_cost  # noqa: E402

CODE_BASE = 0x00010000
RAM = armv6m.RAM_BASE
STACK_TOP = RAM + armv6m.RAM_BYTES
RET = 0x3FF00
CTX, MSG, OUT, KB, UB = RAM + 0x100, RAM + 0x1000, RAM + 0x3000, RAM + 0x4000, RAM + 0x4100
NOOP_RETURN = 2   # `bx lr` of the empty function the board subtracts


class Model:
    def __init__(self, asset):
        obj = os.path.join(ROOT, "build/lib", asset, f"m0crypto_{asset}.o")
        text = open(os.path.join(ROOT, "build/lib", asset, "text.bin"), "rb").read()
        with open(obj, "rb") as f:
            symtab = ELFFile(f).get_section_by_name(".symtab")
            self.sym = {s.name: s["st_value"] & ~1 for s in symtab.iter_symbols()
                        if s.name.startswith("m0c_")}
        self.m = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS)
        self.m.mem_map(CODE_BASE, 0x4000)
        self.m.mem_map(0, 0x1000)   # return-address page is outside; keep 0 mapped for safety
        self.m.mem_map(RAM, armv6m.RAM_BYTES)
        self.m.mem_map(RET & ~0xFFF, 0x1000)
        self.m.mem_write(CODE_BASE, text)
        self.dec = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
        self.dec.detail = True
        self.cache = {}
        self.zw = self.st = 0
        self.m.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, m, address, size, _):
        if address == RET:
            m.emu_stop()
            return
        ins = self.cache.get(address)
        if ins is None:
            d = next(self.dec.disasm(bytes(m.mem_read(address, size)), address))
            regs = tuple(o.reg for o in d.operands if o.type == capstone.arm.ARM_OP_REG)
            ins = self.cache[address] = Instruction(d.mnemonic, regs, d.op_str)
        c, s = instruction_cost(ins, m)
        self.zw += c
        self.st += s

    def call(self, name, r0=0, r1=0, r2=0):
        """Run one entry point; returns (r0, zero-wait cycles, store-model cycles) with the
        board's calibration correction applied."""
        m = self.m
        m.reg_write(arm_const.UC_ARM_REG_SP, STACK_TOP)
        m.reg_write(arm_const.UC_ARM_REG_LR, RET | 1)
        for reg, v in ((arm_const.UC_ARM_REG_R0, r0), (arm_const.UC_ARM_REG_R1, r1),
                       (arm_const.UC_ARM_REG_R2, r2)):
            m.reg_write(reg, v)
        self.zw = self.st = 0
        m.emu_start((CODE_BASE + self.sym[name]) | 1, RET, count=200_000_000)
        assert m.reg_read(arm_const.UC_ARM_REG_PC) == RET, name
        assert m.reg_read(arm_const.UC_ARM_REG_SP) == STACK_TOP
        return (m.reg_read(arm_const.UC_ARM_REG_R0), self.zw - NOOP_RETURN,
                self.zw + self.st - NOOP_RETURN)


def blake2s():
    sys.path.insert(0, HERE)
    import gen_vectors as g
    md = Model("blake2s")
    lens = g.LENS

    def hash_(n, off, family, chunk):
        data = g.fill(family, n)
        md.m.mem_write(MSG + off, data if data else b"\0")
        md.m.mem_write(OUT, b"\xa5" * 48)
        tot = [0, 0]
        parts = {}

        def add(key, name, *a):
            _, zw, st = md.call(name, *a)
            parts[key] = (zw, st)
            tot[0] += zw
            tot[1] += st
        add("init", "m0c_blake2s_init", CTX)
        if n:
            step = chunk or n
            for i in range(0, n, step):
                add(("u", i), "m0c_blake2s_update", CTX, MSG + off + i, min(step, n - i))
        add("final", "m0c_blake2s_final", CTX, OUT + 4)
        digest = bytes(md.m.mem_read(OUT + 4, 32))
        import hashlib
        assert digest == hashlib.blake2s(data, digest_size=32).digest(), (n, off, family, chunk)
        return tot, parts

    _, zw, st = md.call("m0c_blake2s_init", CTX)
    print(f"MODEL,INIT,{zw},{st}")
    for n in lens:
        for off in range(4):
            tot, parts = hash_(n, off, 2, 0)
            u = parts.get(("u", 0), (0, 0))
            print(f"MODEL,UPDATE,{n},{off},{u[0]},{u[1]}")
            for chunk in (0, 64, 17):
                tot, _ = hash_(n, off, 2, chunk)
                print(f"MODEL,TOTAL,{n},{off},{chunk},{tot[0]},{tot[1]}")
        tot, parts = hash_(n, 0, 2, 0)
        print(f"MODEL,FINAL,{n},{parts['final'][0]},{parts['final'][1]}")
    seen = {}
    for n in lens:
        for off in (0, 1):
            for fam in range(g.FAMILIES):
                tot, parts = hash_(n, off, fam, 0)
                print(f"MODEL,DATAVAR,{n},{off},{fam},{tot[0]},{tot[1]}")


def x25519():
    sys.path.insert(0, HERE)
    import gen_vectors as g
    md = Model("x25519")
    for i, (label, k, u) in enumerate(g.vectors()):
        md.m.mem_write(KB, k)
        md.m.mem_write(UB, u)
        md.m.mem_write(OUT, b"\xa5" * 64)
        r0, zw, st = md.call("m0c_x25519", OUT + 8, KB, UB)
        assert r0 == 0
        assert bytes(md.m.mem_read(OUT + 8, 32)) == g.x25519(k, u), label
        print(f"MODEL,X25519,{i},{label.replace(',', ';')},{zw},{st}", flush=True)


if __name__ == "__main__":
    {"blake2s": blake2s, "x25519": x25519}[sys.argv[1]]()
