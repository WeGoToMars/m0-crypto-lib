#!/usr/bin/env python3
"""Check and summarise the comparison board logs; write the board cycle charts.

    python3 -I bench/board/compare_summary.py DATA_DIR [--charts]

DATA_DIR holds compare-PRIMITIVE.log (bench/board/run_board.sh on the
build_compare.sh images) and count-PRIMITIVE.csv (bench/count.py's cycles.csv for the
same objects; for X25519 run with --random 2). Fails (exit 1) if a log lacks
`RESULT: PASS`, `EXIT 0x00000000` or the MSPM0L2228 PLATFORM line, if its cases are not
exactly those of gen_compare.py's table (each once), if a case does not have five runs equal
to its min and max, if a board case has no aligned model row (or two), or if a board count is
below the zero-wait model (the board image
counts at most one SysTick wrap: a second would make a count 2^24 short). Prints, per case, the board count, the zero-wait model, the store
model and their ratios. With --charts, writes bench/charts/PRIMITIVE/cycles_summary.svg.
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "bench"))
sys.path.insert(0, HERE)
from pathlib import Path  # noqa: E402

from chart import BASELINE, RESEARCH, write_cycles_chart  # noqa: E402
import gen_compare  # noqa: E402

D = sys.argv[1]
status = 0


def fail(msg):
    global status
    status = 1
    print("FAIL:", msg)


def key(primitive, impl, op, label, length):
    return (impl, op, label if primitive == "x25519" else "", length if primitive != "x25519" else "")


def expected_keys(primitive):
    """The case keys of the board image's table, in gen_compare.py's order."""
    keys = []

    class Cases(gen_compare.Table):
        def case(self, impl, op, label, wrapper, length, *rest, **kw):
            keys.append(key(primitive, impl, op, label, str(length)))

    getattr(gen_compare, primitive)(Cases(primitive))
    return keys


for primitive in ("chacha20poly1305", "blake2s", "x25519"):
    log = os.path.join(D, f"compare-{primitive}.log")
    lines = open(log, encoding="ascii").read().splitlines()
    if "RESULT: PASS" not in lines or "EXIT 0x00000000" not in lines:
        fail(f"{log}: no PASS/EXIT 0")
    platform = next((l for l in lines if l.startswith("PLATFORM,")), None)
    if platform is None or not platform.startswith("PLATFORM,mspm0l2228"):
        fail(f"{log}: no MSPM0L2228 PLATFORM line")
    board = {}
    for l in lines:
        f = l.split(",")
        if f[0] == "CMP":
            k = key(primitive, f[1], f[2], f[3], f[4])
            # CMP,impl,op,input,len,min,max,t0..t4
            if len(f) != 12 or len(set(f[5:12])) != 1:
                fail(f"{primitive} {f[1:5]}: not five runs equal to min and max: {f[5:]}")
            if k in board:
                fail(f"{primitive} {k}: listed twice")
            board[k] = int(f[5])
    want = expected_keys(primitive)
    if sorted(board) != sorted(want):
        fail(f"{primitive}: cases missing {sorted(set(want) - set(board))[:4]}, "
             f"unexpected {sorted(set(board) - set(want))[:4]}")
    model = {}
    for r in csv.DictReader(open(os.path.join(D, f"count-{primitive}.csv"))):
        if r.get("alignment", "a") != "a":
            continue   # the board runs aligned buffers only
        k = key(primitive, r["impl"], r["op"], r.get("input", ""), r.get("bytes", ""))
        if k in model:
            fail(f"{primitive} {k}: two aligned model rows")
        model[k] = (int(r["zero_wait_cycles"]), int(r["sram_store_model_cycles"]), r)
    print(f"\n## {primitive}: {len(board)} cases, each 5 identical runs; {platform}")
    print("| impl | op | input | bytes | board | model zero-wait | board / zero-wait | "
          "model + stores | board / (model + stores) |")
    print("|---|---|---|---:|---:|---:|---:|---:|---:|")
    rows = []
    for k, b in board.items():
        if k not in model:
            fail(f"{primitive} {k}: no model row")
            continue
        zw, st, r = model[k]
        if b < zw:
            fail(f"{primitive} {k}: board {b} is below the zero-wait model {zw}")
        print(f"| {k[0]} | {k[1]} | {k[2]} | {k[3]} | {b:,} | {zw:,} | {b / zw:.3f} | {st:,} | {b / st:.3f} |")
        rows.append({**r, "board_cycles": b})
    if primitive == "x25519":
        for impl in {k[0] for k in board}:
            v = {b for k, b in board.items() if k[0] == impl and k[1] == "shared"}
            print(f"{impl}: shared-secret counts over {sum(1 for k in board if k[0] == impl and k[1] == 'shared')} inputs: {sorted(v)}")
    # Speedups of m0-crypto over each library on the board (research implementations listed apart).
    groups = {}
    for k, b in board.items():
        groups.setdefault((k[1], k[2], k[3]), {})[k[0]] = b
    print("\nboard ratios other / m0c:")
    for g, v in groups.items():
        if BASELINE in v and g[2] != "0":
            print("  ", g, {i: round(c / v[BASELINE], 3) for i, c in v.items() if i != BASELINE},
                  "(research:", ", ".join(RESEARCH) + ")")
    if "--charts" in sys.argv:
        rows = [r for r in rows if r.get("input", "rfc7748-6.1") == "rfc7748-6.1"]
        print("chart:", write_cycles_chart(primitive, rows, Path(ROOT) / "bench/charts" / primitive))
sys.exit(status)
