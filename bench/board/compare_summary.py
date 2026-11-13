#!/usr/bin/env python3
"""Check and summarise the comparison board logs; write the board cycle charts.

    python3 -I bench/board/compare_summary.py DATA_DIR [--charts]

DATA_DIR holds compare-PRIMITIVE.log (bench/board/run_board.sh on the
build_compare.sh images) and count-PRIMITIVE.csv (bench/count.py's cycles.csv for the
same objects; for X25519 run with --random 2). Fails (exit 1) if a log lacks
`RESULT: PASS` and `EXIT 0x00000000`, if a case's five runs differ, or if a board case
has no model row. Prints, per case, the board count, the zero-wait model, the store
model and their ratios. With --charts, writes bench/charts/PRIMITIVE/cycles_summary.svg.
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "bench"))
from pathlib import Path  # noqa: E402

from chart import BASELINE, RESEARCH, write_cycles_chart  # noqa: E402

D = sys.argv[1]
status = 0


def fail(msg):
    global status
    status = 1
    print("FAIL:", msg)


def key(primitive, impl, op, label, length):
    return (impl, op, label if primitive == "x25519" else "", length if primitive != "x25519" else "")


for primitive in ("chacha20poly1305", "blake2s", "x25519"):
    log = os.path.join(D, f"compare-{primitive}.log")
    lines = open(log, encoding="ascii").read().splitlines()
    if "RESULT: PASS" not in lines or "EXIT 0x00000000" not in lines:
        fail(f"{log}: no PASS/EXIT 0")
    platform = next((l for l in lines if l.startswith("PLATFORM,")), None)
    board = {}
    for l in lines:
        f = l.split(",")
        if f[0] == "CMP":
            runs = set(f[7:12])
            if len(runs) != 1:
                fail(f"{primitive} {f[1:5]}: runs differ {f[7:12]}")
            board[key(primitive, f[1], f[2], f[3], f[4])] = int(f[5])
    model = {}
    for r in csv.DictReader(open(os.path.join(D, f"count-{primitive}.csv"))):
        k = key(primitive, r["impl"], r["op"], r.get("input", ""), r.get("bytes", ""))
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
