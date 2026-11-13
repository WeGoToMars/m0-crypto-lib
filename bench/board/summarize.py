#!/usr/bin/env python3
"""Check and summarise board logs against each other and against the model files.

    python3 -I bench/board/summarize.py DATA_DIR

DATA_DIR holds blake2s-{flash,sram}.log, x25519-{flash,sram}.log and, from model.py,
model-blake2s.txt and model-x25519.txt. Fails (exit 1) if a log lacks `RESULT: PASS` and
`EXIT 0x00000000`, if the PLATFORM lines differ, or if a row is missing. Prints the facts
that go into the receipts; nothing is estimated.
"""
import os
import sys
from collections import defaultdict

D = sys.argv[1]
status = 0


def fail(msg):
    global status
    status = 1
    print("FAIL:", msg)


def load(name):
    p = os.path.join(D, name)
    rows, plat, ok, ex = [], None, False, False
    for line in open(p, encoding="ascii"):
        line = line.rstrip("\n")
        if line.startswith("PLATFORM,"):
            plat = line
        ok |= line == "RESULT: PASS"
        ex |= line == "EXIT 0x00000000"
        rows.append(line.split(","))
    if not (ok and ex):
        fail(f"{name}: no PASS/EXIT 0")
    return rows, plat


def model(name):
    out = defaultdict(dict)
    for line in open(os.path.join(D, name)):
        f = line.strip().split(",")
        if f[0] == "MODEL":
            out[f[1]][tuple(f[2:-2])] = (int(f[-2]), int(f[-1]))
    return out


plats = set()
res = {}
for a in ("blake2s", "x25519"):
    for p in ("flash", "sram"):
        rows, plat = load(f"{a}-{p}.log")
        plats.add(plat)
        res[(a, p)] = rows
if len(plats) != 1:
    fail(f"PLATFORM lines differ: {plats}")
print("PLATFORM:", plats.pop())

# ------------------------------------------------------------------ BLAKE2s ----
print("\n## BLAKE2s")
mb = model("model-blake2s.txt")
for p in ("flash", "sram"):
    rows = res[("blake2s", p)]
    data = defaultdict(dict)
    for r in rows:
        if r[0] in ("INIT", "UPDATE", "FINAL", "TOTAL", "DATAVAR"):
            data[r[0]][tuple(r[1:-2]) if r[0] != "DATAVAR" else tuple(r[1:4])] = (
                tuple(map(int, r[-2:])) if r[0] != "DATAVAR" else tuple(map(int, r[4:])))
    n = sum(len(v) for v in data.values())
    spread = [(k, kk, v) for k, d in data.items() for kk, v in d.items()
              if k != "DATAVAR" and v[0] != v[1]]
    dvspread = [(kk, v) for kk, v in data["DATAVAR"].items() if any(v[i] != v[i + 1] for i in range(0, 8, 2))]
    print(f"\n### {p}: {n} rows; rows with min != max: {len(spread)} {spread[:5]}; "
          f"DATAVAR rows with min != max: {len(dvspread)}")
    # data independence: per (len, off), all 5 contents give identical 8-tuples
    groups = defaultdict(set)
    for (ln, off, fam), v in data["DATAVAR"].items():
        groups[(ln, off)].add(v)
    bad = {k: s for k, s in groups.items() if len(s) != 1}
    print(f"contents compared: {len(groups)} (len, offset) groups x 5 contents; groups whose "
          f"counts differ between contents: {len(bad)} {list(bad)[:5]}")
    # DATAVAR family 2 == profile rows
    mism = 0
    for (ln, off, fam), v in data["DATAVAR"].items():
        if fam == "2":
            if data["UPDATE"][(ln, off)] != v[0:2] or data["FINAL"][(ln,)] != v[2:4] and off == "0" or \
               data["TOTAL"][(ln, off, "0")] != v[4:6] or data["TOTAL"][(ln, off, "17")] != v[6:8]:
                mism += 1
    print(f"DATAVAR family 2 vs profile rows: {mism} mismatches")
    print(f"INIT = {data['INIT'][()][0]}")
    print("\n| bytes | update off0 | off1 | off2 | off3 | final | hash 1 update (off0) | off1 | off2 | off3 | 64-B updates | 17-B updates | "
          "init+update+final | wrapper extra |")
    print("|---:|" + "---:|" * 13)
    for ln in map(str, sorted(int(k[0]) for k in data["FINAL"])):
        u = [data["UPDATE"][(ln, str(o))][1] for o in range(4)]
        t = [data["TOTAL"][(ln, str(o), "0")][1] for o in range(4)]
        t64 = data["TOTAL"][(ln, "0", "64")][1]
        t17 = data["TOTAL"][(ln, "0", "17")][1]
        fin = data["FINAL"][(ln,)][1]
        s = data["INIT"][()][1] + u[0] + fin
        print(f"| {ln} | {u[0]} | {u[1]} | {u[2]} | {u[3]} | {fin} | {t[0]} | {t[1]} | {t[2]} | {t[3]} | {t64} | {t17} | {s} | {t[0] - s} |")
    t = lambda l: data["TOTAL"][(str(l), "0", "0")][1]
    print(f"\ncycles/byte (single update, aligned): 1024 B {t(1024)/1024:.2f}; 4096 B {t(4096)/4096:.2f}; "
          f"slope (4096-1024)/3072 = {(t(4096)-t(1024))/3072:.3f}; "
          f"per 64-B block (4096-1024)/48 = {(t(4096)-t(1024))/48:.2f}")
    # model comparison (UPDATE, FINAL, INIT, TOTAL)
    diffs = defaultdict(list)
    for (ln, off), v in ((k, data["UPDATE"][k]) for k in data["UPDATE"]):
        diffs["UPDATE"].append(v[1] - mb["UPDATE"][(ln, off)][1])
    for k, v in data["FINAL"].items():
        diffs["FINAL"].append(v[1] - mb["FINAL"][k][1])
    for k, v in data["TOTAL"].items():
        diffs["TOTAL(wrapper incl.)"].append(v[1] - mb["TOTAL"][k][1])
    diffs["INIT"].append(data["INIT"][()][1] - mb["INIT"][()][1])
    print("\nboard minus model (store-model figure, calibration-corrected): "
          + "; ".join(f"{k}: min {min(v)}, max {max(v)}, n={len(v)}" for k, v in diffs.items()))
    zero = defaultdict(list)
    for (ln, off), v in ((k, data["UPDATE"][k]) for k in data["UPDATE"]):
        zero["UPDATE"].append(v[1] - mb["UPDATE"][(ln, off)][0])
    print("board minus zero-wait model, UPDATE: min %d max %d" % (min(zero["UPDATE"]), max(zero["UPDATE"])))
    # stack
    print("stack:", "; ".join(",".join(r[1:]) for r in res[("blake2s", p)] if r[0] in ("STACKMAX",)),
          "| init:", [r[3] for r in res[("blake2s", p)] if r[0] == "STACK" and r[1] == "init"])

# ------------------------------------------------------------------- X25519 ----
print("\n## X25519")
mx = model("model-x25519.txt")["X25519"]
allv = {}
for p in ("flash", "sram"):
    rows = [r for r in res[("x25519", p)] if r[0] == "X25519"]
    vals = set()
    per_layout = defaultdict(set)
    for r in rows:
        v = tuple(map(int, r[4:]))
        vals.update(v)
        per_layout[r[3]].update(v)
    allv[p] = vals
    labels = {r[2] for r in rows if r[3] == "a"}
    stack = [r[1:] for r in res[("x25519", p)] if r[0] == "STACKMAX"]
    print(f"\n### {p}: {len(rows)} rows ({len(labels)} vectors in layout a), "
          f"{5 * len(rows)} timed calls; distinct cycle counts over all of them: {sorted(vals)}")
    print("per layout:", {k: sorted(v) for k, v in per_layout.items()}, "| STACKMAX", stack)
    mvals = {v for v in mx.values()}
    print("model (zero-wait, store-model, corrected):", sorted(mvals))
    only = [r for r in rows if r[3] == "a"]
    print("| # | vector | cycles (5 runs identical?) |")
    print("|--:|---|--:|")
    for r in only:
        t = r[6:]
        print(f"| {r[1]} | {r[2]} | {t[0]}{'' if len(set(t)) == 1 else ' RUNS DIFFER ' + ','.join(t)} |")
    print(f"vectors in model: {len(mx)}; model identical for all: {len(mvals) == 1}")
sys.exit(status)
