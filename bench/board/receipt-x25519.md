# X25519 on the board, 2026-11-13

Scope: functional check + cycle counts of one `m0c_x25519` call of the released
`m0crypto_x25519.o` `.text` on one board, one clock.

- Date: 2026-11-13. Board: TI MSPM0L2228 LaunchPad (Cortex-M0+, CPUID 0x410cc601), XDS110
  (fw 3.0.0.45), running behind the eCTF 2026 insecure bootloader v26.0.2 (app at 0x6000,
  SRAM 0x20200000). Host cw-pi (Linux 6.18.33+rpt-rpi-2712), OpenOCD 0.12.0+dev-snapshot
  (2026-02-16), ectf 2026.0.11, Python 3.13.5.
- Clock: reset default, not touched by the harness: `PLATFORM,mspm0l2228-ectf,CPUID=0x410cc601,
  MCLKCFG=0x00000200,SYSOSCCFG=0x00020000,CLKSTATUS=0x00013800,CPUSS_CTL=0x00000007`.
  Cycles are SysTick ticks of the CPU clock, so no frequency is needed for them; frequency and
  supply voltage were not measured.
- Toolchain: Homebrew clang/LLD 23.1.4 (the release build uses the same clang 23.1.4).
- Provenance of the code: worktree `m0-crypto-wt/board-measure`, branch `review/board-measure`,
  based on lib commit 75ab110 (`split-assets` line). Harness files are new under `bench/board/`.
- Object: `.text` 7,022 B, sha256 `bb9c315f5a91a6fb35f81859c1c7562a8e084efef1bddfef2ef949dbd37fec94`
  (MANIFEST in `bench/board/data/2026-11-13/MANIFEST-x25519.txt`). Flashed images (sha256 of `bench.bin`):
  - flash placement `24f5e45ca8708756cf8076317391600e8b613b423a213a2c925a2b2d377a70ec` (library at 0x774c)
  - sram placement `eb39435d477bddf1b6139004f706f0223ca7d1b13c987fe840f438e6ecf7dfd1`
- Commands: see `bench/board/README.md`; logs `bench/board/data/2026-11-13/x25519-{flash,sram}.log`, `bench/board/data/2026-11-13/summary.md`.

## Correctness
`RESULT: PASS`, `EXIT 0x00000000` in both logs. Gate: 44 scalar/point pairs x 4 buffer layouts
(separate, misaligned k+1/u+2/out+3, out==scalar, out==point) equal a pure-Python RFC 7748
ladder (self-checked against the RFC vectors incl. 1000 iterations; 34 of 44 also cross-checked
with `cryptography`). Pairs: 7 RFC vectors, 7 degenerate scalars (all-zero, all-ones, 1, clamp
extremes, single bit), 14 point edge cases (0, 1, low order, p-1, p, p+1, 2^255-1, bit 255 set,
2^256-1, ...), 16 random.

## Cycle counts (one `m0c_x25519` call, library only)
| placement | cycles | distinct values over 62 rows x 5 runs |
|---|---:|---|
| flash | 3,480,832 | 1 |
| sram | 3,453,749 | 1 |
| model, zero-wait (`model.py`) | 3,289,570 | |
| model, store-model (`model.py`, comparable) | 3,453,751 | |

Both model rows come from `bench/board/model.py` (`bench/board/data/2026-11-13/model-x25519.txt`):
the cost of every instruction of the call including its return (3,289,572 zero-wait cycles), minus
the 2 cycles of the `bx lr` that the board's calibration interval also contains. The store-model
figure adds one cycle per store transfer. The 3,289,592 cycles in the main README and the
CHANGELOG are the same zero-wait model counted by `bench/count.py` from the benchmark's C
wrapper `run_m0c_shared`, which adds 20 cycles (`push`, `mov`, three `ldr`, `bl`, `str`, `pop`)
to the call.

Identical for all 44 vectors, all four layouts (other layouts timed for 6 vectors) and all
5 repeats.

## Stack
Stack high-water mark 516 B, matching the claimed 516 B.

## Board vs model
- sram: board 3,453,749 vs model 3,453,751 = -2: the call overhead was calibrated with an empty function in flash, which costs 2 ticks more than in SRAM.
- flash: +27,081 cycles (+0.78%) over the model: flash fetch wait states, not decomposed further.
- zero-wait model is 164,179 cycles below the sram board figure: the store-cycle term is required.

## Not done / limits
- One board, one clock, voltage not measured, no repeat across power cycles, flash alignment
  sensitivity not explored; reset-default wait-state setup only.
- No comparator was measured on the board. The comparisons with x25519-cm0, wolfSSL, Monocypher
  and OpenSSL in `bench/` (`bench/README.md`) are emulator-model estimates, not board measurements.
