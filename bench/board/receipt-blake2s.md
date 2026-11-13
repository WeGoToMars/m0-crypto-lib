# BLAKE2s on the board, 2026-11-13

Scope: functional check + cycle counts of the released `m0crypto_blake2s.o` `.text` on one
board, one clock. These are hardware measurements; modelled numbers are listed separately.

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
- Object: `.text` 4,748 B, sha256 `baf869bf5a30e81fc79956d2d61fde332555816d1cc0b0b0daede80a3dd4c68b`
  (MANIFEST in `bench/board/data/2026-11-13/MANIFEST-blake2s.txt`). `build.sh` asserts the image contains exactly
  this byte string once. Flashed images (sha256 of `bench.bin`, 17,424 B flash / 17,460 B sram):
  - flash placement `b2adf63e8ddb816ee3c38a3574a2e534617610048ea76e225388c989e3a0266f` (library at 0x7ac0)
  - sram placement `aeb8014c9a3eeb8dfe4b47023fb3f790372dad9d42fa7f3769d62e1355f4188a` (library copied to SRAM at reset)
  The sha of the flashed image is also printed in each log (`IMAGE,` line).
- Commands: see `bench/board/README.md`; logs `bench/board/data/2026-11-13/blake2s-{flash,sram}.log`, summary `bench/board/data/2026-11-13/summary.md`.

## Correctness
Each log has `RESULT: PASS` and `EXIT 0x00000000`: every digest of every timed hash (31 lengths
0..4096 x 5 contents x offsets 0-3 x chunkings single/64/17) equals `hashlib.blake2s`.
Gate runs before any timing.

## Cycle counts (board, flash placement; sram in `summary.md`)
Library calls only (no C wrapper). All 5 repeats were identical for every row (838 rows each).
INIT = 60 (flash) / 46 (sram). Selected rows, `update` at word-aligned input, `final` after that update:

| bytes | update | final | init+update+final | update off+1 | update off+2 |
|---:|---:|---:|---:|---:|---:|
| 0 | 37 | 3108 | 3205 | 37 | 37 |
| 1 | 74 | 3125 | 3259 | 74 | 74 |
| 16 | 132 | 3076 | 3268 | 188 | 168 |
| 32 | 151 | 3044 | 3255 | 260 | 220 |
| 64 | 189 | 2980 | 3229 | 404 | 324 |
| 65 | 2994 | 3125 | 6179 | 3361 | 3281 |
| 128 | 3109 | 2980 | 6149 | 3691 | 3531 |
| 256 | 8955 | 2980 | 11995 | 10265 | 9945 |
| 1024 | 44031 | 2980 | 47071 | 49709 | 48429 |
| 4096 | 184335 | 2980 | 187375 | 207485 | 202365 |

Cycles/byte, single aligned update through the C wrapper: 1024 B 46.03; 4096 B 45.76 (sram
45.05). Marginal cost 2,923 cycles per 64-B block (flash), 2,877 (sram). Full table: `bench/board/data/2026-11-13/summary.md`.

## Constant-cycle findings
- Across 5 contents (zeros, 0xff, two xorshift streams, counting) the counts were identical for
  all 62 (length, offset) groups, in both placements.
- Counts do depend on length, input alignment (offsets 1-3 cost more than offset 0) and update
  chunking, which are public parameters.
- Repeats identical (min = max in all rows).

## Stack
Stack high-water mark: update 160 B, final 160 B (init 4 B). Matches the claimed 160 B.

## Board vs model (`model.py`, store-model figure with the no-op return correction)
- sram placement: update -3..+31 cycles, final -3, init -3 (n=124/31/1). The constant -3 is
  the call overhead calibrated in flash (3 ticks more than in SRAM); +31 is the length-0 update,
  which `model.py` does not compute.
- flash placement: update +7..+3,672 cycles (grows with length, about 1.8% at 4 KiB aligned),
  final +47..48, init +11. The model has no flash wait states or prefetch, so flash is
  slower than modelled, as expected; the share was not decomposed further.

## Not done / limits
- One board, one clock, voltage not measured, no repeat across power cycles, flash code alignment
  sensitivity not explored. Only the reset-default wait-state setup was used.
- No comparator was measured on the board. The comparisons with wolfSSL, the BLAKE2 reference and
  OpenSSL in `bench/` (`bench/README.md`) are emulator-model estimates, not board measurements.
