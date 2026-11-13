# Board measurements of the release assets and their comparators

Measures the **unmodified release objects** (`build/lib/ASSET/m0crypto_ASSET.o` from
`tools/build_lib.sh`) on an MSPM0L2228 board and compares with the Unicorn/`bench/armv6m.py`
model. It also runs the `bench/` comparison on the board, through the same wrappers that
`bench/count.py` counts. The board was a TI MSPM0L2228 LaunchPad behind the eCTF 2026
bootloader (application at 0x6000), at the reset-default clock (`PLATFORM` line in each log).
`run_board.sh` writes the raw logs to `bench/board/data/`; they are not checked in.

Files
- `blake2s.c`, `x25519.c`: on-board harnesses of the release assets (correctness gate against
  known vectors, stack paint, then timing). `common.[ch]`, `firmware/` (support.S timing
  helpers, UART, linker fragments; `sections-sram.ld` runs the library object from SRAM).
- `gen_vectors.py`: writes `blake2s_vectors.h`, `x25519_vectors.h` (expected values from
  `hashlib.blake2s` and a pure-Python RFC 7748 ladder checked against the RFC vectors).
  Run without `-I` to get the extra cross-check with the `cryptography` package.
- `build.sh ASSET flash|sram`: builds `build/board/ASSET-PLACEMENT/bench.bin`, asserts the
  library `.text` is in the image exactly once and equals the MANIFEST sha256.
- `compare.c`, `gen_compare.py`, `build_compare.sh PRIMITIVE`: the comparison image. It links
  the objects `bench/build.py` compiles for the emulator with the board code and times each
  `run_IMPL_OP` wrapper on the workloads of `bench/count.py`. Code executes from flash.
- `run_board.sh IMAGE_DIR LOG`: flashes and runs one image through the eCTF bootloader on the
  host with the XDS110 (needs ssh key access; update mode via Pi GPIO23 = PB21).
- `model.py ASSET` (uv inline deps): modelled counts. `summarize.py DATA_DIR`: checks and
  tables. `compare_summary.py DATA_DIR [--charts]`: checks and tables of the comparison logs
  against `count.py`, and the cycle charts `bench/charts/PRIMITIVE/cycles_summary.svg`.

Reproduce
    bench/board/build.sh blake2s flash; bench/board/build.sh blake2s sram   # same for x25519
    bench/board/run_board.sh build/board/blake2s-flash build/board/logs/blake2s-flash.log
    nice uv run --no-project bench/board/model.py blake2s > build/board/logs/model-blake2s.txt
    python3 -I bench/board/summarize.py build/board/logs

    bench/board/build_compare.sh x25519                 # same for chacha20poly1305, blake2s
    bench/board/run_board.sh build/board/compare-x25519 build/board/logs/compare-x25519.log
    nice uv run --no-project bench/count.py x25519 --random 2
    cp build/bench/x25519/cycles.csv build/board/logs/count-x25519.csv
    python3 -I bench/board/compare_summary.py build/board/logs --charts

The board runs another eCTF design between measurements. Dump the flash before the first run
(`openocd -f board/ti_mspm0_launchpad.cfg -c "init; dump_image flash-before.bin 0 0x40000; shutdown"`),
flash that design back afterwards with `ectf hw PORT flash IMAGE -n NAME` and `start`, then
dump again and compare. The design's name and length are at flash 0x5000.

Timing method: SysTick, CLKSOURCE = processor clock (1 tick = 1 CPU cycle), restarted before
each call. The fixed call overhead, measured with an empty function, is subtracted. Library
entry points are timed directly through an assembly helper (`time_call3`). Rows named TOTAL,
and every comparison row, go through a C wrapper and are not library-only costs.
