# Board measurements of the BLAKE2s and X25519 release assets

Measures the **unmodified release objects** (`build/lib/ASSET/m0crypto_ASSET.o` from
`tools/build_lib.sh`) on an MSPM0L2228 board and compares with the Unicorn/`bench/armv6m.py`
model. Receipts: `receipt-blake2s.md`, `receipt-x25519.md`. Raw logs: `bench/board/data/2026-11-13/` on the measuring machine (`run_board.sh` writes them there; they are not checked in).

Files
- `blake2s.c`, `x25519.c`: on-board harnesses (correctness gate against known vectors, stack
  paint, then timing). `common.[ch]`, `firmware/` (support.S timing helpers, UART, linker
  fragments; `sections-sram.ld` runs the library object from SRAM).
- `gen_vectors.py`: writes `blake2s_vectors.h`, `x25519_vectors.h` (expected values from
  `hashlib.blake2s` and a pure-Python RFC 7748 ladder checked against the RFC vectors).
  Run without `-I` to get the extra cross-check with the `cryptography` package.
- `build.sh ASSET flash|sram`: builds `build/board/ASSET-PLACEMENT/bench.bin`, asserts the
  library `.text` is in the image exactly once and equals the MANIFEST sha256.
- `run_board.sh IMAGE_DIR LOG`: flashes and runs one image through the eCTF bootloader on the
  host with the XDS110 (needs ssh key access; update mode via Pi GPIO23 = PB21).
- `model.py ASSET` (uv inline deps): modelled counts. `summarize.py DATA_DIR`: checks and tables.

Reproduce
    bench/board/build.sh blake2s flash; bench/board/build.sh blake2s sram   # same for x25519
    bench/board/run_board.sh build/board/blake2s-flash build/board/logs/blake2s-flash.log
    nice uv run --no-project bench/board/model.py blake2s > build/board/logs/model-blake2s.txt
    python3 -I bench/board/summarize.py build/board/logs

Timing method: SysTick, CLKSOURCE = processor clock (1 tick = 1 CPU cycle), restarted before
each call; fixed call overhead (18 ticks, measured with an empty function) subtracted. Library
entry points are timed directly through an assembly helper (`time_call3`). Rows named TOTAL
go through a C wrapper and are not library-only costs.
