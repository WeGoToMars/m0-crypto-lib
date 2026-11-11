# Cortex-M0+ cycle comparison

![Cortex-M0+ ChaCha20-Poly1305 Performance](charts/chacha20poly1305/cycles_summary.svg)

The benchmark suite builds and evaluates one-shot ChaCha20 and ChaCha20-Poly1305 operations across m0-crypto, wolfSSL, Monocypher, and OpenSSL portable kernels.

From the library root:

```sh
python3 bench/build.py
uv run --no-project bench/count.py
```

Requires Python 3, git, network access on first build, LLVM/LLD 23.1.4, and `uv`. `LLVM_BIN` and `LLD_BIN` select tool directories. `BENCH_OPT=-O2` or `-O3` sets the C optimization level (the default is `-Os` for all three C comparators). The m0-crypto object is built by `tools/build_lib.sh`.

The build records wolfSSL's effective backend macros in `wolfssl-backend.txt` and `manifest.json`. On this target it selects `POLY130532` and `WORD64_AVAILABLE`, without `WOLFSSL_W64_WRAPPER` or `WOLFSSL_ARMASM`. No blanket assembly-disable macro is set. SP Math and Fast Math select public-key arithmetic and do not alter these ChaCha20/Poly1305 kernels.

The build fetches source files pinned by revision and SHA-256 in `sources.lock.json`, plus a clean wolfSSL checkout pinned by commit in `build.py`. Sources and upstream licenses reside in ignored `bench/third_party/`. Comparison images are separate from the release library.

## Code layout

- `build.py`: Source fetching, compilation, linking, and manifest generation.
- `count.py`: Workload generation, correctness verification, and CSV/JSON output.
- `chart/`: Modular SVG performance chart generation package.
- `armv6m.py`: Unicorn/Capstone execution harness, memory layout, and instruction-cost model.
- `reference.py`: Independent [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) calculations used for runtime correctness verification.
- `link.ld`: Comparison image linker script.

## Workloads

Default lengths are 0, 64, 256, 1024, and 4096 bytes with 16-byte AAD and aligned, disjoint buffers. Each implementation runs ChaCha20 (counter 1), AEAD encrypt, AEAD decrypt, and rejection of a modified tag. Key setup and wrapper overhead are included. Each call is validated against an independent Python reference, checked against the [RFC 8439 §2.8.2](https://www.rfc-editor.org/rfc/rfc8439#section-2.8.2) vector. No result file is written until every call passes.

```sh
# Alignment and block-boundary checks
uv run --no-project bench/count.py \
  --lengths 0 1 15 16 17 63 64 65 --alignments a u ip
```

`a` uses aligned disjoint buffers; `u` uses unaligned pointers (input+1, output+3); `ip` uses exact in-place buffers (`out == in`). `--aad-length` accepts 0..64; message lengths accept 0..4096.

- **m0c:** The released assembly object.
- **wolf:** wolfSSL v5.9.4-stable, portable C, one-shot public APIs.
- **mono:** Monocypher 4.0.2, `crypto_chacha20_ietf` and a fresh `crypto_aead_init_ietf` context per AEAD call (context update and wipe included).
- **ossl:** OpenSSL 3.5.0 `ChaCha20_ctr32` and `Poly1305_*`, with [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) composition in `harness.c`. Compatibility headers provide identity conversions; upstream kernel sources are unmodified.

The common runtime provides memory routines and the ARM EABI 64-bit multiply helper required by portable C implementations, with their execution costs included.

## Counts and artifacts

`build/bench/` contains `bench.elf`, `bench.map`, `manifest.json`, `cycles.csv`, and `cycles.json`; repository charts are published to `bench/charts/chacha20poly1305/cycles_summary.svg`. The manifests record source hashes, compiler flags, release text hash, linked ELF hash, workloads, emulator versions, and source hashes of the counter scripts. The CSV reports executed instructions and two cycle estimates:

- `zero_wait_cycles`: Cortex-M0+ instruction costs from [ARM DDI 0484B, table 3-1](https://documentation-service.arm.com/static/60411742ee937942ba3016f2). The model selects the single-cycle multiplier and ordinary AHB memory accesses.
- `sram_store_model_cycles`: The same total plus one cycle per store transfer, including PUSH and STM elements.

Unicorn executes the instructions and the Python hook assigns modeled costs. These metrics represent instruction-cost model estimates without flash wait-states, cache, or bus contention. Physical hardware measurements on the reference [TI MSPM0L2228](https://www.ti.com/product/MSPM0L2228) silicon at 32 MHz yield approximately 72 cycles per byte for AEAD over 4,096 bytes executing from flash.

## Licenses

The harness is MIT licensed. Fetched sources maintain their upstream licenses: wolfSSL GPL-3.0/commercial, Monocypher BSD-2-Clause/CC0, and OpenSSL Apache-2.0. The comparison ELF includes wolfSSL; keep its license materials with any distributed comparison build. The release archive contains only m0-crypto code.
