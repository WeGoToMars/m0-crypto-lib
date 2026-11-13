# m0-crypto

Optimized ARMv6-M assembly implementations of cryptographic primitives for Cortex-M0+ with formal verification in Lean 4.

Current version contains:

| Algorithm | Function | Header | Standard |
|---|---|---|---|
| [ChaCha20](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) | `m0c_chacha20_xor` | [`chacha20.h`](include/m0crypto/chacha20.h) | [RFC 8439 §2.4](https://www.rfc-editor.org/rfc/rfc8439#section-2.4) |
| [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) | `m0c_chacha20poly1305_encrypt` / `_decrypt` | [`chacha20poly1305.h`](include/m0crypto/chacha20poly1305.h) | [RFC 8439 §2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8) |
| [BLAKE2s-256](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) | `m0c_blake2s_init` / `_update` / `_final` | [`blake2s.h`](include/m0crypto/blake2s.h) | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) |
| [X25519](https://en.wikipedia.org/wiki/Curve25519) | `m0c_x25519` | [`x25519.h`](include/m0crypto/x25519.h) | [RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748#section-5) |

The headers document the buffer, aliasing and alignment rules. In short:

- **ChaCha20-Poly1305:** works in place. Decryption checks the tag before writing and leaves `out` unchanged on failure.
- **BLAKE2s-256:** `init`, `update`, `final` on a caller-held 112-byte context, which the caller wipes afterwards.
- **X25519:** `m0c_x25519(out, scalar, point)` per RFC 7748, with any alignment or overlap. It does not reject low-order points.

## Performance

Measured on a [TI MSPM0L2228](https://www.ti.com/product/MSPM0L2228) (Cortex-M0+, single-cycle multiplier).

The charts compare against portable C libraries and other optimized assembly implementations on the same board, code in flash (see [`bench/`](bench/README.md), [`bench/board/`](bench/board/README.md)).

### ChaCha20-Poly1305

**1.6-2.0x** fewer cycles than wolfSSL, OpenSSL and Monocypher for ChaCha20, and **2.0-2.4x** fewer for AEAD encryption/decryption.

<details>
<summary>📊 ChaCha20-Poly1305 performance and memory usage comparison</summary>

![Cortex-M0+ ChaCha20-Poly1305 Performance](bench/charts/chacha20poly1305/cycles_summary.svg)

![Cortex-M0+ ChaCha20-Poly1305 Memory Footprint](bench/charts/chacha20poly1305/size_summary.svg)

</details>

### BLAKE2s-256

**1.5-2.7x** fewer cycles than wolfSSL, OpenSSL and the BLAKE2 reference implementation.

<details>
<summary>📊 BLAKE2s-256 performance and memory usage comparison</summary>

![Cortex-M0+ BLAKE2s-256 Performance](bench/charts/blake2s/cycles_summary.svg)

![Cortex-M0+ BLAKE2s-256 Memory Footprint](bench/charts/blake2s/size_summary.svg)

</details>

### X25519

**3.9x** fewer cycles than the portable C libraries. Thomas Pornin's hand-written assembly, [x25519-cm0](https://github.com/pornin/x25519-cm0), takes 0.7% fewer cycles.[^pornin]

<details>
<summary>📊 X25519 performance and memory usage comparison</summary>

![Cortex-M0+ X25519 Performance](bench/charts/x25519/cycles_summary.svg)

![Cortex-M0+ X25519 Memory Footprint](bench/charts/x25519/size_summary.svg)

</details>

[^pornin]: [x25519-cm0](https://github.com/pornin/x25519-cm0) inverts with Pornin's optimized binary GCD ([eprint 2020/972](https://eprint.iacr.org/2020/972)), 54,793 cycles according to its source. m0-crypto inverts with Fermat's little theorem, a chain of field squarings and multiplications. In the cycle model it costs 277,656 cycles, 8% of a call, and outside the inversion m0-crypto is about 5% faster than x25519-cm0. A GCD-style inversion such as safegcd would save about 5% of a call, but proving it needs the algorithm's iteration bound and a refinement of its batched matrix code, which by my estimation would roughly double the X25519 proofs. The Fermat chain reuses the already proved field multiply and square, so we accepted the slower inversion for a much smaller proof.

## Build

```sh
tools/build_lib.sh            # all assets, or name them: tools/build_lib.sh x25519
```

Requires clang/LLVM 23.1.4 on `PATH`. Each primitive is a separate asset with its own archive and proofs:

| Asset | Archive | `.text` | Max stack |
|---|---|---:|---:|
| ChaCha20, ChaCha20-Poly1305 | `build/lib/chacha20poly1305/libm0crypto_chacha20poly1305.a` | 3,030 B | 176 B (ChaCha20), 320 B (AEAD) |
| BLAKE2s-256 | `build/lib/blake2s/libm0crypto_blake2s.a` | 4,748 B | 160 B |
| X25519 | `build/lib/x25519/libm0crypto_x25519.a` | 7,022 B | 516 B |

Link the archives you use and add `include/` to the include path. There is no heap, static data, relocation or external dependency, so the code runs from flash or SRAM. `MANIFEST.txt` next to each archive records the hashes of the verified bytes.

## Test

```sh
tools/test_qemu.sh            # all assets, or name them
```

Runs each release object on QEMU's Cortex-M0 (QEMU 11.1.3) against RFC, Wycheproof, pyca/cryptography and `hashlib` vectors, including unaligned and overlapping buffers. It also checks callee-saved registers and stack depth, and for ChaCha20-Poly1305 and X25519 the cleared registers and stack bytes.

## Proofs and Scope

Lean 4 proofs in [`proofs/`](proofs/) cover the exact `.text` bytes of each release object, in a model of the ARMv6-M instructions it uses, for calls that meet the preconditions in each header. For every exported function they prove:

- **Correctness:** the output matches RFC 8439, RFC 7693 or RFC 7748 for any length, alignment and allowed overlap, and every call returns.
- **Memory safety:** reads and writes stay inside the caller's buffers, the code and the stack bound above. SP and r4-r11 are restored.
- **Constant-time traces:** the executed instructions and accessed addresses depend only on public inputs (pointers, lengths, the ChaCha20 counter, whether a tag verified, the BLAKE2s buffered byte count).
- **Clearing:** the stack bytes and registers that each header lists as proved are zero on return.

The proofs assume sequential execution in ordinary memory, with no interrupts, concurrent memory writes (such as DMA) or faults during a call. Execution time is assumed to depend only on the instruction and address trace, which the BLAKE2s and X25519 board harnesses in [`bench/board/`](bench/board/README.md) test on varied inputs. Theorem names and exact statements: [`proofs/README.md`](proofs/README.md), [`proofs/docs/REVIEW.md`](proofs/docs/REVIEW.md).

```sh
git clone --recurse-submodules https://github.com/WeGoToMars/m0-crypto-lib
proofs/tools/check.sh              # every asset; requires Lean v4.35.0 (elan), LLVM 23.1.4, QEMU 11.1.3
proofs/tools/check.sh blake2s      # one asset
```

`check.sh` rebuilds each object, checks its bytes against the proofs, builds the proofs, audits their axioms and compares the Lean model with QEMU on sampled calls.

> [!IMPORTANT]
> Physical side channels (power analysis, fault injection) are out of scope. Callers keep nonces unique per key, reject low-order X25519 points where their protocol requires it, and wipe the BLAKE2s context.

## License

Original code is MIT licensed. Test-vector provenance and third-party license notices are documented in [THIRD_PARTY.md](THIRD_PARTY.md).
