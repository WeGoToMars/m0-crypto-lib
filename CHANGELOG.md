# Changelog

## 0.3.0

- Adds unkeyed BLAKE2s-256 (RFC 7693): `m0c_blake2s_init`, `m0c_blake2s_update`, `m0c_blake2s_final` (`include/m0crypto/blake2s.h`). 112-byte caller context; stack 160 bytes.
- Adds X25519 (RFC 7748): `m0c_x25519(out, scalar, point)` (`include/m0crypto/x25519.h`). Stack 516 bytes; no low-order-point check.
- Each primitive is its own release asset, built and checked on its own (`tools/build_lib.sh [ASSET...]`, `proofs/tools/check.sh [ASSET...]`):

  | Asset | `.text` | SHA-256 of `.text` |
  |---|---|---|
  | ChaCha20-Poly1305 | 3,030 | `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3` |
  | BLAKE2s-256 | 4,748 | `baf869bf5a30e81fc79956d2d61fde332555816d1cc0b0b0daede80a3dd4c68b` |
  | X25519 | 7,022 | `bb9c315f5a91a6fb35f81859c1c7562a8e084efef1bddfef2ef949dbd37fec94` |

  The ChaCha20-Poly1305 bytes are those of 0.2.0.
- Proofs: functional correctness, constant-time traces, read bounds and stack bounds for every exported function of all three assets, under one claim policy (`proofs/README.md`; review guide `proofs/docs/REVIEW.md`).
- The Poly1305 entry points are no longer exported. They never had a public header.
- Headers list the preconditions the proofs assume and say which clearing is proved.
- Benchmarks and MSPM0L2228 board measurements for BLAKE2s and X25519 (`bench/`, `bench/board/`).

## 0.2.0

- Proofs: secret-independent instruction and address traces, read-address bounds and per-instruction stack-pointer bounds for all three functions (`proofs/README.md`).
- Release object unchanged: `.text` 3,030 bytes, SHA-256 `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3`.
- Proofs: Lean modules, namespaces and theorem names follow one naming convention (see `proofs/README.md`, section Naming).
- Build: `tools/build_lib.sh` takes no arguments and writes to `build/lib/` (0.1.0: `tools/build_lib.sh speed`, `build/lib/speed/`).
- Proofs: `proofs/tools/check.sh` also runs the Lean specification on the RFC 8439, Wycheproof and pyca/cryptography vectors, and compares the machine model with QEMU after every instruction of sampled calls.

## 0.1.0

- `m0c_chacha20_xor`, `m0c_chacha20poly1305_encrypt` and `_decrypt` (RFC 8439).
- Release object `.text`: 3,030 bytes, SHA-256 `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3`.
- Functional-correctness proofs in `proofs/` (Lean 4).
- Release checks enforce the audited theorem-statement baseline.
- Pinned cycle comparison for m0-crypto, wolfSSL, Monocypher and OpenSSL kernels.
