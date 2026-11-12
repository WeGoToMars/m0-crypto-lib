# Changelog

## 0.2.0

- Proofs: secret-independent instruction and address traces, read-address bounds and per-instruction stack-pointer bounds for all three functions (`proofs/README.md`).
- Release object unchanged: `.text` 3,030 bytes, SHA-256 `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3`.
- Proofs: Lean modules, namespaces and theorem names follow one naming convention (see `proofs/README.md`, section Naming).
- Build: `tools/build_lib.sh` takes no arguments and writes to `build/lib/` (0.1.0: `tools/build_lib.sh speed`, `build/lib/speed/`).
- Proofs: a review guide (`proofs/REVIEW.md`) lists the definitions a reader must check and against which document. The four theorems about each function share one hypothesis, and a concrete call satisfying it is exhibited.
- Proofs: `proofs/tools/check.sh` also runs the Lean specification on the RFC 8439, Wycheproof and pyca/cryptography vectors, and compares the machine model with QEMU after every instruction of sampled calls.

## 0.1.0

- `m0c_chacha20_xor`, `m0c_chacha20poly1305_encrypt` and `_decrypt` (RFC 8439).
- Release object `.text`: 3,030 bytes, SHA-256 `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3`.
- Functional-correctness proofs in `proofs/` (Lean 4).
- Release checks enforce the audited theorem-statement baseline.
- Pinned cycle comparison for m0-crypto, wolfSSL, Monocypher and OpenSSL kernels.
