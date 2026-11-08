# Changelog

## 0.1.0

- `m0c_chacha20_xor`, `m0c_chacha20poly1305_encrypt` and `_decrypt` (RFC 8439).
- Release object `.text`: 3,030 bytes, SHA-256 `b85f137f8356ea1d290578ce03616b3e00cff08aac7cc1104b3e9fdadfc990d3`.
- Functional-correctness proofs in `proofs/` (Lean 4).
- Release checks enforce the audited theorem-statement baseline.
- Pinned cycle comparison for m0-crypto, wolfSSL, Monocypher and OpenSSL kernels.
