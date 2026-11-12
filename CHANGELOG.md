# Changelog

## 0.3.0

- Adds unkeyed BLAKE2s-256 (RFC 7693): `m0c_blake2s_init`, `m0c_blake2s_update`, `m0c_blake2s_final` (`include/m0crypto/blake2s.h`), written in Thumb assembly (`src/blake2s_*.S`) and linked into the release unit `src/m0crypto.S`. `m0c_blake2s_compress` and `m0c_blake2s_copy` are internal entries.
- Release object: `.text` 7,780 bytes, SHA-256 `6249c646e284766a09eb82d4e8c09a5edb1d603a18c5c482e20b6e7e84617427`. The ChaCha20 and ChaCha20-Poly1305 code bytes are unchanged.
- Clearing: each compression zeroes its 100 bytes of stack working state and returns with r0-r3 and r12 zero. `update` and `final` return with r0-r3 zero. The context is caller memory and is not cleared.
- Proofs (Lean, `proofs/`): functional correctness of `compress`, `copy`, `init`, `update` and `final` against the specification in `Spec/Blake2s.lean`, and the composed `hash_correct` (`init; update*; final` returns and writes the RFC 7693 digest of the concatenated inputs). Constant-time trace, read-bound and stack-bound theorems for each BLAKE2s entry, with the composed `hash_constant_time`. The constant-time theorems take as public only the argument registers each entry reads (init 1, final 2, update and copy 3).
- Proofs of the clearing: the `compress` postcondition states zero locals, r0-r3 and r12. The `update` and `final` postconditions state zero r0-r3. No theorem states the stack contents left by a whole `update` or `final` call.
- Checks: the theorems are listed in `proofs/lean/Audit.lean` and locked in `proofs/tools/statements.golden`. `proofs/tools/check.sh` passes on this unit, including the QEMU tests (`tests/test_blake2s.c`) and the instruction-by-instruction comparison of the machine model with QEMU on BLAKE2s calls. The mutation run (`proofs/tools/mutate_blake2s.py`) was not repeated on this unit. No board measurement of BLAKE2s exists.
- Review guide: `proofs/docs/REVIEW.md` still describes 0.2.0. The BLAKE2s review notes (`proofs/REVIEW-blake2s.md`) are a draft written for an earlier unit.

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
