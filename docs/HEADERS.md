# Public header conventions

Public headers in `include/m0crypto/` document the C caller contract and the proved security guarantees of each release asset. Machine-level ABI preconditions (`Pre`), exact `Disj` allowances, the formal interrupt model (`K`, `Handlers`), and exact zeroed stack ranges belong in [`proofs/README.md`](../proofs/README.md) and [`proofs/docs/REVIEW.md`](../proofs/docs/REVIEW.md), never in `.h`.

## Soundness boundary

- **Caller preconditions imply `Pre`.** Every C call permitted by a header — compiled for ARMv6-M AAPCS32 and linked normally, with the stated stack budget — must satisfy the function's Lean `Pre`. Headers state idiomatic C rules that may be stricter than `Pre` (for example, forbidding `key` or `nonce` from overlapping `out`, even when a proof allows it).
- **Proved claims imply header guarantees.** Every behavioral, constant-time, memory/stack, clearing, and interrupt statement in a header must follow from the asset's audited claims in `proofs/assets/*/Audit.lean`.

## Structure and formatting

Headers are written for C programmers: every statement uses C-level terms and is checkable without reading the proofs. Each header uses plain `/* ... */` comments (no Doxygen `@`-tags), wrapped at 80 columns, in two levels:

1. **Top-of-file overview:**
   - `m0-crypto: <Primitive> (<RFC>).` and `SPDX-License-Identifier: MIT`.
   - `Verified in Lean 4 against the release machine code:` followed by five bullets in plain C terms (buffers, pointers, lengths, stack, interrupt handlers), with no proof or register vocabulary:
     - `Correct:` the result matches the RFC for every length, alignment and allowed overlap.
     - `Constant time:` the instructions executed and the memory addresses accessed depend only on addresses and the listed public values, never on the listed secrets.
     - `Memory:` what the function reads (its buffers, its own code, its stack) and writes (its outputs, its stack), within the listed stack size.
     - `Clean-up:` before it returns, the function erases every temporary value it computed from the secrets, so none is left on the stack, with any primitive-specific exception (AEAD decryption's verdict, the caller-owned `m0c_blake2s_ctx`). The bullet names the caller's buffers to wipe and says that interrupt frames are not covered. It does not mention registers: the exact registers and stack bytes are in [`proofs/README.md`](../proofs/README.md), and the proofs say nothing about the flags or LR.
     - `Interrupts:` allowed during a call, with the same result, if the caller reserves 36 bytes of stack beyond the listed size for each interrupt that can be active at once on the same stack, plus what handlers push on it, and handlers restore every register and flag and do not write the call's buffers or stack.
   - A last line linking the proofs repository (https://github.com/WeGoToMars/m0-crypto-proofs) for the exact conditions.
   - Omit platform, DMA and physical side-channel assumptions (documented in [`README.md`](../README.md)), `.text` byte sizes (pinned in `MANIFEST.txt` and [`proofs/README.md`](../proofs/README.md)), and Lean declaration names.

2. **Per-declaration docblocks:** Placed directly above every public `typedef struct` and function prototype so every symbol has standalone editor hover documentation.
   - Function docblocks start with a 1–2 sentence behavioral summary, followed by a blank `*` line and aligned key-value fields (including only those that apply, in this order):
     - `Returns:` status codes (`M0C_OK`, `M0C_ERR_*`) and output state on failure (omitted for `void`).
     - `Buffers:` alignment, idiomatic C overlap rules (`out == in` or non-overlapping writable outputs; arbitrary overlap for `x25519`), and zero-length behavior (not accessed, may be `NULL`, must not point into the middle of another buffer).
     - `Stack:` exact maximum stack bytes used by the function itself (`N bytes.`).
     - `Caution:` caller cryptographic or lifecycle obligations (nonce uniqueness, `< 2^64` stream length, wiping `m0c_blake2s_ctx`, consuming `*c` on `final`, no low-order point check).
