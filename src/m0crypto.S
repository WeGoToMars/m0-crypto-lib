/*
 * m0-crypto library: the one translation unit that is the release artifact.
 * SPDX-License-Identifier: MIT
 *
 * Every call between library functions targets a local label in this unit, so the
 * assembler resolves it and the object has no relocations: its .text bytes are the
 * same at any 4-byte-aligned link address (tools/build_lib.sh checks this).
 * m0c_chacha20_xor is first, so its bytes equal the standalone src/chacha20.S
 * object used by the ChaCha20-only benchmark.
 */
#define M0C_UNIT 1
#include "chacha20.S"
    .p2align 2
#include "chacha20poly1305.S"
    .p2align 2
#include "blake2s_compress.S"
    .p2align 2
#include "blake2s_copy.S"
    .p2align 2
#include "blake2s_stream.S"
