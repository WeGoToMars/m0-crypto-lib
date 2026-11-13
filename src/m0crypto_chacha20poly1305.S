/*
 * m0-crypto library: ChaCha20 and ChaCha20-Poly1305 (RFC 8439), one relocation-free release unit.
 * SPDX-License-Identifier: MIT
 *
 * Every call inside the unit targets a local label, so the assembler resolves it and the
 * object has no relocations: its .text bytes are the same at any 4-byte-aligned link
 * address (tools/build_lib.sh checks this). The unit is released and verified on its own.
 * m0c_chacha20_xor is first, at offset 0: tools/test_qemu.sh locates the internal Poly1305
 * entry points relative to it.
 */
#define M0C_UNIT 1
#include "chacha20.S"
    .p2align 2
#include "chacha20poly1305.S"
