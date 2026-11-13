/*
 * m0-crypto library: X25519 (RFC 7748), one relocation-free release unit.
 * SPDX-License-Identifier: MIT
 *
 * Every call inside the unit targets a local label, so the assembler resolves it and the
 * object has no relocations: its .text bytes are the same at any 4-byte-aligned link
 * address (tools/build_lib.sh checks this). The unit is released and verified on its own.
 */
#define M0C_UNIT 1
#include "x25519.S"
