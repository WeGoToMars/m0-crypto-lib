#!/usr/bin/env python3
"""Generate tests/x25519_vectors.h: expected values for the on-target X25519 test.

    python3 -P tools/gen_x25519_vectors.py [WYCHEPROOF_JSON] > tests/x25519_vectors.h

Oracles, none of them this library's code:
  - Wycheproof x25519_test.json (every test: valid and "acceptable", including low-order,
    twist and non-canonical u >= p points), pinned by SHA-256 below. Default path: the private
    research archive; the generated header is committed, so the library builds without it.
  - RFC 7748 sections 5.2 (two vectors, the iterated value after 1, 1,000 and 1,000,000
    iterations) and 6.1 (Diffie-Hellman): their published values are asserted here.
  - A textbook RFC 7748 section 5 model in Python integers (`x25519` below), and
    pyca/cryptography (OpenSSL) X25519: every vector is cross-checked against both (pyca
    rejects an all-zero result, so for those only the model is compared).
The overlap expectations (buffers sharing bytes) come from the Python model and pyca.
Deterministic: same inputs give the same header.
"""
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import cryptography

WYCHEPROOF_SHA256 = "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d"
DEFAULT_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "m0-crypto-research",
    "sources", "raw", "wycheproof", "35c3f5231cf25cc6", "testvectors_v1", "x25519_test.json")

P = 2 ** 255 - 19
SOURCES = ("RFC 7748 5.2", "RFC 7748 6.1", "Wycheproof")


def x25519(k, u):
    """RFC 7748 section 5, written out with Python integers."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = x2 + z2, x2 - z2
        aa, bb = a * a, b * b
        e = aa - bb
        c, d = x3 + z3, x3 - z3
        da, cb = d * a, c * b
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def oracle(k, u):
    """The model's result, cross-checked against pyca/cryptography."""
    r = x25519(k, u)
    try:
        got = X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
    except ValueError:   # pyca rejects an all-zero shared secret
        assert r == bytes(32), (k.hex(), u.hex())
    else:
        assert got == r, (k.hex(), u.hex())
    return r


def iterate(n):
    k = u = (9).to_bytes(32, "little")
    for _ in range(n):
        k, u = x25519(k, u), k
    return k


# Overlap test: a 96-byte region of this pattern; the scalar is at offset 32 and the point at
# offset 32 + d for d in -32..32 (d = 0: the same buffer). The test writes out at several
# offsets inside the same region.
def region():
    return bytes((i * 251 + 13) & 0xFF for i in range(96))


OVERLAP_D = range(-32, 33)


def row(b):
    return "{" + ", ".join(f"0x{x:02x}" for x in b) + "}"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON
    raw = open(path, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != WYCHEPROOF_SHA256:
        sys.exit(f"Wycheproof JSON sha256 {got} != pinned {WYCHEPROOF_SHA256}")
    wp = json.loads(raw)

    vecs = []   # (scalar, point, shared, source, id)
    h = bytes.fromhex
    # RFC 7748 section 5.2 (the second u has bit 255 set: masked).
    for i, (k, u, r) in enumerate((
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"))):
        assert oracle(h(k), h(u)) == h(r), f"RFC 7748 5.2 vector {i + 1}"
        vecs.append((h(k), h(u), h(r), 0, i + 1))
    # RFC 7748 section 6.1: both public keys from the base point 9, then the shared secret both ways.
    a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    a_pub = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    b_pub = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    nine = (9).to_bytes(32, "little")
    for i, (k, u, r) in enumerate(((a, nine, a_pub), (b, nine, b_pub), (a, b_pub, shared),
                                   (b, a_pub, shared))):
        assert oracle(k, u) == r, f"RFC 7748 6.1 computation {i + 1}"
        vecs.append((k, u, r, 1, i + 1))
    # Wycheproof: every test. The function has no low-order check and no failure result, so
    # "acceptable" vectors are compared on their output bytes like "valid" ones.
    nwp = 0
    for g in wp["testGroups"]:
        assert g["curve"] == "curve25519" and g["type"] == "XdhComp", g.get("curve")
        for t in g["tests"]:
            assert t["result"] in ("valid", "acceptable"), t["tcId"]
            k, u, r = h(t["private"]), h(t["public"]), h(t["shared"])
            assert len(k) == len(u) == len(r) == 32, t["tcId"]
            assert oracle(k, u) == r, f"Wycheproof tcId {t['tcId']}"
            vecs.append((k, u, r, 2, t["tcId"]))
            nwp += 1
    assert nwp == wp["numberOfTests"], (nwp, wp["numberOfTests"])

    iters = {1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
             1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"}
    for n, want in iters.items():
        assert iterate(n).hex() == want, f"RFC 7748 5.2 after {n} iterations"
    # Published, not recomputed here (about an hour of Python).
    iter_1m = "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"

    reg = region()
    overlap = [oracle(reg[32:64], reg[32 + d:64 + d]) for d in OVERLAP_D]

    print("/* Generated by tools/gen_x25519_vectors.py; do not edit. Test image only.")
    print(" * Wycheproof-derived data: Wycheproof project, Apache-2.0.")
    print(" * Transformed into C arrays; see THIRD_PARTY.md and LICENSES/Apache-2.0.txt.")
    print(f" * Wycheproof x25519_test.json sha256 {WYCHEPROOF_SHA256}")
    print(f" * ({nwp} vectors, valid and acceptable), RFC 7748 sections 5.2 and 6.1. Every value was")
    print(f" * cross-checked against a Python RFC 7748 model and pyca/cryptography {cryptography.__version__}.")
    print(" */")
    print("#include <stdint.h>")
    print()
    print("/* source: " + ", ".join(f"{i} = {s}" for i, s in enumerate(SOURCES)) +
          "; id: vector number or Wycheproof tcId. */")
    print("struct x25519_vec { uint8_t scalar[32], point[32], shared[32]; uint8_t source; uint16_t id; };")
    print(f"#define X25519_VEC_COUNT {len(vecs)}")
    print("static const struct x25519_vec x25519_vecs[X25519_VEC_COUNT] = {")
    for k, u, r, src, i in vecs:
        print(f"    {{{row(k)}, {row(u)}, {row(r)}, {src}, {i}}},")
    print("};")
    print()
    print("/* RFC 7748 section 5.2: k = u = 9, then k, u = X25519(k, u), k; k after n iterations. */")
    print(f"static const uint8_t x25519_iter_1[32] = {row(h(iters[1]))};")
    print(f"static const uint8_t x25519_iter_1000[32] = {row(h(iters[1000]))};")
    print(f"static const uint8_t x25519_iter_1000000[32] = {row(h(iter_1m))};")
    print()
    print("/* Overlap: a 96-byte region R[i] = X25519_REGION(i); scalar at R + 32, point at R + 32 + d,")
    print(" * x25519_overlap[d + 32] = X25519(R[32..64), R[32 + d..64 + d)) for d in -32..32. */")
    print("#define X25519_REGION(i) ((uint8_t)((i) * 251u + 13u))")
    print("static const uint8_t x25519_overlap[65][32] = {")
    for r in overlap:
        print(f"    {row(r)},")
    print("};")


if __name__ == "__main__":
    main()
