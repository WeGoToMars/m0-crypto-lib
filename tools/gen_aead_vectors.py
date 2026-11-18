#!/usr/bin/env python3
"""Generate tests/aead_vectors.h: expected values for the AEAD tests on QEMU.

    python3 -P tools/gen_aead_vectors.py WYCHEPROOF_JSON > tests/aead_vectors.h

Oracles, none of them this library's code:
  - Wycheproof chacha20_poly1305_test.json (96-bit nonce groups: valid and
    modified-tag cases) from the Wycheproof repository's testvectors_v1, pinned by
    SHA-256 below. The generated header is committed, so the library builds without it.
  - pyca/cryptography (OpenSSL) ChaCha20Poly1305 and Poly1305, for extra random and
    edge-case vectors. Every Wycheproof vector is also cross-checked against it.
  - RFC 8439 sections 2.5.2 and 2.8.2: their published tags are asserted here.
Deterministic: fixed seed; same inputs give the same header.
"""
import hashlib
import json
import random
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidTag
import cryptography

WYCHEPROOF_SHA256 = "fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d"

blob = bytearray()


def put(b):
    off = len(blob)
    blob.extend(b)
    return off


def poly_ref(key, msg):
    """Textbook Poly1305 with Python integers (RFC 8439 section 2.5.1)."""
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: tools/gen_aead_vectors.py WYCHEPROOF_JSON > tests/aead_vectors.h")
    path = sys.argv[1]
    raw = open(path, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != WYCHEPROOF_SHA256:
        sys.exit(f"Wycheproof JSON sha256 {got} != pinned {WYCHEPROOF_SHA256}")
    wp = json.loads(raw)

    aead = []   # (key, nonce, aad, pt, ct, tag, valid, source)

    # RFC 8439 2.8.2
    key = bytes(range(0x80, 0xa0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
          b"tip for the future, sunscreen would be it.")
    out = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert out[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 2.8.2 tag"
    assert out[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2", "RFC 8439 2.8.2 ct"
    aead.append((key, nonce, aad, pt, out[:-16], out[-16:], 1, 0))

    # Wycheproof, 96-bit nonce groups only (the API takes a 96-bit nonce).
    nwp = 0
    for g in wp["testGroups"]:
        if g["ivSize"] != 96 or g["keySize"] != 256 or g["tagSize"] != 128:
            continue
        for t in g["tests"]:
            k, n, a, m, c, tg = (bytes.fromhex(t[x]) for x in ("key", "iv", "aad", "msg", "ct", "tag"))
            valid = t["result"] == "valid"
            assert t["result"] in ("valid", "invalid"), t["tcId"]
            ref = ChaCha20Poly1305(k)
            if valid:
                assert ref.encrypt(n, m, a) == c + tg, f"wycheproof {t['tcId']}"
            else:
                try:
                    ref.decrypt(n, c + tg, a)
                    raise AssertionError(f"wycheproof {t['tcId']} accepted")
                except InvalidTag:
                    pass
            aead.append((k, n, a, m, c, tg, int(valid), 1))
            nwp += 1

    # Random vectors from pyca/cryptography over block-boundary lengths.
    rnd = random.Random(20261104)
    aad_lens = [0, 1, 12, 15, 16, 17, 31, 32, 33, 64]
    pt_lens = [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 191, 192,
               193, 255, 256, 257, 500, 1000]
    nrand = 0
    for i, pl in enumerate(pt_lens):
        for al in (aad_lens[i % len(aad_lens)], aad_lens[(3 * i + 5) % len(aad_lens)]):
            k = rnd.randbytes(32)
            n = rnd.randbytes(12)
            a = rnd.randbytes(al)
            m = rnd.randbytes(pl)
            out = ChaCha20Poly1305(k).encrypt(n, m, a)
            aead.append((k, n, a, m, out[:-16], out[-16:], 1, 2))
            nrand += 1

    # Poly1305 alone (internal functions): RFC 2.5.2 plus edge and random cases.
    poly = []   # (key, msg, tag)
    k = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    m = b"Cryptographic Forum Research Group"
    assert poly_ref(k, m).hex() == "a8061dc1305136c6c22b8baf0c0127a9", "RFC 8439 2.5.2"
    poly.append((k, m))
    rmax = b"\xff" * 16                       # clamps to the largest r
    for key in (rmax + b"\xff" * 16, rmax + b"\x00" * 16, b"\x00" * 32,
                bytes.fromhex("02") + b"\x00" * 15 + b"\x00" * 16,
                bytes.fromhex("01") + b"\x00" * 15 + b"\xff" * 16):
        for msg in (b"", b"\xff" * 16, b"\xff" * 64, b"\xff" * 63, b"\x00" * 48,
                    b"\xff" * 16 + b"\x00" * 15 + b"\x01", rnd.randbytes(77)):
            poly.append((key, msg))
    for _ in range(40):
        poly.append((rnd.randbytes(32), rnd.randbytes(rnd.choice([1, 15, 16, 17, 33, 64, 95, 160]))))
    poly = [(k, m, poly_ref(k, m)) for k, m in poly]
    for k, m, tg in poly:
        h = Poly1305(k)
        h.update(m)
        assert h.finalize() == tg, "cryptography vs textbook Poly1305"

    rows = []
    for k, n, a, m, c, tg, valid, src in aead:
        rows.append((put(k), put(n), put(a), len(a), put(m), len(m), put(c), put(tg), valid, src))
    prows = [(put(k), put(m), len(m), put(tg)) for k, m, tg in poly]

    w = sys.stdout.write
    w("/* Generated by tools/gen_aead_vectors.py; do not edit. Test image only.\n")
    w(" * Wycheproof-derived data: Wycheproof project, Apache-2.0.\n")
    w(" * Transformed into C arrays; see THIRD_PARTY.md and LICENSES/Apache-2.0.txt.\n")
    w(f" * Wycheproof chacha20_poly1305_test.json sha256 {WYCHEPROOF_SHA256}\n")
    w(f" * ({nwp} vectors with 96-bit nonces), RFC 8439 2.8.2, {nrand} random vectors and\n")
    w(f" * {len(poly)} Poly1305 vectors from pyca/cryptography {cryptography.__version__}.\n */\n")
    w("#include <stdint.h>\n\n")
    w("struct aead_vec { uint32_t key, nonce, aad, aad_len, in, len, ct, tag;"
      " uint8_t valid, source; };\n")
    w("struct poly_vec { uint32_t key, msg, len, tag; };\n\n")
    w("static const uint8_t vec_blob[] = {\n")
    for i in range(0, len(blob), 24):
        w("    " + ", ".join(f"0x{b:02x}" for b in blob[i:i + 24]) + ",\n")
    w("};\n\n")
    w("/* source: 0 = RFC 8439 2.8.2, 1 = Wycheproof, 2 = random (pyca/cryptography) */\n")
    w("static const struct aead_vec aead_vecs[] = {\n")
    for r in rows:
        w("    {" + ", ".join(str(x) for x in r) + "},\n")
    w("};\n\n")
    w("static const struct poly_vec poly_vecs[] = {\n")
    for r in prows:
        w("    {" + ", ".join(str(x) for x in r) + "},\n")
    w("};\n")


if __name__ == "__main__":
    main()
