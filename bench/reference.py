"""Independent reference calculations used to check benchmark calls: ChaCha20-Poly1305
(RFC 8439), BLAKE2s-256 (RFC 7693) and X25519 (RFC 7748). Each is checked against its
RFC's test vectors before any benchmark call is compared with it."""

import struct

WORD_MASK = (1 << 32) - 1
POLY1305_MODULUS = (1 << 130) - 5
POLY1305_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
ROUND_SCHEDULE = (
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
)


def rotate_left(word: int, bits: int) -> int:
    return ((word << bits) | (word >> (32 - bits))) & WORD_MASK


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & WORD_MASK
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & WORD_MASK
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & WORD_MASK
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & WORD_MASK
    state[b] = rotate_left(state[b] ^ state[c], 7)


def chacha_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    initial = list(struct.unpack("<4I", b"expand 32-byte k"))
    initial.extend(struct.unpack("<8I", key))
    initial.append(counter)
    initial.extend(struct.unpack("<3I", nonce))
    state = initial.copy()

    for _ in range(10):
        for a, b, c, d in ROUND_SCHEDULE:
            quarter_round(state, a, b, c, d)

    words = [(word + original) & WORD_MASK for word, original in zip(state, initial)]
    return struct.pack("<16I", *words)


def chacha(key: bytes, nonce: bytes, message: bytes, counter: int = 1) -> bytes:
    output = bytearray()
    for offset in range(0, len(message), 64):
        keystream = chacha_block(key, nonce, counter)
        block = message[offset : offset + 64]
        output.extend(plain ^ stream for plain, stream in zip(block, keystream))
        counter += 1
    return bytes(output)


def tag_for(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    one_time_key = chacha(key, nonce, bytes(32), counter=0)
    multiplier = int.from_bytes(one_time_key[:16], "little") & POLY1305_CLAMP
    pad = int.from_bytes(one_time_key[16:], "little")
    mac_data = (
        aad
        + bytes(-len(aad) % 16)
        + ciphertext
        + bytes(-len(ciphertext) % 16)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )

    accumulator = 0
    for offset in range(0, len(mac_data), 16):
        block = int.from_bytes(mac_data[offset : offset + 16] + b"\x01", "little")
        accumulator = (accumulator + block) * multiplier % POLY1305_MODULUS

    return ((accumulator + pad) % (1 << 128)).to_bytes(16, "little")


def check_rfc_vector() -> None:
    """Check the reference against RFC 8439 section 2.8.2 before benchmarking."""
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    message = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    ciphertext = chacha(key, nonce, message)
    expected_prefix = bytes.fromhex("d31a8d34648e60db7b86afbc53ef7ec2")
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    if (
        ciphertext[:16] != expected_prefix
        or tag_for(key, nonce, aad, ciphertext) != expected_tag
    ):
        raise RuntimeError("Python reference fails RFC 8439 section 2.8.2")


# BLAKE2s (RFC 7693). The IV is the SHA-256 initial hash value.
BLAKE2S_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
BLAKE2S_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


def rotate_right(word: int, bits: int) -> int:
    return ((word >> bits) | (word << (32 - bits))) & WORD_MASK


def blake2s_compress(h: list[int], block: bytes, count: int, last: bool) -> None:
    m = struct.unpack("<16I", block)
    v = h + list(BLAKE2S_IV)
    v[12] ^= count & WORD_MASK
    v[13] ^= count >> 32
    if last:
        v[14] ^= WORD_MASK
    for sigma in BLAKE2S_SIGMA:
        for i, (a, b, c, d) in enumerate(ROUND_SCHEDULE):
            x, y = m[sigma[2 * i]], m[sigma[2 * i + 1]]
            v[a] = (v[a] + v[b] + x) & WORD_MASK
            v[d] = rotate_right(v[d] ^ v[a], 16)
            v[c] = (v[c] + v[d]) & WORD_MASK
            v[b] = rotate_right(v[b] ^ v[c], 12)
            v[a] = (v[a] + v[b] + y) & WORD_MASK
            v[d] = rotate_right(v[d] ^ v[a], 8)
            v[c] = (v[c] + v[d]) & WORD_MASK
            v[b] = rotate_right(v[b] ^ v[c], 7)
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]


def blake2s(message: bytes) -> bytes:
    """Unkeyed BLAKE2s with a 32-byte digest."""
    h = list(BLAKE2S_IV)
    h[0] ^= 0x01010000 ^ 32
    full_blocks = max(0, (len(message) - 1) // 64)
    for index in range(full_blocks):
        block = message[64 * index : 64 * index + 64]
        blake2s_compress(h, block, 64 * (index + 1), last=False)
    tail = message[64 * full_blocks :]
    blake2s_compress(h, tail + bytes(64 - len(tail)), len(message), last=True)
    return struct.pack("<8I", *h)


def check_blake2s_vector() -> None:
    """Check the reference against RFC 7693 appendix B before benchmarking."""
    expected = bytes.fromhex(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
    )
    if blake2s(b"abc") != expected:
        raise RuntimeError("Python reference fails RFC 7693 appendix B")


# X25519 (RFC 7748 section 5).
X25519_PRIME = (1 << 255) - 19


def clamp_scalar(scalar: bytes) -> bytes:
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] = (clamped[31] & 127) | 64
    return bytes(clamped)


def x25519(scalar: bytes, point: bytes) -> bytes:
    k = int.from_bytes(clamp_scalar(scalar), "little")
    u = int.from_bytes(point, "little") & ((1 << 255) - 1)
    p = X25519_PRIME
    x2, z2, x3, z3, swap = 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = u * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


# RFC 7748 section 6.1 key pair, used by the benchmark workloads.
ALICE_PRIVATE = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
BOB_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)


def check_x25519_vectors() -> None:
    """Check the reference against RFC 7748 sections 5.2 and 6.1 before benchmarking."""
    vectors = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
        (
            ALICE_PRIVATE.hex(),
            "09" + "00" * 31,
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ),
        (
            ALICE_PRIVATE.hex(),
            BOB_PUBLIC.hex(),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        ),
    ]
    for scalar, point, expected in vectors:
        if x25519(bytes.fromhex(scalar), bytes.fromhex(point)) != bytes.fromhex(expected):
            raise RuntimeError("Python reference fails RFC 7748 sections 5.2 and 6.1")
