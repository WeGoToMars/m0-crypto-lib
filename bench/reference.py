"""Independent RFC 8439 reference calculations used to check benchmark calls."""

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
