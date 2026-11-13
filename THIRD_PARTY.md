# Third-party material

`tests/aead_vectors.h` contains transformed test data from Wycheproof's `chacha20_poly1305_test.json` (SHA-256 `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d`). Wycheproof is licensed under [Apache-2.0](LICENSES/Apache-2.0.txt). The generated header selects 96-bit-nonce test cases and stores their byte strings in C arrays. Upstream repository: https://github.com/C2SP/wycheproof.

The header also contains [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) vectors and values generated using pyca/cryptography 50.0.1. No pyca implementation code is included.

`tests/x25519_vectors.h` contains transformed test data from Wycheproof's `x25519_test.json` (SHA-256 `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d`), under the same Apache-2.0 license: all 518 test cases, their private key, public key and shared secret stored in C arrays. It also contains [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) vectors; every value was cross-checked against pyca/cryptography 50.0.1 (no pyca code is included).

Benchmark dependencies are fetched separately into ignored `bench/third_party/`:

- wolfSSL v5.9.4-stable: GPL-3.0 / commercial licensing.
- Monocypher 4.0.2: BSD-2-Clause / CC0 dual license.
- OpenSSL 3.5.0: Apache-2.0.
- BLAKE2 reference implementation (commit `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`, `ref/blake2s-ref.c` and its headers): CC0 / OpenSSL / Apache-2.0, at the user's choice.
- x25519-cm0 by Thomas Pornin (commit `75a53f277d15acd9a0a8e220c8e26a48cc8974c2`, `src/x25519-cm0.S`): MIT.

The pinned URLs and SHA-256 hashes are in `bench/sources.lock.json`. Each fetched checkout retains its upstream license. These sources are used exclusively by the benchmark comparison binaries. `tools/build_lib.sh` builds the release library independently without third-party dependencies.
