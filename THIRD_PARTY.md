# Third-party material

`tests/aead_vectors.h` contains transformed test data from Wycheproof's `chacha20_poly1305_test.json` (SHA-256 `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d`). Wycheproof is licensed under [Apache-2.0](LICENSES/Apache-2.0.txt). The generated header selects 96-bit-nonce test cases and stores their byte strings in C arrays. Upstream repository: https://github.com/C2SP/wycheproof.

The header also contains [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) vectors and values generated using pyca/cryptography 50.0.1. No pyca implementation code is included.

Benchmark dependencies are fetched separately into ignored `bench/third_party/`:

- wolfSSL v5.9.4-stable: GPL-3.0 / commercial licensing.
- Monocypher 4.0.2: BSD-2-Clause / CC0 dual license.
- OpenSSL 3.5.0: Apache-2.0.

Each fetched checkout retains its upstream license. These sources are used exclusively by the benchmark comparison binaries. `tools/build_lib.sh` builds the release library independently without third-party dependencies.
