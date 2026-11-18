#!/usr/bin/env python3
"""Fetch pinned sources and build one primitive's ARMv6-M comparison image.

Run from the library root: python3 bench/build.py PRIMITIVE
(PRIMITIVE: chacha20poly1305, blake2s or x25519)
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
THIRD_PARTY = BENCH / "third_party"
WOLFSSL = THIRD_PARTY / "wolfssl"
CLANG = "clang"
LINKER = "ld.lld"
TOOLCHAIN_VERSION = "23.1.4"
WOLFSSL_TAG = "v5.9.4-stable"
WOLFSSL_COMMIT = "3c5eead44904df64e6a5a1f4ebdce377d35a849a"
WOLF_SRC = WOLFSSL / "wolfcrypt/src"
# Mbed TLS 4.3.0 release archive: its tf-psa-crypto/ directory holds the cryptography,
# including the generated PSA driver wrappers that the git tree lacks.
MBEDTLS_VERSION = "4.3.0"
MBEDTLS_URL = (
    "https://github.com/Mbed-TLS/mbedtls/releases/download/"
    f"mbedtls-{MBEDTLS_VERSION}/mbedtls-{MBEDTLS_VERSION}.tar.bz2"
)
MBEDTLS_SHA256 = "1c87cba094cb40f097ebe0eba440a74939b71dab4e1d0d566bc90749ff381d18"
MBEDTLS_ARCHIVE = THIRD_PARTY / f"mbedtls-{MBEDTLS_VERSION}.tar.bz2"
TF_PSA = THIRD_PARTY / f"mbedtls-{MBEDTLS_VERSION}/tf-psa-crypto"
# Library source directories, as upstream's core/crypto-library.make lists them.
TF_PSA_SOURCE_DIRECTORIES = (
    "core", "drivers/builtin/src", "dispatch", "extras", "platform", "utilities",
)


def mbedtls_sources() -> list[Path]:
    return sorted(
        path for directory in TF_PSA_SOURCE_DIRECTORIES
        for path in (TF_PSA / directory).glob("*.c")
    )


def mbedtls_flags(primitive: str) -> list[str]:
    """Include directories of a TF-PSA-Crypto build and the image's configuration."""
    flags = [f'-DTF_PSA_CRYPTO_CONFIG_FILE="crypto_config_{primitive}.h"',
             "-I", str(BENCH / "mbedtls")]
    for directory in (
        "include", "drivers/builtin/include", "drivers/everest/include", "drivers/pqcp/include",
        "drivers/p256-m", *TF_PSA_SOURCE_DIRECTORIES,
    ):
        flags.extend(["-I", str(TF_PSA / directory)])
    return flags

# Shared freestanding runtime: linked into every image, counted in cycles, not in code size.
RUNTIME = [BENCH / "runtime.c", BENCH / "lmul.S"]

# Per primitive: wrapper names run_IMPL_OP, the harness files and, per comparator, its
# sources (code size is summed per comparator from the link map; Mbed TLS's list is
# taken after the fetch), the harness files compiled with the Mbed TLS configuration,
# wolfSSL feature macros,
# the header whose macro dump records wolfSSL's effective backend, and the backend
# macros worth printing.
PRIMITIVES = {
    "chacha20poly1305": {
        "implementations": ("m0c", "wolf", "mono", "ossl", "mbed"),
        "operations": ("chacha", "encrypt", "decrypt"),
        "harness": [
            BENCH / "harness/chacha20poly1305.c",
            BENCH / "harness/chacha20poly1305_mbed.c",
            BENCH / "harness/mbedtls_platform.c",
        ],
        "mbed_harness": ("chacha20poly1305_mbed.c", "mbedtls_platform.c"),
        "setup": ("mbed",),
        "sources": {
            "mbed": mbedtls_sources,
            "mono": [THIRD_PARTY / "monocypher/src/monocypher.c"],
            "ossl": [
                THIRD_PARTY / "openssl/crypto/chacha/chacha_enc.c",
                THIRD_PARTY / "openssl/crypto/poly1305/poly1305.c",
            ],
            "wolf": [
                WOLF_SRC / "chacha.c",
                WOLF_SRC / "poly1305.c",
                WOLF_SRC / "chacha20_poly1305.c",
            ],
        },
        "defines": [],  # HAVE_CHACHA, HAVE_POLY1305 come from user_settings.h
        "backend_header": "wolfssl/wolfcrypt/poly1305.h",
        "backend_macros": {
            "POLY130532",
            "POLY130564",
            "WORD64_AVAILABLE",
            "WOLFSSL_W64_WRAPPER",
            "WOLFSSL_ARMASM",
            "WOLFSSL_ARMASM_THUMB2",
            "WOLFSSL_SP_MATH_ALL",
            "USE_FAST_MATH",
            "WOLFSSL_NO_ASM",
            "NO_CHACHA_ASM",
        },
    },
    "blake2s": {
        "implementations": ("m0c", "wolf", "ref", "ossl"),
        "operations": ("hash", "stream"),
        "harness": [
            BENCH / "harness/blake2s.c",
            BENCH / "harness/blake2s_ref.c",
            BENCH / "harness/blake2s_ossl.c",
        ],
        "sources": {
            "wolf": [WOLF_SRC / "blake2s.c"],
            "ref": [THIRD_PARTY / "blake2/ref/blake2s-ref.c"],
            "ossl": [THIRD_PARTY / "openssl/providers/implementations/digests/blake2s_prov.c"],
        },
        "defines": ["-DHAVE_BLAKE2S"],
        "file_flags": {
            name: ["-include", str(BENCH / "compat/blake2_ref_names.h")]
            for name in ("blake2s_ref.c", "blake2s-ref.c")
        },
        "backend_header": "wolfssl/wolfcrypt/blake2.h",
        "backend_macros": {"HAVE_BLAKE2S", "WOLFSSL_ARMASM", "WOLFSSL_NO_ASM"},
    },
    "x25519": {
        "implementations": ("m0c", "pornin", "wolf", "mono", "ossl", "mbed"),
        "operations": ("shared", "public"),
        "harness": [
            BENCH / "harness/x25519.c",
            BENCH / "harness/x25519_mbed.c",
            BENCH / "harness/mbedtls_platform.c",
        ],
        "mbed_harness": ("x25519_mbed.c", "mbedtls_platform.c"),
        "setup": ("mbed",),
        "sources": {
            "mbed": mbedtls_sources,
            "pornin": [THIRD_PARTY / "x25519-cm0/src/x25519-cm0.S"],
            "wolf": [WOLF_SRC / "curve25519.c", WOLF_SRC / "fe_operations.c"],
            "mono": [THIRD_PARTY / "monocypher/src/monocypher.c"],
            "ossl": [THIRD_PARTY / "openssl/crypto/ec/curve25519.c"],
        },
        "defines": ["-DHAVE_CURVE25519", "-DWC_NO_HASHDRBG"],  # no RNG in the image
        "backend_header": "wolfssl/wolfcrypt/curve25519.h",
        "backend_macros": {
            "CURVE25519_SMALL",
            "CURVED25519_SMALL",
            "CURVED25519_128BIT",
            "CURVED25519_ASM",
            "WOLFSSL_CURVE25519_BLINDING",
            "WOLFSSL_CURVE25519_NOT_USE_ED25519",
            "WOLFSSL_ARMASM",
            "WOLFSSL_NO_ASM",
            "WC_NO_RNG",
        },
    },
}


def run(*arguments) -> None:
    subprocess.run([str(argument) for argument in arguments], check=True)


def capture(*arguments) -> str:
    command = [str(argument) for argument in arguments]
    return subprocess.check_output(command, text=True).strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_toolchain() -> tuple[str, str]:
    clang_version = capture(CLANG, "--version").splitlines()[0]
    linker_version = capture(LINKER, "--version")
    if clang_version.split("clang version ")[-1].split()[0] != TOOLCHAIN_VERSION:
        raise SystemExit(f"expected clang {TOOLCHAIN_VERSION}: {clang_version}")
    if linker_version.split("LLD ")[-1].split()[0] != TOOLCHAIN_VERSION:
        raise SystemExit(f"expected LLD {TOOLCHAIN_VERSION}: {linker_version}")
    return clang_version, linker_version


def fetch_locked_sources(sources: list[dict]) -> None:
    for source in sources:
        destination = THIRD_PARTY / source["path"]
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(source["url"], timeout=60) as response:
                destination.write_bytes(response.read())
        if sha256(destination) != source["sha256"]:
            raise SystemExit(f"source checksum mismatch: {destination}")


def fetch_mbedtls() -> None:
    """Download the pinned archive once, and extract a fresh tree from it on every build, so
    the compiled sources are always the checksummed ones."""
    if not MBEDTLS_ARCHIVE.exists():
        THIRD_PARTY.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(MBEDTLS_URL, timeout=120) as response:
            MBEDTLS_ARCHIVE.write_bytes(response.read())
    if sha256(MBEDTLS_ARCHIVE) != MBEDTLS_SHA256:
        raise SystemExit(f"source checksum mismatch: {MBEDTLS_ARCHIVE}")
    shutil.rmtree(TF_PSA.parent, ignore_errors=True)
    with tarfile.open(MBEDTLS_ARCHIVE) as archive:
        archive.extractall(THIRD_PARTY, filter="data")


def fetch_wolfssl() -> None:
    if not WOLFSSL.exists():
        run(
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            WOLFSSL_TAG,
            "https://github.com/wolfSSL/wolfssl.git",
            WOLFSSL,
        )
    commit = capture("git", "-C", WOLFSSL, "rev-parse", "HEAD")
    changes = capture("git", "-C", WOLFSSL, "status", "--porcelain")
    if commit != WOLFSSL_COMMIT or changes:
        raise SystemExit(f"wolfSSL must be a clean checkout of {WOLFSSL_COMMIT}")


def compiler_flags(optimization: str, config: dict) -> list[str]:
    flags = [
        "--target=thumbv6m-none-eabi",
        "-mcpu=cortex-m0plus",
        "-mthumb",
        optimization,
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        "-DWOLFSSL_USER_SETTINGS",
        "-DOPENSSL_NO_ASM",
        *config["defines"],
    ]
    include_directories = [
        ROOT / "include",
        ROOT / "src",
        BENCH / "compat",
        BENCH / "compat/libc",
        BENCH,
        WOLFSSL,
        THIRD_PARTY / "monocypher/src",
        THIRD_PARTY / "openssl/include",
        THIRD_PARTY / "openssl/providers/implementations/include",
    ]
    for directory in include_directories:
        flags.extend(["-I", str(directory)])
    return flags


def compile_sources(
    flags: list[str], primitive: str, config: dict, output: Path
) -> tuple[list[Path], dict[Path, str]]:
    """Compile every source; return the objects and the comparator owning each one."""
    m0c_object = ROOT / f"build/lib/{primitive}/m0crypto_{primitive}.o"
    owners = {m0c_object: "m0c"}
    sources = [(source, None) for source in config["harness"] + RUNTIME]
    for implementation, paths in config["sources"].items():
        paths = paths() if callable(paths) else paths
        sources.extend((path, implementation) for path in paths)
    for stale in output.glob("[0-9]*-*.o"):  # build_compare.sh links every numbered object
        stale.unlink()
    objects = [m0c_object]
    for index, (source, owner) in enumerate(sources):
        destination = output / f"{index}-{source.stem}.o"
        extra_flags = []
        if source == BENCH / "runtime.c":
            extra_flags.append("-fno-builtin")
        extra_flags += config.get("file_flags", {}).get(source.name, [])
        if owner == "mbed" or source.name in config.get("mbed_harness", ()):
            extra_flags += mbedtls_flags(primitive)
        run(CLANG, *flags, *extra_flags, "-c", source, "-o", destination)
        objects.append(destination)
        if owner:
            owners[destination] = owner
    return objects, owners


def link_image(objects: list[Path], config: dict, output: Path) -> None:
    # Keep every wrapper even though this image has no firmware startup routine.
    roots = [
        f"--undefined=run_{implementation}_{operation}"
        for implementation in config["implementations"]
        for operation in config["operations"]
    ]
    # One-time initialisation that armv6m.py and the board image run before timing.
    roots += [f"--undefined=setup_{implementation}" for implementation in config.get("setup", ())]
    run(
        LINKER,
        "-T",
        BENCH / "link.ld",
        "--gc-sections",
        "--build-id=none",
        f"--entry=run_m0c_{config['operations'][0]}",
        *roots,
        f"-Map={output / 'bench.map'}",
        "-o",
        output / "bench.elf",
        *objects,
    )


# lld map line of an input section: VMA LMA Size Align then "file.o:(section)".
MAP_INPUT = re.compile(r"^\s*[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)\s+\d+\s+(\S+\.o):\((\S+)\)")


def section_bytes(
    map_path: Path, owners: dict[Path, str], prefixes: tuple[str, ...]
) -> dict[str, int]:
    """Bytes of linked input sections with these name prefixes per comparator, after
    --gc-sections. Harness and shared runtime sections are not counted."""
    sizes = {implementation: 0 for implementation in owners.values()}
    by_name = {str(path): owner for path, owner in owners.items()}
    for line in map_path.read_text().splitlines():
        match = MAP_INPUT.match(line)
        if match and match[2] in by_name and match[3].startswith(prefixes):
            sizes[by_name[match[2]]] += int(match[1], 16)
    return sizes


def record_wolfssl_backend(flags: list[str], config: dict, output: Path) -> list[str]:
    macro_dump = capture(
        CLANG,
        *flags,
        "-dM",
        "-E",
        "-include",
        config["backend_header"],
        "-x",
        "c",
        "/dev/null",
    )
    (output / "wolfssl-backend.txt").write_text(macro_dump + "\n")
    selected = []
    for line in macro_dump.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in config["backend_macros"]:
            selected.append(line)
    print("wolfSSL effective backend: " + "; ".join(selected))
    return selected


def local_input_hashes() -> dict[str, str]:
    paths = list((ROOT / "src").glob("*"))
    for path in BENCH.rglob("*"):
        if (
            path.is_file()
            and "third_party" not in path.parts
            and "__pycache__" not in path.parts
        ):
            paths.append(path)
    return {str(path.relative_to(ROOT)): sha256(path) for path in sorted(paths)}


def write_manifest(
    primitive: str,
    output: Path,
    code_sizes: dict[str, int],
    ram_sizes: dict[str, int],
    clang_version: str,
    linker_version: str,
    optimization: str,
    flags: list[str],
    sources: list[dict],
    backend: list[str],
) -> None:
    manifest = {
        "primitive": primitive,
        "wolfssl_backend": backend,
        "clang": clang_version,
        "lld": linker_version,
        "flags": flags,
        "opt": optimization,
        "target": "thumbv6m-none-eabi cortex-m0plus",
        "wolfssl_commit": WOLFSSL_COMMIT,
        "mbedtls": {"version": MBEDTLS_VERSION, "url": MBEDTLS_URL, "sha256": MBEDTLS_SHA256},
        "sources": sources,
        "inputs": local_input_hashes(),
        "m0c_text_sha256": sha256(ROOT / f"build/lib/{primitive}/text.bin"),
        "code_bytes": code_sizes,
        "static_ram_bytes": ram_sizes,
        "elf_sha256": sha256(output / "bench.elf"),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primitive", choices=PRIMITIVES)
    primitive = parser.parse_args().primitive
    config = PRIMITIVES[primitive]
    optimization = os.environ.get("BENCH_OPT", "-Os")
    if optimization not in {"-Os", "-O2", "-O3"}:
        raise SystemExit("BENCH_OPT must be -Os, -O2 or -O3")

    output = ROOT / "build/bench" / primitive
    output.mkdir(parents=True, exist_ok=True)
    clang_version, linker_version = check_toolchain()
    sources = json.loads((BENCH / "sources.lock.json").read_text())
    fetch_locked_sources(sources)
    fetch_wolfssl()
    if "mbed" in config["implementations"]:
        fetch_mbedtls()
    run(ROOT / "tools/build_lib.sh", primitive)
    flags = compiler_flags(optimization, config)
    objects, owners = compile_sources(flags, primitive, config, output)
    link_image(objects, config, output)
    code_sizes = section_bytes(output / "bench.map", owners, (".text", ".rodata"))
    ram_sizes = section_bytes(output / "bench.map", owners, (".data", ".bss"))
    print("code bytes (" + optimization + "): " + ", ".join(f"{k} {v}" for k, v in code_sizes.items()))
    print("static RAM bytes: " + ", ".join(f"{k} {v}" for k, v in ram_sizes.items() if v))
    backend = record_wolfssl_backend(flags, config, output)
    write_manifest(
        primitive, output, code_sizes, ram_sizes, clang_version, linker_version,
        optimization, flags, sources, backend,
    )
    print(output / "bench.elf")


if __name__ == "__main__":
    main()
