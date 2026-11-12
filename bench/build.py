#!/usr/bin/env python3
"""Fetch pinned sources and build the ARMv6-M comparison image.

Run from the library root: python3 bench/build.py
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
OUTPUT = ROOT / "build/bench"
THIRD_PARTY = BENCH / "third_party"
WOLFSSL = THIRD_PARTY / "wolfssl"
LLVM_BIN = Path(os.environ.get("LLVM_BIN", "/opt/homebrew/opt/llvm/bin"))
LLD_BIN = Path(os.environ.get("LLD_BIN", "/opt/homebrew/opt/lld/bin"))
CLANG = LLVM_BIN / "clang"
LINKER = LLD_BIN / "ld.lld"
TOOLCHAIN_VERSION = "23.1.4"
WOLFSSL_TAG = "v5.9.4-stable"
WOLFSSL_COMMIT = "3c5eead44904df64e6a5a1f4ebdce377d35a849a"
IMPLEMENTATIONS = ("m0c", "wolf", "mono", "ossl")
OPERATIONS = ("chacha", "encrypt", "decrypt")
BACKEND_MACROS = {
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


def compiler_flags(optimization: str) -> list[str]:
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
    ]
    for directory in include_directories:
        flags.extend(["-I", str(directory)])
    return flags


def compile_sources(flags: list[str]) -> list[Path]:
    sources = [
        BENCH / "harness.c",
        BENCH / "runtime.c",
        BENCH / "lmul.S",
        THIRD_PARTY / "monocypher/src/monocypher.c",
        THIRD_PARTY / "openssl/crypto/chacha/chacha_enc.c",
        THIRD_PARTY / "openssl/crypto/poly1305/poly1305.c",
        WOLFSSL / "wolfcrypt/src/chacha.c",
        WOLFSSL / "wolfcrypt/src/poly1305.c",
        WOLFSSL / "wolfcrypt/src/chacha20_poly1305.c",
    ]
    objects = [ROOT / "build/lib/m0crypto.o"]
    for index, source in enumerate(sources):
        destination = OUTPUT / f"{index}-{source.stem}.o"
        extra_flags = []
        if source == BENCH / "runtime.c":
            extra_flags.append("-fno-builtin")
        run(CLANG, *flags, *extra_flags, "-c", source, "-o", destination)
        objects.append(destination)
    return objects


def link_image(objects: list[Path]) -> None:
    # Keep every wrapper even though this image has no firmware startup routine.
    roots = [
        f"--undefined=run_{implementation}_{operation}"
        for implementation in IMPLEMENTATIONS
        for operation in OPERATIONS
    ]
    run(
        LINKER,
        "-T",
        BENCH / "link.ld",
        "--gc-sections",
        "--build-id=none",
        *roots,
        f"-Map={OUTPUT / 'bench.map'}",
        "-o",
        OUTPUT / "bench.elf",
        *objects,
    )


def record_wolfssl_backend(flags: list[str]) -> list[str]:
    macro_dump = capture(
        CLANG,
        *flags,
        "-dM",
        "-E",
        "-include",
        "wolfssl/wolfcrypt/poly1305.h",
        "-x",
        "c",
        "/dev/null",
    )
    (OUTPUT / "wolfssl-backend.txt").write_text(macro_dump + "\n")
    selected = []
    for line in macro_dump.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in BACKEND_MACROS:
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
    clang_version: str,
    linker_version: str,
    optimization: str,
    flags: list[str],
    sources: list[dict],
    backend: list[str],
) -> None:
    manifest = {
        "wolfssl_backend": backend,
        "clang": clang_version,
        "lld": linker_version,
        "flags": flags,
        "opt": optimization,
        "target": "thumbv6m-none-eabi cortex-m0plus",
        "wolfssl_commit": WOLFSSL_COMMIT,
        "sources": sources,
        "inputs": local_input_hashes(),
        "m0c_text_sha256": sha256(ROOT / "build/lib/text.bin"),
        "elf_sha256": sha256(OUTPUT / "bench.elf"),
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    optimization = os.environ.get("BENCH_OPT", "-Os")
    if optimization not in {"-Os", "-O2", "-O3"}:
        raise SystemExit("BENCH_OPT must be -Os, -O2 or -O3")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    clang_version, linker_version = check_toolchain()
    sources = json.loads((BENCH / "sources.lock.json").read_text())
    fetch_locked_sources(sources)
    fetch_wolfssl()
    run(ROOT / "tools/build_lib.sh")
    flags = compiler_flags(optimization)
    objects = compile_sources(flags)
    link_image(objects)
    backend = record_wolfssl_backend(flags)
    write_manifest(clang_version, linker_version, optimization, flags, sources, backend)
    print(OUTPUT / "bench.elf")


if __name__ == "__main__":
    main()
