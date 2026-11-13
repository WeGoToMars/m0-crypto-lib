#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["unicorn==2.1.4", "capstone==5.0.9", "pyelftools==0.32"]
# ///
"""Check one primitive's benchmark calls and report Cortex-M0+ cycle estimates.

Run from the library root: uv run --no-project bench/count.py PRIMITIVE
(PRIMITIVE: chacha20poly1305, blake2s or x25519; build it first with bench/build.py)
"""

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path

import capstone
import unicorn

from armv6m import CallResult, Counts, OUTPUT_SENTINEL, Runner
from chart import M0C_STACK_BOUNDS, write_charts
from reference import (
    ALICE_PRIVATE,
    BOB_PUBLIC,
    blake2s,
    chacha,
    check_blake2s_vector,
    check_rfc_vector,
    check_x25519_vectors,
    clamp_scalar,
    tag_for,
    x25519,
)

ROOT = Path(__file__).resolve().parents[1]
CHACHA_IMPLEMENTATIONS = ("m0c", "wolf", "mono", "ossl")
CHACHA_OPERATIONS = ("chacha", "encrypt", "decrypt", "reject")
BLAKE2S_IMPLEMENTATIONS = ("m0c", "wolf", "ref", "ossl")
BLAKE2S_OPERATIONS = ("hash", "stream")
X25519_IMPLEMENTATIONS = ("m0c", "wolf", "pornin", "mono", "ossl")
X25519_INSTRUCTION_LIMIT = 200_000_000


@dataclass(frozen=True)
class Workload:
    key: bytes
    nonce: bytes
    aad: bytes
    plaintext: bytes
    ciphertext: bytes
    tag: bytes

    @classmethod
    def create(cls, length: int, aad_length: int) -> "Workload":
        key = bytes(range(32))
        nonce = bytes(range(12))
        aad = bytes(range(aad_length))
        plaintext = bytes(index % 251 for index in range(length))
        ciphertext = chacha(key, nonce, plaintext)
        tag = tag_for(key, nonce, aad, ciphertext)
        return cls(key, nonce, aad, plaintext, ciphertext, tag)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primitive", choices=("chacha20poly1305", "blake2s", "x25519"))
    parser.add_argument(
        "--lengths", type=int, nargs="+", default=[0, 64, 256, 1024, 4096]
    )
    parser.add_argument(
        "--alignments", choices=["a", "u", "ip"], nargs="+", default=["a"]
    )
    parser.add_argument("--aad-length", type=int, default=16)
    parser.add_argument(
        "--random", type=int, default=0,
        help="X25519: extra shared-secret calls on seeded pseudo-random inputs",
    )
    arguments = parser.parse_args()
    if arguments.primitive != "chacha20poly1305" and "ip" in arguments.alignments:
        parser.error("in-place buffers apply to ChaCha20-Poly1305 only")
    if any(length < 0 or length > 4096 for length in arguments.lengths):
        parser.error("message lengths must be 0..4096")
    if not 0 <= arguments.aad_length <= 64:
        parser.error("AAD length must be 0..64")
    return arguments


def verified_elf_hash(output: Path) -> str:
    manifest = json.loads((output / "manifest.json").read_text())
    digest = hashlib.sha256((output / "bench.elf").read_bytes()).hexdigest()
    if digest != manifest["elf_sha256"]:
        raise RuntimeError("ELF differs from build manifest")
    return digest


def check_result(
    result: CallResult,
    workload: Workload,
    implementation: str,
    operation: str,
    alignment: str,
) -> None:
    if operation == "reject":
        if result.status == 0:
            raise RuntimeError("accepted modified tag")
        # wolfSSL has a different rejected-decrypt output convention.
        if implementation != "wolf":
            expected = OUTPUT_SENTINEL * len(workload.ciphertext)
            if alignment == "ip":
                expected = workload.ciphertext
            if result.output != expected:
                raise RuntimeError("wrote output on authentication failure")
        return

    if result.status != 0:
        raise RuntimeError(f"returned error status {result.status}")
    expected_output = (
        workload.plaintext if operation == "decrypt" else workload.ciphertext
    )
    if result.output != expected_output:
        raise RuntimeError("output differs from the reference")
    if operation == "encrypt" and result.tag != workload.tag:
        raise RuntimeError("tag differs from the reference")


def run_case(
    runner: Runner,
    workload: Workload,
    implementation: str,
    operation: str,
    alignment: str,
) -> dict:
    message = workload.plaintext
    if operation in {"decrypt", "reject"}:
        message = workload.ciphertext
    tag = workload.tag
    if operation == "reject":
        tag = bytes([tag[0] ^ 1]) + tag[1:]
    wrapper_operation = "decrypt" if operation == "reject" else operation

    try:
        result = runner.call(
            implementation=implementation,
            operation=wrapper_operation,
            key=workload.key,
            nonce=workload.nonce,
            aad=workload.aad,
            message=message,
            tag=tag,
            alignment=alignment,
        )
        check_result(result, workload, implementation, operation, alignment)
    except RuntimeError as error:
        context = (
            f"{implementation} {operation}, {len(message)} bytes, alignment {alignment}"
        )
        raise RuntimeError(f"{context}: {error}") from error

    return {
        "impl": implementation,
        "op": operation,
        "bytes": len(message),
        "aad_bytes": len(workload.aad),
        "alignment": alignment,
        **count_columns(result.counts),
    }


def count_columns(counts: Counts) -> dict:
    return {
        "instructions": counts.instructions,
        "zero_wait_cycles": counts.zero_wait_cycles,
        "store_units": counts.store_units,
        "sram_store_model_cycles": counts.sram_store_model_cycles,
        "peak_stack_bytes": counts.peak_stack,
        "caller_state_bytes": counts.caller_state,
    }


def chacha_rows(runner: Runner, arguments: argparse.Namespace) -> list[dict]:
    check_rfc_vector()
    rows = []
    for length in arguments.lengths:
        workload = Workload.create(length, arguments.aad_length)
        for alignment in arguments.alignments:
            for implementation in CHACHA_IMPLEMENTATIONS:
                for operation in CHACHA_OPERATIONS:
                    rows.append(
                        run_case(runner, workload, implementation, operation, alignment)
                    )
    return rows


def checked_call(runner: Runner, context: str, expected: bytes, **call) -> CallResult:
    """Run one wrapper; fail unless it returns status 0 and the expected output."""
    try:
        result = runner.call(**call, nonce=b"", aad=b"", tag=bytes(16))
        if result.status != 0:
            raise RuntimeError(f"returned error status {result.status}")
        if result.output != expected:
            raise RuntimeError("output differs from the reference")
    except RuntimeError as error:
        raise RuntimeError(f"{context}: {error}") from error
    return result


def blake2s_rows(runner: Runner, arguments: argparse.Namespace) -> list[dict]:
    check_blake2s_vector()
    rows = []
    for length in arguments.lengths:
        message = bytes(index % 251 for index in range(length))
        digest = blake2s(message)
        for alignment in arguments.alignments:
            for implementation in BLAKE2S_IMPLEMENTATIONS:
                for operation in BLAKE2S_OPERATIONS:
                    result = checked_call(
                        runner,
                        f"{implementation} {operation}, {length} bytes, alignment {alignment}",
                        digest,
                        implementation=implementation,
                        operation=operation,
                        key=bytes(32),  # unused
                        message=message,
                        alignment=alignment,
                        output_length=32,
                    )
                    rows.append({
                        "impl": implementation,
                        "op": operation,
                        "bytes": length,
                        "alignment": alignment,
                        **count_columns(result.counts),
                    })
    return rows


def x25519_inputs(count: int) -> list[tuple[str, str, bytes, bytes]]:
    """(input label, operation, scalar, point). Scalars are clamped and points have
    bit 255 clear: X25519 does both anyway, and wolfSSL's key import requires it."""
    base = bytes([9]) + bytes(31)
    inputs = [
        ("rfc7748-6.1", "shared", clamp_scalar(ALICE_PRIVATE), BOB_PUBLIC),
        ("rfc7748-6.1", "public", clamp_scalar(ALICE_PRIVATE), base),
    ]
    for index in range(count):
        seed = hashlib.sha256(f"m0c-bench-x25519-{index}".encode()).digest()
        scalar = clamp_scalar(seed)
        point = x25519(hashlib.sha256(seed).digest(), base)  # a valid public key
        inputs.append((f"random-{index}", "shared", scalar, point))
    return inputs


def x25519_rows(runner: Runner, arguments: argparse.Namespace) -> list[dict]:
    check_x25519_vectors()
    rows = []
    for label, operation, scalar, point in x25519_inputs(arguments.random):
        expected = x25519(scalar, point)
        for alignment in arguments.alignments:
            for implementation in X25519_IMPLEMENTATIONS:
                result = checked_call(
                    runner,
                    f"{implementation} {operation} ({label}), alignment {alignment}",
                    expected,
                    implementation=implementation,
                    operation=operation,
                    key=scalar,
                    message=point,
                    alignment=alignment,
                    output_length=32,
                    instruction_limit=X25519_INSTRUCTION_LIMIT,
                )
                rows.append({
                    "impl": implementation,
                    "op": operation,
                    "input": label,
                    "alignment": alignment,
                    **count_columns(result.counts),
                })
    return rows


ROWS = {"chacha20poly1305": chacha_rows, "blake2s": blake2s_rows, "x25519": x25519_rows}


def write_results(
    rows: list[dict], arguments: argparse.Namespace, elf_hash: str, output: Path
) -> list[Path]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    (output / "cycles.csv").write_text(buffer.getvalue())

    primitive = arguments.primitive
    chart_paths = write_charts(primitive, rows, ROOT / "bench/charts" / primitive)

    source_hashes = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("count.py", "armv6m.py", "reference.py", "chart.py")
    }
    metadata = {
        "primitive": primitive,
        "elf_sha256": elf_hash,
        "unicorn": unicorn.__version__,
        "capstone_runtime": capstone.__version__,
        "lengths": arguments.lengths,
        "alignments": arguments.alignments,
        "aad_length": arguments.aad_length if primitive == "chacha20poly1305" else None,
        "random_inputs": arguments.random if primitive == "x25519" else None,
        "calls_checked": len(rows),
        "count_script_sha256": source_hashes["count.py"],
        "counter_sources_sha256": source_hashes,
        "model": "ARM DDI 0484B instruction cost model (zero-wait-state memory baseline)",
    }
    (output / "cycles.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return chart_paths


def main() -> None:
    arguments = parse_arguments()
    output = ROOT / "build/bench" / arguments.primitive
    elf_hash = verified_elf_hash(output)
    runner = Runner(output / "bench.elf")
    rows = ROWS[arguments.primitive](runner, arguments)

    bound = M0C_STACK_BOUNDS[arguments.primitive]
    m0c_stack = max(row["peak_stack_bytes"] for row in rows if row["impl"] == "m0c")
    if m0c_stack > bound:
        raise RuntimeError(f"m0c used {m0c_stack} B of stack; proved bound is {bound} B")

    # Publish results only after every correctness check succeeds.
    chart_paths = write_results(rows, arguments, elf_hash, output)
    print(f"PASS: {len(rows)} oracle-checked calls; ELF {elf_hash}")
    print(output / "cycles.csv")
    print(*chart_paths, sep="\n")


if __name__ == "__main__":
    main()
