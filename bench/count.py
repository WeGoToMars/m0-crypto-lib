#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["unicorn==2.1.4", "capstone==5.0.9", "pyelftools==0.32"]
# ///
"""Check benchmark calls and report Cortex-M0+ cycle estimates.

Run from the library root: uv run --no-project bench/count.py
"""

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import shutil

import capstone
import unicorn

from armv6m import CallResult, OUTPUT_SENTINEL, Runner
from chart import generate_all as generate_charts
from reference import chacha, check_rfc_vector, tag_for

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "build/bench"
IMPLEMENTATIONS = ("m0c", "wolf", "mono", "ossl")
OPERATIONS = ("chacha", "encrypt", "decrypt", "reject")
CSV_FIELDS = [
    "impl",
    "op",
    "bytes",
    "aad_bytes",
    "alignment",
    "instructions",
    "zero_wait_cycles",
    "store_units",
    "sram_store_model_cycles",
]


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
    parser.add_argument(
        "--lengths", type=int, nargs="+", default=[0, 64, 256, 1024, 4096]
    )
    parser.add_argument(
        "--alignments", choices=["a", "u", "ip"], nargs="+", default=["a"]
    )
    parser.add_argument("--aad-length", type=int, default=16)
    arguments = parser.parse_args()
    if any(length < 0 or length > 4096 for length in arguments.lengths):
        parser.error("message lengths must be 0..4096")
    if not 0 <= arguments.aad_length <= 64:
        parser.error("AAD length must be 0..64")
    return arguments


def verified_elf_hash() -> str:
    manifest = json.loads((OUTPUT / "manifest.json").read_text())
    digest = hashlib.sha256((OUTPUT / "bench.elf").read_bytes()).hexdigest()
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
        "instructions": result.counts.instructions,
        "zero_wait_cycles": result.counts.zero_wait_cycles,
        "store_units": result.counts.store_units,
        "sram_store_model_cycles": result.counts.sram_store_model_cycles,
    }


def write_results(
    rows: list[dict], arguments: argparse.Namespace, elf_hash: str
) -> None:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    (OUTPUT / "cycles.csv").write_text(buffer.getvalue())

    generate_charts(rows, OUTPUT)
    charts_dir = ROOT / "bench/charts/chacha20poly1305"
    charts_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(OUTPUT / "cycles_summary.svg", charts_dir / "cycles_summary.svg")

    source_hashes = {}
    for name in ("count.py", "armv6m.py", "reference.py"):
        source = Path(__file__).with_name(name)
        source_hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    for py_file in sorted((Path(__file__).parent / "chart").glob("*.py")):
        source_hashes[f"chart/{py_file.name}"] = hashlib.sha256(py_file.read_bytes()).hexdigest()
    metadata = {
        "elf_sha256": elf_hash,
        "unicorn": unicorn.__version__,
        "capstone_runtime": capstone.__version__,
        "lengths": arguments.lengths,
        "alignments": arguments.alignments,
        "aad_length": arguments.aad_length,
        "calls_checked": len(rows),
        "count_script_sha256": source_hashes["count.py"],
        "counter_sources_sha256": source_hashes,
        "model": "ARM DDI 0484B instruction cost model (zero-wait-state memory baseline)",
    }
    (OUTPUT / "cycles.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main() -> None:
    arguments = parse_arguments()
    check_rfc_vector()
    elf_hash = verified_elf_hash()
    runner = Runner(OUTPUT / "bench.elf")

    rows = []
    for length in arguments.lengths:
        workload = Workload.create(length, arguments.aad_length)
        for alignment in arguments.alignments:
            for implementation in IMPLEMENTATIONS:
                for operation in OPERATIONS:
                    rows.append(
                        run_case(runner, workload, implementation, operation, alignment)
                    )

    # Publish results only after every correctness check succeeds.
    write_results(rows, arguments, elf_hash)
    print(f"PASS: {len(rows)} oracle-checked calls; ELF {elf_hash}")
    print(OUTPUT / "cycles.csv")
    print(ROOT / "bench/charts/chacha20poly1305/cycles_summary.svg")


if __name__ == "__main__":
    main()
