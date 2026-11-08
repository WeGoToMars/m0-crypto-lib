"""Benchmark data extraction, grouping, and speedup metrics."""

from collections import defaultdict
from typing import Dict, List, Tuple


def group_workload_rows(
    rows: List[dict],
    operation: str,
    alignment: str = "a",
) -> Tuple[List[int], List[str], Dict[str, Dict[int, float]]]:
    """Extract lengths, active implementation keys, and cycles-per-byte values.

    Returns:
        (lengths, active_impl_keys, data_map)
    """
    filtered = [
        row
        for row in rows
        if row.get("op") == operation
        and row.get("alignment") == alignment
        and int(row.get("bytes", 0)) > 0
    ]
    if not filtered:
        filtered = [
            row
            for row in rows
            if row.get("op") == operation and int(row.get("bytes", 0)) > 0
        ]

    lengths = sorted(list({int(row["bytes"]) for row in filtered}))
    impl_order: List[str] = []
    data: Dict[str, Dict[int, float]] = defaultdict(dict)

    for row in filtered:
        impl = row["impl"]
        if impl not in impl_order:
            impl_order.append(impl)
        length = int(row["bytes"])
        cycles = int(row["zero_wait_cycles"])
        data[impl][length] = cycles / length

    # Ensure baseline "m0c" is first if present
    if "m0c" in impl_order:
        impl_order.remove("m0c")
        impl_order.insert(0, "m0c")

    return lengths, impl_order, data


def calculate_speedup_range(
    lengths: List[int],
    data: Dict[str, Dict[int, float]],
    baseline_key: str = "m0c",
) -> Tuple[float, float]:
    """Calculate min and max speedup of baseline over all comparators across lengths."""
    ratios: List[float] = []
    if baseline_key not in data:
        return 1.0, 1.0

    for length in lengths:
        base_val = data[baseline_key].get(length, 0.0)
        if base_val <= 0:
            continue
        for impl, vals in data.items():
            if impl == baseline_key:
                continue
            val = vals.get(length, 0.0)
            if val > 0:
                ratios.append(val / base_val)

    if not ratios:
        return 1.0, 1.0
    return min(ratios), max(ratios)

