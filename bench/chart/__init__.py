"""Cortex-M0+ benchmark chart generation package.

Provides modular SVG performance chart rendering with automatic support for
scaling to arbitrary numbers of cryptographic implementations.
"""

from pathlib import Path
from typing import List

from .model import group_workload_rows
from .palette import ImplMeta, get_impl_meta
from .render import render_dashboard


def generate_all(
    rows: List[dict], output_dir: Path, primitive: str = "chacha20poly1305"
) -> List[Path]:
    """Generate benchmark SVG charts into the target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    prim_dir = output_dir / primitive
    prim_dir.mkdir(parents=True, exist_ok=True)

    summary_svg = render_dashboard(rows)
    summary_path = output_dir / "cycles_summary.svg"
    summary_path.write_text(summary_svg)
    prim_path = prim_dir / "cycles_summary.svg"
    prim_path.write_text(summary_svg)
    return [summary_path, prim_path]


__all__ = ["generate_all", "render_dashboard", "get_impl_meta", "ImplMeta"]

