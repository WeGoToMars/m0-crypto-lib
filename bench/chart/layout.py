"""Dynamic layout calculations that scale to any number of implementations."""

from dataclasses import dataclass
from typing import List, Tuple
from .palette import ImplMeta


@dataclass(frozen=True)
class BarGeometry:
    bar_width: float
    bar_gap: float
    group_bars_total_w: float
    center_to_center: float


def compute_bar_geometry(num_bars: int, group_width: float) -> BarGeometry:
    """Calculate bar widths and gaps that scale gracefully with implementation count."""
    if num_bars <= 0:
        return BarGeometry(bar_width=16.0, bar_gap=7.0, group_bars_total_w=16.0, center_to_center=23.0)

    # Target: bars and gaps fill ~75% to 80% of group width
    available_w = group_width * 0.78
    # bar_gap is approximately 40% of bar_width, bounded between 5.0 and 8.0 px
    ideal_unit = available_w / (num_bars + (num_bars - 1) * 0.42)
    bar_width = max(10.0, min(20.0, ideal_unit))
    bar_gap = max(4.0, min(8.0, bar_width * 0.44))

    group_bars_total_w = num_bars * bar_width + (num_bars - 1) * bar_gap
    center_to_center = bar_width + bar_gap
    return BarGeometry(
        bar_width=bar_width,
        bar_gap=bar_gap,
        group_bars_total_w=group_bars_total_w,
        center_to_center=center_to_center,
    )


def compute_y_ticks(max_val: float) -> Tuple[float, float]:
    """Return (max_y_tick, tick_step) providing comfortable headroom for labels."""
    if max_val <= 100:
        return 100.0, 20.0
    if max_val <= 200:
        return 220.0, 50.0
    if max_val <= 320:
        return 350.0, 50.0
    tick_step = 100.0
    max_y_tick = (int(max_val // tick_step) + 1) * tick_step
    return max_y_tick, tick_step


@dataclass(frozen=True)
class LegendLayout:
    items: List[Tuple[ImplMeta, float, float]]  # (meta, x, y)
    total_height: float


def layout_legend(
    metas: List[ImplMeta],
    canvas_width: float,
    start_y: float = 72.0,
    gap_between: float = 24.0,
) -> LegendLayout:
    """Position legend items, wrapping into multiple centered rows if needed."""
    if not metas:
        return LegendLayout(items=[], total_height=0.0)

    # Estimate item widths: 14px box + 6px gap + text + padding
    entries = []
    for meta in metas:
        text_w = len(meta.name) * 7.5
        item_w = 14.0 + 6.0 + text_w
        entries.append((meta, item_w))

    # Single-line check
    total_single_w = sum(w for _, w in entries) + gap_between * (len(entries) - 1)
    if total_single_w <= canvas_width - 64.0:
        cur_x = (canvas_width - total_single_w) / 2.0
        positioned = []
        for meta, item_w in entries:
            positioned.append((meta, cur_x, start_y))
            cur_x += item_w + gap_between
        return LegendLayout(items=positioned, total_height=20.0)

    # Multi-line wrapping
    rows: List[List[Tuple[ImplMeta, float]]] = []
    current_row: List[Tuple[ImplMeta, float]] = []
    current_row_w = 0.0

    for meta, item_w in entries:
        if current_row and (current_row_w + gap_between + item_w > canvas_width - 64.0):
            rows.append(current_row)
            current_row = [(meta, item_w)]
            current_row_w = item_w
        else:
            current_row.append((meta, item_w))
            current_row_w += (gap_between if current_row_w > 0 else 0) + item_w
    if current_row:
        rows.append(current_row)

    positioned = []
    row_y = start_y
    for r in rows:
        row_w = sum(w for _, w in r) + gap_between * (len(r) - 1)
        cur_x = (canvas_width - row_w) / 2.0
        for meta, item_w in r:
            positioned.append((meta, cur_x, row_y))
            cur_x += item_w + gap_between
        row_y += 22.0

    return LegendLayout(items=positioned, total_height=(len(rows) * 22.0))

