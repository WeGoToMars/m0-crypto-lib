"""SVG rendering primitives and dashboard builder."""

import html
from typing import Dict, List

from .layout import compute_bar_geometry, compute_y_ticks, layout_legend
from .model import calculate_speedup_range, group_workload_rows
from .palette import ImplMeta, get_impl_meta


def render_panel(
    lengths: List[int],
    impl_keys: List[str],
    impl_metas: Dict[str, ImplMeta],
    data: Dict[str, Dict[int, float]],
    x: float,
    y: float,
    width: float,
    height: float,
    panel_title: str,
    speedup_label: str,
    baseline_key: str = "m0c",
) -> str:
    """Render a single grouped bar chart panel."""
    if not lengths:
        return ""

    pad_left = 50.0
    pad_right = 16.0
    pad_top = 54.0
    pad_bottom = 36.0

    plot_x = x + pad_left
    plot_y = y + pad_top
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    max_val = 0.0
    for impl_data in data.values():
        for val in impl_data.values():
            if val > max_val:
                max_val = val
    if max_val <= 0:
        max_val = 100.0

    max_y_tick, tick_step = compute_y_ticks(max_val)

    parts: List[str] = []

    # Title & speedup badge
    parts.append(
        f'<text x="{plot_x:.1f}" y="{y + 22:.1f}" font-size="14" font-weight="600" fill="#0f172a">{html.escape(panel_title)}</text>'
    )
    if speedup_label:
        badge_x = plot_x + plot_w - 116.0
        badge_y = y + 7.0
        parts.append(
            f'<rect x="{badge_x:.1f}" y="{badge_y:.1f}" width="116" height="20" rx="10" fill="#ecfdf5"/>'
            f'<text x="{badge_x + 58.0:.1f}" y="{badge_y + 14.0:.1f}" text-anchor="middle" '
            f'font-size="11" font-weight="600" fill="#065f46">{html.escape(speedup_label)}</text>'
        )

    # Gridlines and Y ticks
    num_ticks = int(round(max_y_tick / tick_step))
    for i in range(num_ticks + 1):
        val = i * tick_step
        tick_y = plot_y + plot_h - (val / max_y_tick) * plot_h
        parts.append(
            f'<line x1="{plot_x:.1f}" y1="{tick_y:.1f}" x2="{plot_x + plot_w:.1f}" y2="{tick_y:.1f}" '
            f'stroke="#f1f5f9" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{plot_x - 8:.1f}" y="{tick_y + 3.5:.1f}" text-anchor="end" '
            f'font-size="10" font-family="monospace" fill="#64748b">{int(val)}</text>'
        )

    # Y-axis title
    parts.append(
        f'<text transform="rotate(-90)" x="{- (plot_y + plot_h / 2):.1f}" y="{x + 13:.1f}" '
        f'text-anchor="middle" font-size="11" fill="#64748b">Cycles / Byte (lower is better)</text>'
    )

    # Bars layout
    num_groups = len(lengths)
    group_width = plot_w / num_groups
    active_impls = [k for k in impl_keys if k in data]
    geom = compute_bar_geometry(len(active_impls), group_width)

    for g_idx, length in enumerate(lengths):
        center_x = plot_x + (g_idx + 0.5) * group_width
        start_x = center_x - geom.group_bars_total_w / 2.0
        base_val = data.get(baseline_key, {}).get(length, 0.0)

        for b_idx, impl_key in enumerate(active_impls):
            val = data[impl_key].get(length, 0.0)
            bar_x = start_x + b_idx * (geom.bar_width + geom.bar_gap)
            bar_h = (val / max_y_tick) * plot_h if max_y_tick > 0 else 0
            bar_y = plot_y + plot_h - bar_h
            meta = impl_metas[impl_key]

            parts.append(
                f'<rect x="{bar_x:.1f}" y="{bar_y:.1f}" width="{geom.bar_width:.1f}" height="{bar_h:.1f}" '
                f'fill="{meta.color}" rx="2"/>'
            )

            # Labels above bar
            if val > 0:
                cx = bar_x + geom.bar_width / 2.0
                val_text = f"{val:.1f}" if val < 100 else f"{int(round(val))}"
                parts.append(
                    f'<text x="{cx:.1f}" y="{bar_y - 4.0:.1f}" text-anchor="middle" '
                    f'font-size="8.5" font-family="monospace" font-weight="600" fill="#334155">{val_text}</text>'
                )

                if base_val > 0:
                    ratio = val / base_val
                    mult_text = "1.0x" if impl_key == baseline_key else f"{ratio:.1f}x"
                    mult_fill = "#059669" if impl_key == baseline_key else "#64748b"
                    parts.append(
                        f'<text x="{cx:.1f}" y="{bar_y - 14.0:.1f}" text-anchor="middle" '
                        f'font-size="8" font-family="monospace" font-weight="700" fill="{mult_fill}">{mult_text}</text>'
                    )

        # X-axis length label
        parts.append(
            f'<text x="{center_x:.1f}" y="{plot_y + plot_h + 17:.1f}" text-anchor="middle" '
            f'font-size="11" font-weight="500" fill="#475569">{length} B</text>'
        )

    # X-axis line
    parts.append(
        f'<line x1="{plot_x:.1f}" y1="{plot_y + plot_h:.1f}" x2="{plot_x + plot_w:.1f}" y2="{plot_y + plot_h:.1f}" '
        f'stroke="#cbd5e1" stroke-width="1"/>'
    )

    return "\n".join(parts)


def render_dashboard(rows: List[dict], alignment: str = "a") -> str:
    """Render the dual-panel summary SVG dashboard."""
    total_w = 1080.0
    total_h = 500.0

    lengths_cha, impls_cha, data_cha = group_workload_rows(rows, "chacha", alignment)
    lengths_enc, impls_enc, data_enc = group_workload_rows(rows, "encrypt", alignment)

    # Common benchmark lengths
    common = [l for l in [64, 256, 1024, 4096] if l in lengths_cha and l in lengths_enc]
    if common:
        lengths_cha = common
        lengths_enc = common

    # All active implementations
    all_impls = list(dict.fromkeys(impls_cha + impls_enc))
    impl_metas = {key: get_impl_meta(key, idx) for idx, key in enumerate(all_impls)}

    # Headline speedup badges
    min_cha, max_cha = calculate_speedup_range(lengths_cha, data_cha)
    min_enc, max_enc = calculate_speedup_range(lengths_enc, data_enc)
    badge_cha = f"{min_cha:.1f}x \u2013 {max_cha:.1f}x faster"
    badge_enc = f"{min_enc:.1f}x \u2013 {max_enc:.1f}x faster"

    # Dynamic legend layout
    legend_layout = layout_legend(list(impl_metas.values()), total_w, start_y=72.0)
    legend_parts = []
    for meta, lx, ly in legend_layout.items:
        legend_parts.append(
            f'<rect x="{lx:.1f}" y="{ly - 9:.1f}" width="12" height="12" rx="2" fill="{meta.color}"/>'
            f'<text x="{lx + 18.0:.1f}" y="{ly + 1.0:.1f}" font-size="12" fill="#334155">{html.escape(meta.name)}</text>'
        )
    legend_svg = "\n    ".join(legend_parts)

    panel_y = max(104.0, 72.0 + legend_layout.total_height + 14.0)
    panel_w = 502.0
    panel_h = total_h - panel_y - 58.0

    left_panel = render_panel(
        lengths_cha,
        impls_cha,
        impl_metas,
        data_cha,
        24.0,
        panel_y,
        panel_w,
        panel_h,
        "ChaCha20 Stream Cipher",
        badge_cha,
    )
    right_panel = render_panel(
        lengths_enc,
        impls_enc,
        impl_metas,
        data_enc,
        554.0,
        panel_y,
        panel_w,
        panel_h,
        "ChaCha20-Poly1305 AEAD Encrypt",
        badge_enc,
    )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {int(total_w)} {int(total_h)}" width="{int(total_w)}" height="{int(total_h)}">
  <style>
    text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  </style>
  <rect width="100%" height="100%" fill="#ffffff" rx="8" stroke="#e2e8f0" stroke-width="1"/>

  <!-- Header -->
  <text x="32" y="36" font-size="18" font-weight="700" fill="#0f172a">Cortex-M0+ ChaCha20-Poly1305 Performance</text>
  <text x="32" y="54" font-size="12" fill="#64748b">Cycles per byte (lower is better) · ARM DDI 0484B zero-wait-state model</text>

  <!-- Legend -->
  <g>
    {legend_svg}
  </g>

  <!-- Panels -->
  <g>
    {left_panel}
  </g>
  <g>
    {right_panel}
  </g>

  <!-- Clean footer -->
  <line x1="24" y1="{total_h - 32}" x2="{total_w - 24}" y2="{total_h - 32}" stroke="#f1f5f9" stroke-width="1"/>
  <text x="32" y="{total_h - 14}" font-size="11" fill="#94a3b8">TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, aligned buffers, 16-byte AAD)</text>
</svg>"""
    return svg

