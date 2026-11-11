"""Render the benchmark summary charts as standalone SVG."""

from html import escape
from pathlib import Path

WIDTH, HEIGHT = 1080, 450
LEGEND_CHAR_W = 6.5  # approximate width of a 12px sans-serif character
BASELINE = "m0c"
# Legend and bar order.
IMPLS = {
    "m0c": ("m0-crypto", "#059669"),
    "wolf": ("wolfSSL 5.9.4", "#7c3aed"),
    "mono": ("Monocypher 4.0.2", "#2563eb"),
    "ossl": ("OpenSSL 3.5.0", "#d97706"),
}
ALIGNMENT_TEXT = {"a": "aligned buffers", "u": "unaligned buffers", "ip": "in-place buffers"}

# Hand-entered; count.py does not measure code size.
CODE_SIZES = {  # Flash bytes per optimization level
    "m0c": {"-Os (Size)": 3030, "-O2": 3030, "-O3 (Speed)": 3030},
    "wolf": {"-Os (Size)": 4092, "-O2": 5982, "-O3 (Speed)": 6848},
    "mono": {"-Os (Size)": 2890, "-O2": 5364, "-O3 (Speed)": 6648},
    "ossl": {"-Os (Size)": 2430, "-O2": 2502, "-O3 (Speed)": 2510},
}
M0C_STACK_BOUND = 320  # bytes, proved in Lean 4
STACK_GROUPS = {"AEAD Encrypt": {"encrypt"}, "AEAD Decrypt": {"decrypt", "reject"}, "ChaCha20": {"chacha"}}


def y_axis(max_value: float) -> tuple[float, float]:
    """Return (axis top, tick step) with headroom for the labels above bars."""
    for limit, top, step in (
        (100, 100, 20), (200, 220, 50), (320, 350, 50),
        (600, 600, 100), (1000, 1000, 200), (2500, 2500, 500),
    ):
        if max_value <= limit:
            return top, step
    step = 1000 if max_value <= 8000 else 2000
    return (max_value // step + 1) * step, step


def total(value) -> float:
    return sum(value) if isinstance(value, tuple) else value


def number(value: float) -> str:
    return f"{value:.1f}" if value < 100 else f"{round(value):,}"


def panel(x, y, w, h, title, badge, y_title, data, pad_left) -> str:
    """Grouped bar chart. data maps impl -> {group label: value}.

    A (base, extra) tuple value draws a stacked bar: base solid, extra light.
    """
    groups = list(data[BASELINE])
    stacked = any(isinstance(v, tuple) for values in data.values() for v in values.values())
    plot_x, plot_y = x + pad_left, y + 54
    plot_w, plot_h = w - pad_left - 16, h - 90
    bottom = plot_y + plot_h
    top, step = y_axis(max(total(v) for values in data.values() for v in values.values()))
    badge_w = max(116.0, len(badge) * 6.5 + 24)
    badge_x = plot_x + plot_w - badge_w
    parts = [
        f'<text x="{plot_x:.1f}" y="{y + 22:.1f}" font-size="14" font-weight="600" fill="#0f172a">{escape(title)}</text>',
        f'<rect x="{badge_x:.1f}" y="{y + 7:.1f}" width="{badge_w:.1f}" height="20" rx="10" fill="#ecfdf5"/>'
        f'<text x="{badge_x + badge_w / 2:.1f}" y="{y + 21:.1f}" text-anchor="middle" '
        f'font-size="11" font-weight="600" fill="#065f46">{escape(badge)}</text>',
    ]
    for i in range(round(top / step) + 1):
        tick_y = bottom - i * step / top * plot_h
        parts += [
            f'<line x1="{plot_x:.1f}" y1="{tick_y:.1f}" x2="{plot_x + plot_w:.1f}" y2="{tick_y:.1f}" '
            f'stroke="#f1f5f9" stroke-width="1"/>',
            f'<text x="{plot_x - 8:.1f}" y="{tick_y + 3.5:.1f}" text-anchor="end" '
            f'font-size="10" font-family="monospace" fill="#64748b">{int(i * step):,}</text>',
        ]
    parts.append(
        f'<text transform="rotate(-90)" x="{-(plot_y + plot_h / 2):.1f}" y="{x + 13:.1f}" '
        f'text-anchor="middle" font-size="11" fill="#64748b">{escape(y_title)}</text>'
    )

    # Bars fill ~78% of each group; widths and gaps are clamped.
    group_w = plot_w / len(groups)
    n = len(data)
    bar_w = max(10.0, min(20.0, group_w * 0.78 / (n + (n - 1) * 0.42)))
    gap = max(4.0, min(8.0, bar_w * 0.44))
    for g, group in enumerate(groups):
        center = plot_x + (g + 0.5) * group_w
        base = total(data[BASELINE][group])
        for b, (impl, values) in enumerate(data.items()):
            value = total(values[group])
            bar_x = center - (n * bar_w + (n - 1) * gap) / 2 + b * (bar_w + gap)
            bar_h = value / top * plot_h
            bar_y = bottom - bar_h
            cx = bar_x + bar_w / 2
            color = IMPLS[impl][1]
            if isinstance(values[group], tuple):
                # Light full-height bar, then the solid base segment over it.
                parts.append(
                    f'<rect x="{bar_x:.1f}" y="{bar_y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
                    f'fill="{color}" fill-opacity="0.35" rx="2"/>'
                )
                bar_h = values[group][0] / top * plot_h
            parts += [
                f'<rect x="{bar_x:.1f}" y="{bottom - bar_h:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
                f'fill="{color}" rx="2"/>',
                f'<text x="{cx:.1f}" y="{bar_y - 4:.1f}" text-anchor="middle" font-size="8.5" '
                f'font-family="monospace" font-weight="600" fill="#334155">{number(value)}</text>',
            ]
            if impl != BASELINE:
                parts.append(
                    f'<text x="{cx:.1f}" y="{bar_y - 14:.1f}" text-anchor="middle" font-size="8" '
                    f'font-family="monospace" font-weight="700" fill="#64748b">{value / base:.1f}x</text>'
                )
        parts.append(
            f'<text x="{center:.1f}" y="{bottom + 17:.1f}" text-anchor="middle" '
            f'font-size="11" font-weight="500" fill="#475569">{escape(group)}</text>'
        )
    parts.append(
        f'<line x1="{plot_x:.1f}" y1="{bottom:.1f}" x2="{plot_x + plot_w:.1f}" y2="{bottom:.1f}" '
        f'stroke="#cbd5e1" stroke-width="1"/>'
    )
    if stacked:
        for i, (label, opacity) in enumerate((("Library peak", 1), ("Caller-held API state", 0.35))):
            key_y = plot_y + 6 + i * 16
            parts.append(
                f'<rect x="{plot_x + 10:.1f}" y="{key_y:.1f}" width="10" height="10" rx="2" '
                f'fill="#64748b" fill-opacity="{opacity}"/>'
                f'<text x="{plot_x + 26:.1f}" y="{key_y + 9:.1f}" font-size="10" fill="#475569">{label}</text>'
            )
    return "\n".join(parts)


def dashboard(title, subtitle, footer, left, right) -> str:
    """Two panels side by side under a shared header and legend."""
    x, legend = 32.0, []
    for name, color in IMPLS.values():
        legend.append(
            f'<rect x="{x:.1f}" y="67" width="12" height="12" rx="2" fill="{color}"/>'
            f'<text x="{x + 18:.1f}" y="77" font-size="12" fill="#334155">{escape(name)}</text>'
        )
        x += 18 + len(name) * LEGEND_CHAR_W + 28
    legend_svg = "\n    ".join(legend)
    # 2. panels start just below the legend and end just above the footer
    panel_y, panel_w = 92.0, 502.0
    panel_h = HEIGHT - panel_y - 40
    left_svg = panel(24.0, panel_y, panel_w, panel_h, *left)
    right_svg = panel(554.0, panel_y, panel_w, panel_h, *right)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" width="{WIDTH}" height="{HEIGHT}">
  <style>
    text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  </style>
  <rect width="100%" height="100%" fill="#ffffff" rx="8" stroke="#e2e8f0" stroke-width="1"/>

  <!-- Header -->
  <text x="32" y="36" font-size="18" font-weight="700" fill="#0f172a">{escape(title)}</text>
  <text x="32" y="54" font-size="12" fill="#64748b">{escape(subtitle)}</text>

  <!-- Legend -->
  <g>
    {legend_svg}
  </g>

  <!-- Panels -->
  <g>
    {left_svg}
  </g>
  <g>
    {right_svg}
  </g>

  <!-- Clean footer -->
  <line x1="24" y1="{HEIGHT - 32}" x2="{WIDTH - 24}" y2="{HEIGHT - 32}" stroke="#f1f5f9" stroke-width="1"/>
  <text x="32" y="{HEIGHT - 14}" font-size="11" fill="#94a3b8">{escape(footer)}</text>
</svg>"""


def cycles_per_byte(rows: list[dict], operation: str, alignment: str) -> dict:
    data = {impl: {} for impl in IMPLS}
    for row in rows:
        length = int(row["bytes"])
        if row["op"] == operation and row["alignment"] == alignment and length > 0:
            data[row["impl"]][f"{length} B"] = int(row["zero_wait_cycles"]) / length
    return data


def speedup_badge(data: dict) -> str:
    ratios = [
        values[group] / base
        for impl, values in data.items()
        if impl != BASELINE
        for group, base in data[BASELINE].items()
    ]
    return f"{min(ratios):.1f}x – {max(ratios):.1f}x faster"


def cycles_chart(rows: list[dict]) -> str:
    alignments = [row["alignment"] for row in rows]
    alignment = "a" if "a" in alignments else alignments[0]
    chacha = cycles_per_byte(rows, "chacha", alignment)
    encrypt = cycles_per_byte(rows, "encrypt", alignment)
    y_title = "Cycles / Byte (lower is better)"
    return dashboard(
        "Cortex-M0+ ChaCha20-Poly1305 Performance",
        "Cycles per byte (lower is better) · ARM DDI 0484B zero-wait-state model",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, {rows[0]['aad_bytes']}-byte AAD)",
        ("ChaCha20 Stream Cipher", speedup_badge(chacha), y_title, chacha, 50.0),
        ("ChaCha20-Poly1305 AEAD Encrypt", speedup_badge(encrypt), y_title, encrypt, 50.0),
    )


def peak_stack(rows: list[dict]) -> dict:
    """(library peak, caller-held state) of the worst run per implementation and group."""
    return {
        impl: {
            group: max(
                (int(r["peak_stack_bytes"]), int(r["caller_state_bytes"]))
                for r in rows
                if r["impl"] == impl and r["op"] in ops
            )
            for group, ops in STACK_GROUPS.items()
        }
        for impl in IMPLS
    }


def size_chart(rows: list[dict]) -> str:
    code_badge = f"{CODE_SIZES[BASELINE]['-Os (Size)']:,} B fixed"
    stack_badge = f"{M0C_STACK_BOUND:,} B verified bound"
    return dashboard(
        "Cortex-M0+ ChaCha20-Poly1305 Memory Footprint",
        "Code size (Flash) and peak stack usage (SRAM) in bytes · ARM Cortex-M0+ (thumbv6m-none-eabi)",
        "Stack: emulator-measured peak below the library call plus caller-held API state, worst run · "
        "m0-crypto stack bound proved in Lean 4",
        ("Code Size (Flash / ROM)", code_badge, "Bytes in Flash (lower is better)", CODE_SIZES, 56.0),
        ("Peak Stack Usage (SRAM)", stack_badge, "Bytes on Stack (lower is better)", peak_stack(rows), 56.0),
    )


def write_charts(rows: list[dict], directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = [directory / "cycles_summary.svg", directory / "size_summary.svg"]
    paths[0].write_text(cycles_chart(rows))
    paths[1].write_text(size_chart(rows))
    return paths
