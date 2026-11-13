"""Render each primitive's benchmark summary charts as standalone SVG."""

from html import escape
from pathlib import Path

WIDTH, HEIGHT = 1080, 450
LEGEND_CHAR_W = 6.5  # approximate width of a 12px sans-serif character
BASELINE = "m0c"
# Name and color follow the implementation, and this order is the bar and legend order,
# in every chart. It keeps wolfSSL and Monocypher apart, and x25519-cm0 away from
# m0-crypto: those hue pairs are too close for color-vision deficiencies when adjacent.
NAMES = {
    "m0c": ("m0-crypto (ours)", "#059669"),
    "wolf": ("wolfSSL 5.9.4", "#7c3aed"),
    "ossl": ("OpenSSL 3.5.0", "#d97706"),
    "mono": ("Monocypher 4.0.2", "#2563eb"),
    "ref": ("BLAKE2 reference", "#0891b2"),
    "pornin": ("x25519-cm0 (Pornin)†", "#db2777"),
}
# Research implementations in hand-written assembly, as opposed to production libraries:
# hatched bars, and footnote lines with the citation.
RESEARCH = {
    "pornin": (
        "† Research implementation in hand-written ARMv6-M assembly, provided here as reference "
        "(T. Pornin, github.com/pornin/x25519-cm0).",
        "   Its field inversion: T. Pornin, \u201cOptimized Binary GCD for Modular Inversion\u201d, "
        "IACR Cryptology ePrint Archive 2020/972.",
    ),
}


def ordered(implementations) -> tuple:
    return tuple(impl for impl in NAMES if impl in implementations)


def fill(impl: str) -> str:
    return f"url(#hatch-{impl})" if impl in RESEARCH else NAMES[impl][1]
ALIGNMENT_TEXT = {"a": "aligned buffers", "u": "unaligned buffers", "ip": "in-place buffers"}
OPT_LEVELS = ("-Os (Size)", "-O2", "-O3 (Speed)")

# Proved in Lean 4: the largest stack bound over the asset's public functions, in bytes.
M0C_STACK_BOUNDS = {"chacha20poly1305": 320, "blake2s": 160, "x25519": 516}

# Hand-entered; count.py does not measure code size. The BLAKE2s and X25519 figures are
# the code_bytes of build/bench/PRIMITIVE/manifest.json for BENCH_OPT=-Os, -O2 and -O3:
# linked .text and .rodata of each comparator's own objects (harness and shared runtime
# excluded). The ChaCha20-Poly1305 OpenSSL figures include the harness composition.
CODE_SIZES = {
    "chacha20poly1305": {  # Flash bytes per optimization level
        "m0c": (3030, 3030, 3030),
        "wolf": (4092, 5982, 6848),
        "mono": (2890, 5364, 6648),
        "ossl": (2430, 2502, 2510),
    },
    "blake2s": {
        "m0c": (4748, 4748, 4748),
        "wolf": (7020, 7684, 7870),
        "ref": (5152, 5394, 5520),
        "ossl": (5828, 6292, 6292),
    },
    "x25519": {
        "m0c": (7022, 7022, 7022),
        "wolf": (8060, 10036, 10790),
        "pornin": (8850, 8850, 8850),
        "mono": (7258, 11778, 12434),
        "ossl": (6340, 7534, 8288),
    },
}
STACK_GROUPS = {
    "chacha20poly1305": {"AEAD Encrypt": {"encrypt"}, "AEAD Decrypt": {"decrypt", "reject"}, "ChaCha20": {"chacha"}},
    "blake2s": {"One update": {"hash"}, "16-byte updates": {"stream"}},
    "x25519": {"Shared secret": {"shared"}, "Public key": {"public"}},
}


def y_axis(max_value: float) -> tuple[float, float]:
    """Return (axis top, tick step) with headroom for the labels above bars."""
    for limit, top, step in (
        (100, 100, 20), (200, 220, 50), (320, 350, 50),
        (600, 600, 100), (1000, 1000, 200), (2500, 2500, 500),
    ):
        if max_value <= limit:
            return top, step
    if max_value <= 8000:
        step = 1000
    else:  # at most about eight ticks
        magnitude = 10 ** (len(str(int(max_value / 8))) - 1)
        step = next(m * magnitude for m in (1, 2, 5, 10) if m * magnitude >= max_value / 8)
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
    peak = max(total(v) for values in data.values() for v in values.values())
    # Stacked panels carry a two-row key in the top-left corner: keep bars below it.
    top, step = y_axis(peak * 1.3 if stacked else peak)
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
    bar_w = max(10.0, min(20.0 if w < 600 else 30.0, group_w * 0.78 / (n + (n - 1) * 0.42)))
    gap = max(4.0, min(8.0, bar_w * 0.44))
    for g, group in enumerate(groups):
        center = plot_x + (g + 0.5) * group_w
        base = total(data[BASELINE][group])
        for b, impl in enumerate(ordered(data)):
            values = data[impl]
            value = total(values[group])
            bar_x = center - (n * bar_w + (n - 1) * gap) / 2 + b * (bar_w + gap)
            bar_h = value / top * plot_h
            bar_y = bottom - bar_h
            cx = bar_x + bar_w / 2
            color = NAMES[impl][1]
            if impl == BASELINE:  # highlighted column behind our bar
                parts.append(
                    f'<rect x="{bar_x - gap / 2:.1f}" y="{plot_y:.1f}" width="{bar_w + gap:.1f}" '
                    f'height="{plot_h:.1f}" fill="{color}" fill-opacity="0.08"/>'
                )
            if isinstance(values[group], tuple):
                # Light full-height bar, then the solid base segment over it.
                parts.append(
                    f'<rect x="{bar_x:.1f}" y="{bar_y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
                    f'fill="{color}" fill-opacity="0.35" rx="2"/>'
                )
                bar_h = values[group][0] / top * plot_h
            parts += [
                f'<rect x="{bar_x:.1f}" y="{bottom - bar_h:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
                f'fill="{fill(impl)}" rx="2"/>',
                f'<text x="{cx:.1f}" y="{bar_y - 4:.1f}" text-anchor="middle" font-size="8.5" '
                f'font-family="monospace" font-weight="{800 if impl == BASELINE else 600}" '
                f'fill="{"#0f172a" if impl == BASELINE else "#334155"}">{number(value)}</text>',
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


def dashboard(title, subtitle, footer, impls, left, right=None) -> str:
    """Two panels side by side (or one full-width panel) under a shared header and legend.
    Footnotes for research implementations go below the footer."""
    impls = ordered(impls)
    x, legend = 32.0, []
    for impl in impls:
        name = NAMES[impl][0]
        ours = impl == BASELINE
        legend.append(
            f'<rect x="{x:.1f}" y="67" width="12" height="12" rx="2" fill="{fill(impl)}"/>'
            f'<text x="{x + 18:.1f}" y="77" font-size="12" font-weight="{700 if ours else 400}" '
            f'fill="{"#0f172a" if ours else "#334155"}">{escape(name)}</text>'
        )
        x += 18 + len(name) * LEGEND_CHAR_W * (1.08 if ours else 1) + 28
    legend_svg = "\n    ".join(legend)
    patterns = "".join(
        f'<pattern id="hatch-{impl}" patternUnits="userSpaceOnUse" width="6" height="6" '
        f'patternTransform="rotate(45)"><rect width="6" height="6" fill="{NAMES[impl][1]}" '
        f'fill-opacity="0.3"/><rect width="3" height="6" fill="{NAMES[impl][1]}"/></pattern>'
        for impl in impls if impl in RESEARCH
    )
    notes = [line for impl in impls if impl in RESEARCH for line in RESEARCH[impl]]
    height = HEIGHT + 16 * len(notes)
    notes_svg = "".join(
        f'<text x="32" y="{HEIGHT - 14 + 16 * (i + 1)}" font-size="11" fill="#94a3b8">{escape(note)}</text>'
        for i, note in enumerate(notes)
    )
    # 2. panels start just below the legend and end just above the footer
    panel_y, panel_w = 92.0, 502.0
    panel_h = HEIGHT - panel_y - 40
    if right is None:
        left_svg, right_svg = panel(24.0, panel_y, WIDTH - 48.0, panel_h, *left), ""
    else:
        left_svg = panel(24.0, panel_y, panel_w, panel_h, *left)
        right_svg = panel(554.0, panel_y, panel_w, panel_h, *right)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" height="{height}">
  <defs>{patterns}</defs>
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
  {notes_svg}
</svg>"""


def cycles_per_byte(rows: list[dict], impls, operation: str, alignment: str) -> dict:
    data = {impl: {} for impl in impls}
    for row in rows:
        length = int(row["bytes"])
        if row["op"] == operation and row["alignment"] == alignment and length > 0:
            data[row["impl"]][f"{length} B"] = int(row["zero_wait_cycles"]) / length
    return data


def speedup_badge(data: dict) -> str:
    """Range of speedups over the libraries; research implementations are excluded."""
    ratios = [
        values[group] / base
        for impl, values in data.items()
        if impl != BASELINE and impl not in RESEARCH
        for group, base in data[BASELINE].items()
    ]
    if min(ratios) < 1:
        return f"{min(ratios):.2f}x – {max(ratios):.1f}x m0-crypto time"
    return f"{min(ratios):.1f}x – {max(ratios):.1f}x faster"


def chart_alignment(rows: list[dict]) -> str:
    alignments = [row["alignment"] for row in rows]
    return "a" if "a" in alignments else alignments[0]


def chacha_cycles_chart(rows: list[dict]) -> str:
    impls = ordered(CODE_SIZES["chacha20poly1305"])
    alignment = chart_alignment(rows)
    chacha = cycles_per_byte(rows, impls, "chacha", alignment)
    encrypt = cycles_per_byte(rows, impls, "encrypt", alignment)
    y_title = "Cycles / Byte (lower is better)"
    return dashboard(
        "Cortex-M0+ ChaCha20-Poly1305 Performance",
        "Cycles per byte (lower is better) · ARM DDI 0484B zero-wait-state model",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, {rows[0]['aad_bytes']}-byte AAD)",
        impls,
        ("ChaCha20 Stream Cipher", speedup_badge(chacha), y_title, chacha, 50.0),
        ("ChaCha20-Poly1305 AEAD Encrypt", speedup_badge(encrypt), y_title, encrypt, 50.0),
    )


def blake2s_cycles_chart(rows: list[dict]) -> str:
    impls = ordered(CODE_SIZES["blake2s"])
    alignment = chart_alignment(rows)
    one = cycles_per_byte(rows, impls, "hash", alignment)
    stream = cycles_per_byte(rows, impls, "stream", alignment)
    y_title = "Cycles / Byte (lower is better)"
    return dashboard(
        "Cortex-M0+ BLAKE2s-256 Performance",
        "Cycles per byte, init + update + final (lower is better) · ARM DDI 0484B zero-wait-state model",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, unkeyed 32-byte digest)",
        impls,
        ("One Update Call", speedup_badge(one), y_title, one, 50.0),
        ("Updates of 16 Bytes", speedup_badge(stream), y_title, stream, 50.0),
    )


def x25519_cycles_chart(rows: list[dict]) -> str:
    impls = ordered(CODE_SIZES["x25519"])
    alignment = chart_alignment(rows)
    groups = {"shared": "Shared secret", "public": "Public key"}
    data = {impl: {} for impl in impls}
    for row in rows:
        if row["input"] == "rfc7748-6.1" and row["alignment"] == alignment:
            data[row["impl"]][groups[row["op"]]] = int(row["zero_wait_cycles"]) / 1000
    return dashboard(
        "Cortex-M0+ X25519 Performance",
        "Thousands of cycles per scalar multiplication (lower is better) · "
        "ARM DDI 0484B zero-wait-state model",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, RFC 7748 section 6.1 keys)",
        impls,
        ("X25519 Scalar Multiplication", speedup_badge(data),
         "Thousand Cycles (lower is better)", data, 60.0),
    )


def peak_stack(primitive: str, rows: list[dict]) -> dict:
    """(library peak, caller-held state) of the worst run per implementation and group."""
    return {
        impl: {
            group: max(
                (int(r["peak_stack_bytes"]), int(r["caller_state_bytes"]))
                for r in rows
                if r["impl"] == impl and r["op"] in ops
            )
            for group, ops in STACK_GROUPS[primitive].items()
        }
        for impl in ordered(CODE_SIZES[primitive])
    }


TITLES = {"chacha20poly1305": "ChaCha20-Poly1305", "blake2s": "BLAKE2s-256", "x25519": "X25519"}


def size_chart(primitive: str, rows: list[dict]) -> str:
    sizes = {
        impl: dict(zip(OPT_LEVELS, values)) for impl, values in CODE_SIZES[primitive].items()
    }
    code_badge = f"{sizes[BASELINE]['-Os (Size)']:,} B fixed"
    stack_badge = f"{M0C_STACK_BOUNDS[primitive]:,} B verified bound"
    return dashboard(
        f"Cortex-M0+ {TITLES[primitive]} Memory Footprint",
        "Code size (Flash) and peak stack usage (SRAM) in bytes · ARM Cortex-M0+ (thumbv6m-none-eabi)",
        "Stack: emulator-measured peak below the library call plus caller-held API state, worst run · "
        "m0-crypto stack bound proved in Lean 4",
        tuple(sizes),
        ("Code Size (Flash / ROM)", code_badge, "Bytes in Flash (lower is better)", sizes, 56.0),
        ("Peak Stack Usage (SRAM)", stack_badge, "Bytes on Stack (lower is better)",
         peak_stack(primitive, rows), 56.0),
    )


CYCLES_CHARTS = {
    "chacha20poly1305": chacha_cycles_chart,
    "blake2s": blake2s_cycles_chart,
    "x25519": x25519_cycles_chart,
}


def write_charts(primitive: str, rows: list[dict], directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = [directory / "cycles_summary.svg", directory / "size_summary.svg"]
    paths[0].write_text(CYCLES_CHARTS[primitive](rows))
    paths[1].write_text(size_chart(primitive, rows))
    return paths
