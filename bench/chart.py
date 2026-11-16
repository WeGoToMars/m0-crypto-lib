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
    "ossl": ("OpenSSL 3.5.0 kernels‡", "#d97706"),
    "mono": ("Monocypher 4.0.2", "#2563eb"),
    "mbed": ("Mbed TLS 4.3.0", "#475569"),
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


# Every other comparator is measured through its public API; OpenSSL's internal kernels
# are footnoted.
KERNELS = {
    "ossl": (
        "‡ OpenSSL's internal portable C functions, called directly; its public API (EVP) "
        "does not build for this target.",
    ),
}
# The ChaCha20-Poly1305 charts add this line under the OpenSSL footnote.
OSSL_COMPOSITION = (
    "   Its ChaCha20-Poly1305 composes OpenSSL's ChaCha20 and Poly1305 kernels in benchmark "
    "code (RFC 8439)."
)


def ordered(implementations) -> tuple:
    return tuple(impl for impl in NAMES if impl in implementations)


def fill(impl: str) -> str:
    return f"url(#hatch-{impl})" if impl in RESEARCH else NAMES[impl][1]
ALIGNMENT_TEXT = {"a": "aligned buffers", "u": "unaligned buffers", "ip": "in-place buffers"}
OPT_LEVELS = ("-Os (Size)", "-O2", "-O3 (Speed)")

# Proved in Lean 4: the largest stack bound over the asset's public functions, in bytes.
M0C_STACK_BOUNDS = {"chacha20poly1305": 320, "blake2s": 160, "x25519": 516}

# Hand-entered; count.py does not measure code size. The BLAKE2s and X25519 figures, and
# the ChaCha20-Poly1305 Mbed TLS figures, are the code_bytes of
# build/bench/PRIMITIVE/manifest.json for BENCH_OPT=-Os, -O2 and -O3: linked .text and
# .rodata of each comparator's own objects (harness and shared runtime excluded). The
# ChaCha20-Poly1305 OpenSSL figures include the harness composition.
CODE_SIZES = {
    "chacha20poly1305": {  # Flash bytes per optimization level
        "m0c": (3030, 3030, 3030),
        "wolf": (4092, 5982, 6848),
        "mono": (2890, 5364, 6648),
        "ossl": (2430, 2502, 2510),
        "mbed": (10196, 10950, 11360),
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
        "mbed": (14484, 20502, 22282),
    },
}
STACK_GROUPS = {
    "chacha20poly1305": {"AEAD Encrypt": {"encrypt"}, "AEAD Decrypt": {"decrypt", "reject"}, "ChaCha20": {"chacha"}},
    "blake2s": {"One update": {"hash"}, "16-byte updates": {"stream"}},
    "x25519": {"Shared secret": {"shared"}, "Public key": {"public"}},
}


# Segments of the RAM bars, bottom up; the third appears only where a library has
# static data or a heap (Mbed TLS).
STACK_KEY = ("Library stack peak", "Caller-held API state", "Library heap and static data")
STACK_OPACITY = (1, 0.35, 0.15)


def y_axis(max_value: float) -> tuple[float, float]:
    """Return (axis top, tick step) with headroom for the labels above bars."""
    for limit, top, step in (
        (100, 100, 20), (200, 220, 50), (320, 350, 50),
        (600, 600, 100), (1000, 1000, 200), (1600, 1600, 400), (2500, 2500, 500),
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

    A tuple value draws a stacked bar, bottom up: solid, light, then lighter outlined.
    """
    groups = list(data[BASELINE])
    stacked = any(isinstance(v, tuple) for values in data.values() for v in values.values())
    plot_x, plot_y = x + pad_left, y + 54
    plot_w, plot_h = w - pad_left - 16, h - 90
    bottom = plot_y + plot_h
    peak = max(total(v) for values in data.values() for v in values.values())
    # Stacked panels carry a key in the top-left corner: keep bars below it.
    key = [label for i, label in enumerate(STACK_KEY) if stacked and any(
        isinstance(v, tuple) and len(v) > i and v[i] for values in data.values()
        for v in values.values())]
    top, step = y_axis(peak * (1.1 + 0.1 * len(key)) if stacked else peak)
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
            segments = values[group] if isinstance(values[group], tuple) else (value,)
            segment_bottom = bottom
            for i, segment in enumerate(segments):
                segment_h = segment / top * plot_h
                style = (f'fill="{fill(impl)}"' if i == 0 else
                         f'fill="{color}" fill-opacity="{STACK_OPACITY[i]}"'
                         + (f' stroke="{color}" stroke-width="0.8"' if i == 2 else ""))
                if segment:
                    parts.append(
                        f'<rect x="{bar_x:.1f}" y="{segment_bottom - segment_h:.1f}" width="{bar_w:.1f}" '
                        f'height="{segment_h:.1f}" {style} rx="2"/>'
                    )
                segment_bottom -= segment_h
            parts += [
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
    for i, label in enumerate(key):
        key_y = plot_y + 6 + i * 16
        outline = ' stroke="#64748b" stroke-width="0.8"' if i == 2 else ""
        parts.append(
            f'<rect x="{plot_x + 10:.1f}" y="{key_y:.1f}" width="10" height="10" rx="2" '
            f'fill="#64748b" fill-opacity="{STACK_OPACITY[i]}"{outline}/>'
            f'<text x="{plot_x + 26:.1f}" y="{key_y + 9:.1f}" font-size="10" fill="#475569">{label}</text>'
        )
    return "\n".join(parts)


def dashboard(title, subtitle, footer, impls, left, right=None, extra_notes=()) -> str:
    """Two panels side by side (or one full-width panel) under a shared header and legend.
    Footnotes for research implementations and kernels go below the footer."""
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
    footnotes = {**RESEARCH, **KERNELS}
    notes = [line for impl in impls if impl in footnotes for line in footnotes[impl]]
    notes += [note for note in extra_notes if "ossl" in impls]
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
            data[row["impl"]][f"{length} B"] = int(row["board_cycles"]) / length
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


def measured(rows: list[dict]) -> tuple:
    """Implementations with board counts in rows."""
    return ordered({row["impl"] for row in rows})


def chacha_cycles_chart(rows: list[dict]) -> str:
    impls = measured(rows)
    alignment = chart_alignment(rows)
    chacha = cycles_per_byte(rows, impls, "chacha", alignment)
    encrypt = cycles_per_byte(rows, impls, "encrypt", alignment)
    y_title = "Cycles / Byte (lower is better)"
    return dashboard(
        "Cortex-M0+ ChaCha20-Poly1305 Performance",
        "Cycles per byte (lower is better) · measured on one TI MSPM0L2228, code in flash",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, {rows[0]['aad_bytes']}-byte AAD)",
        impls,
        ("ChaCha20 Stream Cipher", speedup_badge(chacha), y_title, chacha, 50.0),
        ("ChaCha20-Poly1305 AEAD Encrypt", speedup_badge(encrypt), y_title, encrypt, 50.0),
        extra_notes=(OSSL_COMPOSITION,),
    )


def blake2s_cycles_chart(rows: list[dict]) -> str:
    impls = measured(rows)
    alignment = chart_alignment(rows)
    one = cycles_per_byte(rows, impls, "hash", alignment)
    stream = cycles_per_byte(rows, impls, "stream", alignment)
    y_title = "Cycles / Byte (lower is better)"
    return dashboard(
        "Cortex-M0+ BLAKE2s-256 Performance",
        "Cycles per byte, init + update + final (lower is better) · measured on one TI MSPM0L2228, code in flash",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, unkeyed 32-byte digest)",
        impls,
        ("One Update Call", speedup_badge(one), y_title, one, 50.0),
        ("Updates of 16 Bytes", speedup_badge(stream), y_title, stream, 50.0),
    )


def x25519_cycles_chart(rows: list[dict]) -> str:
    impls = measured(rows)
    alignment = chart_alignment(rows)
    groups = {"shared": "Shared secret", "public": "Public key"}
    data = {impl: {} for impl in impls}
    for row in rows:
        if row["input"] == "rfc7748-6.1" and row["alignment"] == alignment:
            data[row["impl"]][groups[row["op"]]] = int(row["board_cycles"]) / 1000
    return dashboard(
        "Cortex-M0+ X25519 Performance",
        "Thousands of cycles per scalar multiplication (lower is better) · "
        "measured on one TI MSPM0L2228, code in flash",
        "TI MSPM0L2228 reference configuration (single-cycle hardware multiplier, "
        f"{ALIGNMENT_TEXT[alignment]}, RFC 7748 section 6.1 keys)",
        impls,
        ("X25519 Scalar Multiplication", speedup_badge(data),
         "Thousand Cycles (lower is better)", data, 60.0),
    )


def peak_ram(primitive: str, rows: list[dict]) -> dict:
    """(library stack peak, caller-held state, library heap and static data): the largest
    of each over the runs, per implementation and group."""
    def worst(impl, ops, *columns):
        return max(
            sum(int(r.get(column, 0)) for column in columns)
            for r in rows if r["impl"] == impl and r["op"] in ops
        )

    return {
        impl: {
            group: (
                worst(impl, ops, "peak_stack_bytes"),
                worst(impl, ops, "caller_state_bytes"),
                worst(impl, ops, "peak_heap_bytes", "static_ram_bytes"),
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
        "Code size (Flash) and peak RAM usage (SRAM) in bytes · ARM Cortex-M0+ (thumbv6m-none-eabi)",
        "RAM: emulator-measured stack peak, caller-held API state, static data and peak heap, worst run · "
        "m0-crypto stack bound proved in Lean 4",
        tuple(sizes),
        ("Code Size (Flash / ROM)", code_badge, "Bytes in Flash (lower is better)", sizes, 56.0),
        ("Peak RAM Usage (SRAM)", stack_badge, "Bytes of RAM (lower is better)",
         peak_ram(primitive, rows), 56.0),
        extra_notes=(OSSL_COMPOSITION,) if primitive == "chacha20poly1305" else (),
    )


CYCLES_CHARTS = {
    "chacha20poly1305": chacha_cycles_chart,
    "blake2s": blake2s_cycles_chart,
    "x25519": x25519_cycles_chart,
}


def write_charts(primitive: str, rows: list[dict], directory: Path) -> list[Path]:
    """The size chart, from count.py rows."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "size_summary.svg"
    path.write_text(size_chart(primitive, rows))
    return [path]


def write_cycles_chart(primitive: str, rows: list[dict], directory: Path) -> Path:
    """The cycles chart, from bench/board/compare_summary.py rows ("board_cycles")."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "cycles_summary.svg"
    path.write_text(CYCLES_CHARTS[primitive](rows))
    return path
