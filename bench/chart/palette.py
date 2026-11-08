"""Implementation registry and color palette for benchmark charts."""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ImplMeta:
    key: str
    name: str
    color: str
    is_baseline: bool = False


KNOWN_IMPLEMENTATIONS: Dict[str, ImplMeta] = {
    "m0c": ImplMeta(key="m0c", name="m0-crypto", color="#059669", is_baseline=True),
    "mono": ImplMeta(key="mono", name="Monocypher 4.0.2", color="#2563eb"),
    "ossl": ImplMeta(key="ossl", name="OpenSSL 3.5.0", color="#d97706"),
    "wolf": ImplMeta(key="wolf", name="wolfSSL 5.9.4", color="#7c3aed"),
    "sodium": ImplMeta(key="sodium", name="libsodium", color="#0284c7"),
    "bear": ImplMeta(key="bear", name="BearSSL", color="#e11d48"),
    "hacl": ImplMeta(key="hacl", name="HACL*", color="#4f46e5"),
}

# Distinct fallback colors for dynamically added implementations
FALLBACK_COLORS: List[str] = [
    "#0891b2",  # Cyan 600
    "#db2777",  # Pink 600
    "#65a30d",  # Lime 600
    "#d946ef",  # Fuchsia 500
    "#ca8a04",  # Yellow 600
    "#0d9488",  # Teal 600
    "#6366f1",  # Indigo 500
]


def get_impl_meta(key: str, index: Optional[int] = None) -> ImplMeta:
    """Return metadata for an implementation, falling back gracefully for new additions."""
    if key in KNOWN_IMPLEMENTATIONS:
        return KNOWN_IMPLEMENTATIONS[key]

    idx = index if index is not None else hash(key)
    color = FALLBACK_COLORS[abs(idx) % len(FALLBACK_COLORS)]
    name = key.replace("_", " ").title()
    return ImplMeta(key=key, name=name, color=color, is_baseline=False)

