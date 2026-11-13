"""Shannon entropy computation."""
from __future__ import annotations

import math
from collections import Counter


def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = completely random)."""
    if not data:
        return 0.0
    n = len(data)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in Counter(data).values()))


def sliding(data: bytes, window: int = 256, step: int | None = None) -> list[tuple[int, float]]:
    """Entropy over windows along the file: list of (offset, entropy).

    The step is adapted to get at most ~2000 points, enough for a chart.
    """
    if not data:
        return []
    if step is None:
        step = max(window, len(data) // 2000)
    return [(off, shannon(data[off:off + window])) for off in range(0, len(data), step)]


def describe(value: float) -> str:
    if value >= 7.2:
        return "very high (compressed/encrypted)"
    if value >= 6.5:
        return "high"
    if value >= 4.0:
        return "normal"
    if value > 0.0:
        return "low"
    return "none"
