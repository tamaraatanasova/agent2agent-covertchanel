from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from math import log2
from statistics import median
from typing import Deque, DefaultDict, Iterable


@dataclass(frozen=True)
class TimingAlert:
    key: str
    score: float
    reason: str
    sample_count: int


def _entropy_score(latencies_ms: list[float], *, min_samples: int = 12, bins: int = 16) -> tuple[float, str]:
    if len(latencies_ms) < min_samples:
        return 0.0, "insufficient_samples"

    latencies_ms = [float(x) for x in latencies_ms]
    lo = min(latencies_ms)
    hi = max(latencies_ms)
    rng = hi - lo
    if rng < 50:
        return 0.0, f"range_too_small({rng:.1f}ms)"

    # Quantize into fixed bins across observed range.
    counts = [0] * bins
    for x in latencies_ms:
        t = (x - lo) / rng
        idx = int(t * bins)
        if idx >= bins:
            idx = bins - 1
        if idx < 0:
            idx = 0
        counts[idx] += 1

    n = sum(counts)
    if n <= 0:
        return 0.0, "no_samples"

    probs = [c / n for c in counts if c > 0]
    h = -sum(p * log2(p) for p in probs)
    h_norm = h / log2(bins)

    # "Consistent pattern" heuristic: concentrated into 1–2 bins (low entropy)
    # and not a single constant bin.
    top = sorted((c / n for c in counts), reverse=True)
    top1 = top[0] if top else 0.0
    top2 = top[1] if len(top) > 1 else 0.0

    if top1 > 0.95:
        return 0.0, f"almost_constant(p={top1:.2f})"
    if top1 + top2 < 0.75:
        return 0.0, f"not_concentrated(p12={top1 + top2:.2f}, Hn={h_norm:.2f})"

    # Low normalized entropy + large range indicates stable timing levels.
    if h_norm > 0.45 or rng < 120:
        return 0.0, f"entropy_not_suspicious(Hn={h_norm:.2f}, range={rng:.1f}ms)"

    ent_factor = min(1.0, (0.45 - h_norm) / 0.45)
    rng_factor = min(1.0, rng / 250.0)
    score = min(1.0, ent_factor * (0.65 + 0.35 * rng_factor))
    return score, f"low_entropy(Hn={h_norm:.2f}, bins={bins}, range={rng:.1f}ms, p12={top1 + top2:.2f})"


class LatencyDetector:
    def __init__(self, *, window: int = 64) -> None:
        self._window = window
        self._latencies: DefaultDict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def observe(self, key: str, latency_ms: float) -> TimingAlert | None:
        buf = self._latencies[key]
        buf.append(float(latency_ms))
        score, reason = _entropy_score(list(buf))
        if score >= 0.7:
            return TimingAlert(key=key, score=score, reason=reason, sample_count=len(buf))
        return None

    def get_window(self, key: str) -> list[float]:
        return list(self._latencies[key])
