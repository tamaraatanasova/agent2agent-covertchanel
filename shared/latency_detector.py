from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import median
from typing import Deque, DefaultDict, Iterable


@dataclass(frozen=True)
class TimingAlert:
    key: str
    score: float
    reason: str
    sample_count: int


def _bimodal_score(latencies_ms: list[float], *, min_samples: int = 12) -> tuple[float, str]:
    if len(latencies_ms) < min_samples:
        return 0.0, "insufficient_samples"

    latencies_ms = sorted(latencies_ms)
    m = median(latencies_ms)
    low = [x for x in latencies_ms if x <= m]
    high = [x for x in latencies_ms if x > m]
    if not low or not high:
        return 0.0, "no_split"

    low_med = median(low)
    high_med = median(high)
    sep = high_med - low_med

    if sep < 120:
        return 0.0, f"separation_too_small({sep:.1f}ms)"

    balance = min(len(low), len(high)) / max(len(low), len(high))
    if balance < 0.25:
        return 0.2, f"unbalanced_modes(balance={balance:.2f}, sep={sep:.1f}ms)"

    score = min(1.0, (sep / 250.0) * (0.6 + 0.4 * balance))
    return score, f"bimodal_latency(sep={sep:.1f}ms, balance={balance:.2f})"


class LatencyDetector:
    def __init__(self, *, window: int = 64) -> None:
        self._window = window
        self._latencies: DefaultDict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def observe(self, key: str, latency_ms: float) -> TimingAlert | None:
        buf = self._latencies[key]
        buf.append(float(latency_ms))
        score, reason = _bimodal_score(list(buf))
        if score >= 0.7:
            return TimingAlert(key=key, score=score, reason=reason, sample_count=len(buf))
        return None

    def get_window(self, key: str) -> list[float]:
        return list(self._latencies[key])
