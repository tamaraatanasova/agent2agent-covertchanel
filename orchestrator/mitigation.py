from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class MitigationConfig:
    jitter_ms: tuple[int, int] = (10, 40)
    min_response_ms: int = 400


class TimingMitigator:
    def __init__(self, cfg: MitigationConfig) -> None:
        self._cfg = cfg

    def apply(self, elapsed_ms: float) -> float:
        extra_ms = 0.0

        extra_ms = max(extra_ms, float(self._cfg.min_response_ms) - float(elapsed_ms))

        j_lo, j_hi = self._cfg.jitter_ms
        extra_ms += float(random.randint(j_lo, j_hi))

        time.sleep(extra_ms / 1000.0)
        return extra_ms
