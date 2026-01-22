from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitConfig:
    capacity: int = 30
    refill_per_sec: float = 0.5  # 30/min


class TokenBucket:
    def __init__(self, cfg: RateLimitConfig) -> None:
        self._cfg = cfg
        self._tokens = float(cfg.capacity)
        self._last = time.monotonic()

    def allow(self, *, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now

        self._tokens = min(float(self._cfg.capacity), self._tokens + elapsed * float(self._cfg.refill_per_sec))
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

