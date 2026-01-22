from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, median


@dataclass(frozen=True)
class DecodeMetrics:
    threshold_ms: float
    accuracy: float
    ber: float
    zeros_mean_ms: float
    ones_mean_ms: float
    sample_count: int


def decode_bits_by_latency(bits: str, latencies_ms: list[float | None]) -> tuple[str, DecodeMetrics | None]:
    """
    Unsupervised-ish decoder:
    - split by overall median into low/high groups
    - threshold = midpoint(median(low), median(high))
    - decode: latency <= threshold -> 0 else 1
    This models an observer attempting to infer the timing channel.
    """

    if not bits:
        raise ValueError("empty bits")

    pairs: list[tuple[str, float]] = [(b, float(x)) for b, x in zip(bits, latencies_ms, strict=False) if x is not None]
    if len(pairs) < 8:
        # Not enough samples to decode reliably.
        decoded = "".join("?" for _ in bits)
        return decoded, None

    ordered = sorted(x for _b, x in pairs)
    m = median(ordered)
    low = [x for _b, x in pairs if x <= m]
    high = [x for _b, x in pairs if x > m]
    if not low or not high:
        threshold = m
    else:
        threshold = (median(low) + median(high)) / 2.0

    decoded_list: list[str] = []
    for x in latencies_ms:
        if x is None:
            decoded_list.append("?")
        else:
            decoded_list.append("0" if float(x) <= threshold else "1")
    decoded = "".join(decoded_list)

    correct = sum(1 for a, b in zip(bits, decoded, strict=False) if b != "?" and a == b)
    sample_count = sum(1 for _a, b in zip(bits, decoded, strict=False) if b != "?")
    accuracy = (correct / sample_count) if sample_count else 0.0
    ber = 1.0 - accuracy if sample_count else 1.0

    zeros = [x for b, x in pairs if b == "0"]
    ones = [x for b, x in pairs if b == "1"]
    zeros_mean = mean(zeros) if zeros else 0.0
    ones_mean = mean(ones) if ones else 0.0

    metrics = DecodeMetrics(
        threshold_ms=float(threshold),
        accuracy=float(accuracy),
        ber=float(ber),
        zeros_mean_ms=float(zeros_mean),
        ones_mean_ms=float(ones_mean),
        sample_count=int(sample_count),
    )
    return decoded, metrics
