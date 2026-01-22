from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OutputPolicy:
    """
    Minimal output hardening for covert-channel demos.
    - For storage-channel demo: forbid unexpected fields from malicious agent.
    - For size-channel demo: optionally normalize note length.
    """

    normalize_note_len: int | None = None


def enforce_malicious_output(task_name: str, output: dict[str, Any], *, policy: OutputPolicy) -> dict[str, Any]:
    allowed_keys = {"bit", "note"}
    if task_name == "covert_send_storage_bit":
        extras = set(output.keys()) - allowed_keys
        if extras:
            raise ValueError(f"storage_channel_blocked(extra_keys={sorted(extras)})")

    if task_name == "covert_send_size_bit" and policy.normalize_note_len is not None:
        note = str(output.get("note", ""))
        n = int(policy.normalize_note_len)
        if len(note) < n:
            note = note + (" " * (n - len(note)))
        else:
            note = note[:n]
        output = {**output, "note": note}

    # For timing channel, keep as-is (already defended by latency mitigations).
    return output

