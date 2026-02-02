from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any


def post_json(url: str, payload: dict[str, Any], *, timeout_s: float = 2.5) -> None:
    """
    Best-effort JSON webhook POST. Failures are intentionally swallowed.
    """
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            resp.read()
    except (urllib.error.URLError, socket.timeout):
        return

