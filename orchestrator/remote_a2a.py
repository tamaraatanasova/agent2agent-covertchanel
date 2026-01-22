from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from shared.a2a_types import A2AEnvelope


@dataclass(frozen=True)
class RemoteAgentError(RuntimeError):
    agent: str
    url: str
    message: str


def fetch_agent_card(url: str, *, timeout_s: float = 1.5) -> dict[str, Any]:
    req = urllib.request.Request(url.rstrip("/") + "/agent-card", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout) as e:
        raise RemoteAgentError(agent="unknown", url=url, message=str(e)) from e


def send_envelope(url: str, envelope: A2AEnvelope, *, timeout_s: float = 8.0) -> dict[str, Any]:
    # Use JSON-mode serialization so UUID/datetime are converted to JSON-safe values.
    body = json.dumps(envelope.model_dump(mode="json")).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/a2a",
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout) as e:
        raise RemoteAgentError(agent=envelope.to_agent, url=url, message=str(e)) from e
