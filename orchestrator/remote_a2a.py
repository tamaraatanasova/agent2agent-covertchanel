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


def _normalize_agent_card(data: dict[str, Any]) -> dict[str, Any]:
    """
    AI-SOC historically used a minimal agent card at `/agent-card`:
      {name, description, tasks}

    The google/a2a-python SDK uses `/.well-known/agent.json` with `skills[]`.
    Normalize both into the minimal shape expected by the gateway UI.
    """
    if not isinstance(data, dict):
        return {}

    if isinstance(data.get("skills"), list) and not isinstance(data.get("tasks"), list):
        tasks: list[str] = []
        for s in data.get("skills") or []:
            if not isinstance(s, dict):
                continue
            sid = s.get("id")
            if isinstance(sid, str) and sid.strip():
                tasks.append(sid.strip())
        return {
            "name": data.get("name"),
            "description": data.get("description"),
            "tasks": tasks,
            "raw": data,
        }

    return data


def fetch_agent_card(url: str, *, timeout_s: float = 1.5) -> dict[str, Any]:
    base = url.rstrip("/")
    paths = ("/.well-known/agent.json", "/agent-card")

    last_err: Exception | None = None
    for p in paths:
        req = urllib.request.Request(base + p, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, dict):
                    return _normalize_agent_card(data)
                return {}
        except urllib.error.HTTPError as e:
            # Try the next path on 404 (different agent-card conventions).
            last_err = e
            if getattr(e, "code", None) == 404:
                continue
            break
        except (urllib.error.URLError, socket.timeout) as e:
            last_err = e
            break

    raise RemoteAgentError(agent="unknown", url=url, message=str(last_err) if last_err else "unknown error")


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
