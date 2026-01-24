from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def jsonrpc_error(
    request_id: str | int | None,
    *,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def jsonrpc_success(request_id: str | int | None, *, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_text_part(text: str) -> dict[str, Any]:
    return {"kind": "text", "text": str(text)}


def build_data_part(data: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "data", "data": data}


def build_artifact(*, name: str | None, parts: list[dict[str, Any]], description: str | None = None) -> dict[str, Any]:
    art: dict[str, Any] = {
        "artifactId": str(uuid4()),
        "parts": parts,
    }
    if name:
        art["name"] = str(name)
    if description:
        art["description"] = str(description)
    return art


def build_task(
    *,
    task_id: str,
    context_id: str,
    state: str,
    artifacts: list[dict[str, Any]] | None = None,
    history: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task: dict[str, Any] = {
        "kind": "task",
        "id": str(task_id),
        "contextId": str(context_id),
        "status": {"state": str(state), "timestamp": utc_now_iso()},
    }
    if artifacts:
        task["artifacts"] = artifacts
    if history:
        task["history"] = history
    if metadata:
        task["metadata"] = metadata
    return task


def build_agent_card(
    *,
    name: str,
    description: str,
    url: str,
    skills: list[dict[str, Any]],
    version: str = "0.1.0",
    streaming: bool = False,
    documentation_url: str | None = None,
) -> dict[str, Any]:
    card: dict[str, Any] = {
        "name": str(name),
        "description": str(description),
        "url": str(url),
        "version": str(version),
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "capabilities": {"streaming": bool(streaming), "pushNotifications": False, "stateTransitionHistory": False},
        "skills": skills,
    }
    if documentation_url:
        card["documentationUrl"] = str(documentation_url)
    return card


def extract_text(parts: list[dict[str, Any]] | None) -> str:
    if not parts:
        return ""
    chunks: list[str] = []
    for p in parts:
        if not isinstance(p, dict):
            continue
        if isinstance(p.get("text"), str):
            chunks.append(p["text"])
    return "\n".join(chunks).strip()


def extract_data(parts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not parts:
        return []
    out: list[dict[str, Any]] = []
    for p in parts:
        if not isinstance(p, dict):
            continue
        data = p.get("data")
        if isinstance(data, dict):
            out.append(data)
    return out


def parse_json_object(text: str) -> dict[str, Any] | None:
    s = (text or "").strip()
    if not s:
        return None
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None

