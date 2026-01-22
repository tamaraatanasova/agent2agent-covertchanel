from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from orchestrator.config import AGENT_URLS, USE_REMOTE_AGENTS
from orchestrator.local_dispatch import dispatch_task as local_dispatch_task
from orchestrator.remote_a2a import RemoteAgentError, fetch_agent_card, send_envelope
from shared.a2a_types import A2AEnvelope, MessageType


router = APIRouter(prefix="/agents")


@router.get("")
def list_agents() -> dict[str, list[dict[str, Any]]]:
    """
    Returns configured agents (local config) + live connectivity if remote mode is enabled.
    """

    agents: list[dict[str, Any]] = []
    for name, url in AGENT_URLS.items():
        entry: dict[str, Any] = {"name": name, "url": url, "mode": "remote" if USE_REMOTE_AGENTS else "local"}
        if USE_REMOTE_AGENTS:
            try:
                card = fetch_agent_card(url)
                entry["online"] = True
                entry["description"] = card.get("description")
                entry["tasks"] = card.get("tasks", [])
            except RemoteAgentError as e:
                entry["online"] = False
                entry["error"] = e.message
        agents.append(entry)
    return {"agents": agents}


@router.post("/{name}/a2a")
def agent_a2a(name: str, envelope: A2AEnvelope) -> dict[str, Any]:
    """
    In local mode, dispatches to in-process agent implementation.
    In remote mode, proxies an A2A envelope to the selected agent service.
    """

    if envelope.to_agent != name:
        raise HTTPException(status_code=400, detail="to_agent does not match endpoint")

    if USE_REMOTE_AGENTS:
        url = AGENT_URLS.get(name)
        if url is None:
            raise HTTPException(status_code=404, detail="agent not configured")
        try:
            return send_envelope(url, envelope)
        except RemoteAgentError as e:
            raise HTTPException(status_code=502, detail=f"upstream agent error: {e.message}") from e

    # Local mode
    if envelope.type == MessageType.HEARTBEAT:
        resp = A2AEnvelope(
            case_id=envelope.case_id,
            parent_id=envelope.message_id,
            from_agent=name,
            to_agent=envelope.from_agent,
            type=MessageType.HEARTBEAT,
            trace=envelope.trace,
        )
        return resp.model_dump()

    if envelope.type != MessageType.TASK or envelope.task is None:
        raise HTTPException(status_code=400, detail="expected TASK with task (or HEARTBEAT)")

    try:
        output = local_dispatch_task(name, envelope.task)
        resp = A2AEnvelope(
            case_id=envelope.case_id,
            parent_id=envelope.message_id,
            from_agent=name,
            to_agent=envelope.from_agent,
            type=MessageType.RESULT,
            result={"output": output},
            trace=envelope.trace,
        )
        return resp.model_dump()
    except Exception as e:
        err = A2AEnvelope(
            case_id=envelope.case_id,
            parent_id=envelope.message_id,
            from_agent=name,
            to_agent=envelope.from_agent,
            type=MessageType.ERROR,
            error={"code": "AGENT_ERROR", "message": str(e)},
            trace=envelope.trace,
        )
        return err.model_dump()
