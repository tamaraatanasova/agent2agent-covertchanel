from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException

from shared.a2a_types import A2AEnvelope, MessageType


def create_agent_app(*, name: str, description: str, tasks: list[str], handler) -> FastAPI:
    """
    Shared FastAPI wrapper for standalone agent services.
    Exposes:
      - GET /agent-card
      - POST /a2a  (TASK -> RESULT/ERROR)
    """

    app = FastAPI(title=f"AI-SOC Agent: {name}")
    router = APIRouter()

    @router.get("/agent-card")
    def agent_card() -> dict[str, Any]:
        return {"name": name, "description": description, "tasks": tasks}

    @router.post("/a2a")
    def a2a(envelope: A2AEnvelope) -> dict[str, Any]:
        if envelope.to_agent != name:
            raise HTTPException(status_code=400, detail="to_agent does not match agent")
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
        if envelope.task.name not in tasks:
            raise HTTPException(status_code=400, detail="unsupported task")

        try:
            output = handler(envelope.task)
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

    app.include_router(router)
    return app
