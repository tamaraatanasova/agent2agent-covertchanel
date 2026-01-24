from __future__ import annotations

import json
import os
from threading import Lock
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, FastAPI, HTTPException, Request

from shared.a2a_keys import KeyRegistry, load_private_key_b64, security_enabled
from shared.a2a_jsonrpc import (
    build_agent_card,
    build_artifact,
    build_data_part,
    build_task,
    build_text_part,
    extract_data,
    extract_text,
    jsonrpc_error,
    jsonrpc_success,
    parse_json_object,
)
from shared.a2a_types import A2AEnvelope, MessageType, A2ASecurity
from shared.a2a_types import A2ATask


def create_agent_app(*, name: str, description: str, tasks: list[str], handler) -> FastAPI:
    """
    Shared FastAPI wrapper for standalone agent services.
    Exposes:
      - GET /agent-card
      - POST /a2a  (TASK -> RESULT/ERROR)
    """

    app = FastAPI(title=f"AI-SOC Agent: {name}")
    router = APIRouter()

    require_sig = security_enabled()
    registry: KeyRegistry | None = None
    private_key_b64: str | None = None
    if require_sig:
        registry = KeyRegistry.load()
        private_key_b64 = load_private_key_b64(name)

    a2a_task_store: dict[str, dict[str, Any]] = {}
    a2a_task_store_lock = Lock()

    @router.get("/.well-known/agent.json")
    def well_known_agent_card(request: Request) -> dict[str, Any]:
        base_url = str(request.base_url)
        skills: list[dict[str, Any]] = []
        for t in tasks:
            skills.append(
                {
                    "id": t,
                    "name": t,
                    "description": f"{description} (task: {t})",
                    "tags": ["ai-soc", name],
                    "examples": [
                        json.dumps({"name": t, "parameters": {}}, ensure_ascii=False),
                        json.dumps({"task": {"name": t, "parameters": {}}}, ensure_ascii=False),
                    ],
                }
            )

        return build_agent_card(
            name=name,
            description=description,
            url=base_url,
            version="0.1.0",
            streaming=False,
            documentation_url=base_url.rstrip("/") + "/docs",
            skills=skills,
        )

    @router.get("/agent-card")
    def agent_card() -> dict[str, Any]:
        return {"name": name, "description": description, "tasks": tasks}

    @router.post("/")
    def a2a_jsonrpc(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """
        Minimal A2A JSON-RPC compatibility:
        - POST /            (message/send, tasks/get)
        - GET /.well-known/agent.json
        This enables interoperability with the google/a2a-python client SDK.
        """

        req_id = payload.get("id")
        if payload.get("jsonrpc") != "2.0":
            return jsonrpc_error(req_id, code=-32600, message='Invalid JSON-RPC version (expected "2.0")')

        method = payload.get("method")
        if not isinstance(method, str) or not method:
            return jsonrpc_error(req_id, code=-32600, message="Invalid JSON-RPC request (missing method)")

        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}

        if method == "tasks/get":
            task_id = params.get("id")
            if not isinstance(task_id, str) or not task_id.strip():
                return jsonrpc_error(req_id, code=-32602, message="Invalid params (missing task id)")
            with a2a_task_store_lock:
                task = a2a_task_store.get(task_id)
            if task is None:
                return jsonrpc_error(req_id, code=-32001, message="Task not found")
            return jsonrpc_success(req_id, result=task)

        if method != "message/send":
            return jsonrpc_error(req_id, code=-32601, message="Method not found")

        msg = params.get("message") if isinstance(params.get("message"), dict) else {}
        parts = msg.get("parts") if isinstance(msg.get("parts"), list) else []

        context_id = msg.get("contextId") if isinstance(msg.get("contextId"), str) and msg.get("contextId").strip() else str(uuid4())
        task_id = msg.get("taskId") if isinstance(msg.get("taskId"), str) and msg.get("taskId").strip() else str(uuid4())

        candidates = extract_data(parts)
        text_obj = parse_json_object(extract_text(parts))
        if text_obj:
            candidates.append(text_obj)

        task_obj: dict[str, Any] | None = None
        for c in candidates:
            if not isinstance(c, dict):
                continue
            if isinstance(c.get("task"), dict):
                task_obj = c["task"]
                break
            task_obj = c
            break

        if not task_obj:
            return jsonrpc_error(
                req_id,
                code=-32602,
                message="Invalid params (expected a task payload)",
                data={
                    "hint": "Provide a data part like {kind:'data',data:{name:'<task>',parameters:{...}}} or send a JSON text object.",
                    "supported_tasks": tasks,
                },
            )

        task_name = task_obj.get("name")
        task_params = task_obj.get("parameters")
        if not isinstance(task_name, str) or not task_name.strip():
            return jsonrpc_error(req_id, code=-32602, message="Invalid params (task.name is required)")
        if task_name not in tasks:
            return jsonrpc_error(
                req_id,
                code=-32602,
                message=f"Unsupported task: {task_name}",
                data={"supported_tasks": tasks},
            )
        if not isinstance(task_params, dict):
            task_params = {}

        try:
            output = handler(A2ATask(name=task_name, parameters=task_params))
            if not isinstance(output, dict):
                output = {"output": output}
        except Exception as e:
            return jsonrpc_error(req_id, code=-32603, message=str(e) or "Internal error")

        artifacts = [
            build_artifact(
                name="result",
                description=f"{name}:{task_name} output",
                parts=[
                    build_data_part(output),
                    build_text_part(json.dumps(output, ensure_ascii=False)[:8000]),
                ],
            )
        ]
        task = build_task(task_id=task_id, context_id=context_id, state="completed", artifacts=artifacts)
        with a2a_task_store_lock:
            a2a_task_store[task_id] = task
        return jsonrpc_success(req_id, result=task)

    @router.post("/a2a")
    def a2a(envelope: A2AEnvelope) -> dict[str, Any]:
        if envelope.to_agent != name:
            raise HTTPException(status_code=400, detail="to_agent does not match agent")

        if require_sig:
            if envelope.security is None:
                raise HTTPException(status_code=401, detail="missing A2A security signature")
            pub = registry.public_key_for(envelope.from_agent) if registry else None
            if not pub:
                raise HTTPException(status_code=401, detail=f"unknown sender public key: {envelope.from_agent}")
            try:
                envelope.security.verify_envelope(envelope, public_key_b64=pub)
            except Exception:
                raise HTTPException(status_code=401, detail="invalid A2A signature")

        if envelope.type == MessageType.HEARTBEAT:
            resp = A2AEnvelope(
                case_id=envelope.case_id,
                parent_id=envelope.message_id,
                from_agent=name,
                to_agent=envelope.from_agent,
                type=MessageType.HEARTBEAT,
                trace=envelope.trace,
            )
            if require_sig and private_key_b64:
                resp.security = A2ASecurity.sign_envelope(resp, private_key_b64=private_key_b64)
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
            if require_sig and private_key_b64:
                resp.security = A2ASecurity.sign_envelope(resp, private_key_b64=private_key_b64)
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
            if require_sig and private_key_b64:
                err.security = A2ASecurity.sign_envelope(err, private_key_b64=private_key_b64)
            return err.model_dump()

    app.include_router(router)
    return app
