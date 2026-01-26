from __future__ import annotations

import json
import os
from threading import Lock
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

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
    utc_now_iso,
)
from shared.a2a_types import A2AEnvelope, MessageType, A2ASecurity
from shared.a2a_types import A2ATask
from shared.webhooks import post_json


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

    def _task_set_state(task: dict[str, Any], state: str) -> None:
        status = task.get("status")
        if not isinstance(status, dict):
            status = {}
            task["status"] = status
        status["state"] = str(state)
        status["timestamp"] = utc_now_iso()

        hist = task.get("history")
        if not isinstance(hist, list):
            hist = []
            task["history"] = hist
        hist.append({"state": status["state"], "timestamp": status["timestamp"]})

    def _sse(event: str, data: dict[str, Any]) -> str:
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    def _maybe_push(task: dict[str, Any], event: str, data: dict[str, Any]) -> None:
        url = task.get("pushNotificationUrl")
        if not isinstance(url, str):
            return
        u = url.strip()
        if not (u.startswith("http://") or u.startswith("https://")):
            return
        post_json(u, {"event": event, "data": data})

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
            streaming=True,
            push_notifications=True,
            state_transition_history=True,
            documentation_url=base_url.rstrip("/") + "/docs",
            skills=skills,
        )

    @router.get("/agent-card")
    def agent_card() -> dict[str, Any]:
        return {"name": name, "description": description, "tasks": tasks}

    @router.post("/", response_model=None)
    def a2a_jsonrpc(payload: dict[str, Any], request: Request) -> dict[str, Any] | StreamingResponse:
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

        if method == "tasks/pushNotificationSet":
            task_id = params.get("id") or params.get("taskId")
            url = params.get("url") or params.get("pushNotificationUrl") or params.get("webhookUrl")
            if not isinstance(task_id, str) or not task_id.strip():
                return jsonrpc_error(req_id, code=-32602, message="Invalid params (missing task id)")
            if not isinstance(url, str) or not url.strip():
                return jsonrpc_error(req_id, code=-32602, message="Invalid params (missing url)")
            u = url.strip()
            if not (u.startswith("http://") or u.startswith("https://")):
                return jsonrpc_error(req_id, code=-32602, message="Invalid params (url must start with http:// or https://)")

            with a2a_task_store_lock:
                task = a2a_task_store.get(task_id)
                if task is None:
                    return jsonrpc_error(req_id, code=-32001, message="Task not found")
                task["pushNotificationUrl"] = u
                a2a_task_store[task_id] = task
            _maybe_push(task, "TaskSnapshotEvent", {"taskId": task_id, "task": task})
            return jsonrpc_success(req_id, result={"ok": True, "taskId": task_id})

        if method not in ("message/send", "tasks/send", "message/sendSubscribe", "tasks/sendSubscribe"):
            return jsonrpc_error(req_id, code=-32601, message="Method not found")

        msg = params.get("message") if isinstance(params.get("message"), dict) else {}
        parts = msg.get("parts") if isinstance(msg.get("parts"), list) else []

        context_id = msg.get("contextId") if isinstance(msg.get("contextId"), str) and msg.get("contextId").strip() else str(uuid4())
        task_id = msg.get("taskId") if isinstance(msg.get("taskId"), str) and msg.get("taskId").strip() else str(uuid4())
        push_url = params.get("pushNotificationUrl") or params.get("push_notification_url") or params.get("webhookUrl")
        push_url = push_url.strip() if isinstance(push_url, str) and push_url.strip() else None

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

        if method in ("message/sendSubscribe", "tasks/sendSubscribe"):
            accept = (request.headers.get("accept") or "").lower()
            if "text/event-stream" not in accept:
                return jsonrpc_error(req_id, code=-32600, message="sendSubscribe requires Accept: text/event-stream")

            task = build_task(task_id=task_id, context_id=context_id, state="submitted", artifacts=None, history=[])
            _task_set_state(task, "submitted")
            if push_url and (push_url.startswith("http://") or push_url.startswith("https://")):
                task["pushNotificationUrl"] = push_url
            with a2a_task_store_lock:
                a2a_task_store[task_id] = task

            def gen():
                _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                yield _sse("TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                try:
                    _task_set_state(task, "working")
                    with a2a_task_store_lock:
                        a2a_task_store[task_id] = task
                    _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                    yield _sse("TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})

                    output = handler(A2ATask(name=task_name, parameters=task_params))
                    if not isinstance(output, dict):
                        output = {"output": output}

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
                    existing = task.get("artifacts")
                    if not isinstance(existing, list):
                        existing = []
                        task["artifacts"] = existing
                    existing.extend(artifacts)
                    with a2a_task_store_lock:
                        a2a_task_store[task_id] = task
                    _maybe_push(task, "TaskArtifactUpdateEvent", {"taskId": task_id, "artifact": artifacts[0]})
                    yield _sse("TaskArtifactUpdateEvent", {"taskId": task_id, "artifact": artifacts[0]})

                    _task_set_state(task, "completed")
                    with a2a_task_store_lock:
                        a2a_task_store[task_id] = task
                    _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                    yield _sse("TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                except Exception as e:
                    _task_set_state(task, "failed")
                    task["error"] = {"code": "AGENT_ERROR", "message": str(e) or "error"}
                    with a2a_task_store_lock:
                        a2a_task_store[task_id] = task
                    _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status"), "error": task.get("error")})
                    yield _sse(
                        "TaskStatusUpdateEvent",
                        {"taskId": task_id, "status": task.get("status"), "error": task.get("error")},
                    )

            return StreamingResponse(gen(), media_type="text/event-stream")

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
        task = build_task(task_id=task_id, context_id=context_id, state="completed", artifacts=artifacts, history=[])
        _task_set_state(task, "completed")
        if push_url and (push_url.startswith("http://") or push_url.startswith("https://")):
            task["pushNotificationUrl"] = push_url
        with a2a_task_store_lock:
            a2a_task_store[task_id] = task
        _maybe_push(task, "TaskSnapshotEvent", {"taskId": task_id, "task": task})
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
