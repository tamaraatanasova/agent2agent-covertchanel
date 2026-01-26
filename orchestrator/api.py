from __future__ import annotations

import json
from threading import Lock
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from orchestrator.orchestrator import Orchestrator
from orchestrator.store import InMemoryStore
from orchestrator.host_agent import HostAgentService
from orchestrator.agent_server import router as agents_router
from orchestrator.mitigation import MitigationConfig
from orchestrator.case_analysis import analyze_case
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
    utc_now_iso,
)
from shared.a2a_types import A2AEnvelope
from shared.webhooks import post_json


router = APIRouter()
store = InMemoryStore()
orch = Orchestrator(store)
host = HostAgentService(store=store, orch=orch)
router.include_router(agents_router)

a2a_task_store: dict[str, dict] = {}
a2a_task_store_lock = Lock()


def _task_set_state(task: dict, state: str) -> None:
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


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _maybe_push(task: dict, event: str, data: dict) -> None:
    url = task.get("pushNotificationUrl")
    if not isinstance(url, str):
        return
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return
    post_json(u, {"event": event, "data": data})


class IncidentBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    events: list[dict] = Field(default_factory=list)
    artifacts: dict = Field(default_factory=dict)


@router.post("/cases")
def create_case(bundle: IncidentBundle) -> dict:
    return orch.run_case(bundle.model_dump())

@router.get("/cases")
def list_cases() -> dict:
    return {"cases": store.list_cases()}


@router.get("/cases/{case_id}")
def get_case(case_id: str) -> dict:
    rec = store.get_case(case_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="case not found")

    bundle = rec.incident_bundle
    if isinstance(bundle, dict) and bundle.get("demo") == "covert" and "bits" in bundle:
        # Redact the actual bits from the JSON view (more realistic and safer).
        bundle = {**bundle, "bits": "<redacted>"}

    return {
        "case_id": rec.case_id,
        "created_at": rec.created_at,
        "incident_bundle": bundle,
        "agent_outputs": rec.agent_outputs,
        "final_report": rec.final_report,
        "alerts": rec.alerts,
        "analysis": analyze_case(rec),
        "messages": [m.model_dump() for m in rec.messages],
    }

@router.get("/health")
def health() -> dict:
    return {"ok": True}

@router.get("/.well-known/agent.json")
def well_known_agent_card(request: Request) -> dict:
    base_url = str(request.base_url).rstrip("/")
    skills = [
        {
            "id": "analyze_incident",
            "name": "Analyze Incident",
            "description": "Analyze an incident bundle or free-text description and return a SOC-style report.",
            "tags": ["soc", "incident", "analysis"],
            "examples": [
                "User reports suspicious PowerShell activity and login failures.",
                json.dumps({"title": "Demo", "events": [{"msg": "powershell spawned"}, {"msg": "login failure"}]}),
            ],
        }
    ]
    return build_agent_card(
        name="AI-SOC Host Agent",
        description="Host/orchestrator for AI-SOC agents (A2A Gateway + Orchestrator).",
        url=base_url + "/a2a/rpc",
        version="0.1.0",
        streaming=True,
        push_notifications=True,
        state_transition_history=True,
        documentation_url=base_url + "/docs",
        skills=skills,
    )

@router.post("/a2a/rpc", response_model=None)
def a2a_jsonrpc(payload: dict, request: Request) -> dict | StreamingResponse:
    """
    Minimal A2A JSON-RPC compatibility endpoint for the Host Agent.
    Supports:
      - message/send  (synchronous)
      - tasks/get     (in-memory, best-effort)
    """
    req_id = payload.get("id") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return jsonrpc_error(req_id, code=-32600, message='Invalid JSON-RPC request (expected {"jsonrpc":"2.0",...})')

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

    text = extract_text(parts)
    data_parts = extract_data(parts)
    for d in data_parts:
        # Convenience: allow sending an incident bundle as a data part.
        if not isinstance(d, dict):
            continue
        candidate = d.get("incident_bundle") if isinstance(d.get("incident_bundle"), dict) else d
        if isinstance(candidate, dict) and ("events" in candidate or "artifacts" in candidate or "title" in candidate):
            text = json.dumps(candidate, ensure_ascii=False)
            break

    if not text:
        return jsonrpc_error(req_id, code=-32602, message="Invalid params (message must include text or data)")

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

                resp = host.handle_message(session_id=context_id, text=text)
                sess = host.get_session(context_id)
                state = "input-required" if (sess is not None and sess.triage_pending) else "completed"

                artifacts = [
                    build_artifact(
                        name="reply",
                        description="Host Agent response",
                        parts=[
                            build_text_part(resp.get("reply") or ""),
                            build_data_part(resp if isinstance(resp, dict) else {"reply": str(resp)}),
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

                _task_set_state(task, state)
                with a2a_task_store_lock:
                    a2a_task_store[task_id] = task
                _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
                yield _sse("TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status")})
            except Exception as e:
                _task_set_state(task, "failed")
                task["error"] = {"code": "INTERNAL", "message": str(e) or "error"}
                with a2a_task_store_lock:
                    a2a_task_store[task_id] = task
                _maybe_push(task, "TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status"), "error": task.get("error")})
                yield _sse("TaskStatusUpdateEvent", {"taskId": task_id, "status": task.get("status"), "error": task.get("error")})

        return StreamingResponse(gen(), media_type="text/event-stream")

    resp = host.handle_message(session_id=context_id, text=text)
    sess = host.get_session(context_id)
    state = "input-required" if (sess is not None and sess.triage_pending) else "completed"

    artifacts = [
        build_artifact(
            name="reply",
            description="Host Agent response",
            parts=[
                build_text_part(resp.get("reply") or ""),
                build_data_part(resp if isinstance(resp, dict) else {"reply": str(resp)}),
            ],
        )
    ]
    task = build_task(task_id=task_id, context_id=context_id, state=state, artifacts=artifacts, history=[])
    _task_set_state(task, state)
    if push_url and (push_url.startswith("http://") or push_url.startswith("https://")):
        task["pushNotificationUrl"] = push_url
    with a2a_task_store_lock:
        a2a_task_store[task_id] = task
    _maybe_push(task, "TaskSnapshotEvent", {"taskId": task_id, "task": task})
    return jsonrpc_success(req_id, result=task)

@router.post("/a2a/send")
def a2a_send(envelope: A2AEnvelope) -> dict:
    """
    Gateway-like endpoint that strictly validates the envelope schema.
    """
    store.append_message(envelope)
    return {"stored": True, "message_id": str(envelope.message_id)}


class CovertDemoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(default="timing", pattern="^(timing|storage|size)$")
    topology: str = Field(default="single", pattern="^(single|mesh)$")
    message: str | None = Field(default=None, min_length=1, max_length=64)
    # For a realistic demo, prefer server-side generation (so the "secret" is not typed or exposed).
    server_generate_bits: bool = True
    bits_len: int = Field(default=64, ge=8, le=256)
    bits: str | None = Field(default=None, pattern="^[01]{8,256}$")
    compare: bool = True
    min_response_ms: int = Field(default=400, ge=0, le=5000)
    jitter_ms_low: int = Field(default=10, ge=0, le=5000)
    jitter_ms_high: int = Field(default=40, ge=0, le=5000)


@router.post("/demo/covert")
def demo_covert(req: CovertDemoRequest) -> dict:
    jitter = (int(req.jitter_ms_low), int(req.jitter_ms_high))
    if jitter[0] > jitter[1]:
        jitter = (jitter[1], jitter[0])
    return orch.demo_covert(
        bits=req.bits,
        bits_len=req.bits_len,
        server_generate_bits=req.server_generate_bits,
        channel=req.channel,
        compare=req.compare,
        topology=req.topology,
        message=req.message,
        mitigation=MitigationConfig(jitter_ms=jitter, min_response_ms=int(req.min_response_ms)),
    )


class HostMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=50_000)


@router.post("/host/sessions")
def host_create_session() -> dict:
    sess = host.create_session()
    return {
        "session_id": sess.session_id,
        "welcome": "Hi — I’m the Host Agent. Describe an incident or paste a JSON incident bundle (Ctrl+Enter to send). Tip: type /help for commands, or use the sample loader to try realistic scenarios.",
    }


@router.post("/host/sessions/{session_id}/messages")
def host_message(session_id: str, req: HostMessageRequest) -> dict:
    return host.handle_message(session_id=session_id, text=req.text)
