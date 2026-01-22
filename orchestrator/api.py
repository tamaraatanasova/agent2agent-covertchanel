from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from orchestrator.orchestrator import Orchestrator
from orchestrator.store import InMemoryStore
from orchestrator.host_agent import HostAgentService
from orchestrator.agent_server import router as agents_router
from orchestrator.mitigation import MitigationConfig
from orchestrator.case_analysis import analyze_case
from shared.a2a_types import A2AEnvelope


router = APIRouter()
store = InMemoryStore()
orch = Orchestrator(store)
host = HostAgentService(store=store, orch=orch)
router.include_router(agents_router)


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
