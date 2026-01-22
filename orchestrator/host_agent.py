from __future__ import annotations

import json
from dataclasses import dataclass, field
from threading import Lock
from typing import Any
from uuid import uuid4

from orchestrator.orchestrator import Orchestrator
from orchestrator.store import InMemoryStore


@dataclass
class HostSession:
    session_id: str
    messages: list[dict[str, str]] = field(default_factory=list)
    last_case_id: str | None = None


class HostAgentService:
    """
    Simple in-process “Host Agent” that:
    - accepts user messages (text or JSON incident bundles)
    - calls the orchestrator (which calls internal agents)
    - returns a user-facing summary + links to stored case traces
    """

    def __init__(self, *, store: InMemoryStore, orch: Orchestrator) -> None:
        self._store = store
        self._orch = orch
        self._lock = Lock()
        self._sessions: dict[str, HostSession] = {}

    def create_session(self) -> HostSession:
        session_id = str(uuid4())
        sess = HostSession(session_id=session_id)
        with self._lock:
            self._sessions[session_id] = sess
        return sess

    def get_session(self, session_id: str) -> HostSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def handle_message(self, *, session_id: str, text: str) -> dict[str, Any]:
        sess = self.get_session(session_id)
        if sess is None:
            sess = self.create_session()
            session_id = sess.session_id

        text = (text or "").strip()
        if not text:
            return {"session_id": session_id, "reply": "Send an incident description or paste a JSON incident bundle."}

        sess.messages.append({"role": "user", "text": text})

        if text.lower().startswith("/help"):
            reply = (
                "Commands:\n"
                "- Paste JSON incident bundle\n"
                "- /case <id> (summarize an existing case)\n"
                "- /help"
            )
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply}

        if text.lower().startswith("/case"):
            parts = text.split(maxsplit=1)
            if len(parts) != 2:
                return {"session_id": session_id, "reply": "Usage: /case <case_id>"}
            case_id = parts[1].strip()
            rec = self._store.get_case(case_id)
            if rec is None:
                return {"session_id": session_id, "reply": f"Case not found: {case_id}"}
            reply = self._summarize_case(rec)
            sess.last_case_id = case_id
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

        bundle = self._parse_incident_bundle(text)
        result = self._orch.run_case(bundle)
        case_id = result.get("case_id")
        sess.last_case_id = case_id
        sess.messages.append({"role": "assistant", "text": self._format_reply(result)})

        alerts: list[dict[str, Any]] = []
        if case_id:
            rec = self._store.get_case(case_id)
            if rec is not None:
                alerts = rec.alerts

        return {"session_id": session_id, "reply": self._format_reply(result), "case_id": case_id, "alerts": alerts}

    def _parse_incident_bundle(self, text: str) -> dict[str, Any]:
        text = (text or "").strip()

        # If the user pasted a JSON bundle, use it directly.
        if text.startswith("{") and text.endswith("}"):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        # If the user pasted an LLM-style prompt, extract the incident portion.
        # Supported format:
        #   Title: ...
        #   Incident: ...
        # Anything before "Incident:" is treated as instructions and ignored for telemetry.
        lowered = text.lower()
        incident_text = text
        title: str | None = None

        if "incident:" in lowered:
            i = lowered.index("incident:")
            incident_text = text[i + len("incident:") :].strip()

        if "title:" in lowered:
            i = lowered.index("title:")
            rest = text[i + len("title:") :]
            title = rest.splitlines()[0].strip() or None

        # If the extracted incident is JSON, use it.
        if incident_text.startswith("{") and incident_text.endswith("}"):
            try:
                obj = json.loads(incident_text)
                if isinstance(obj, dict):
                    if title and "title" not in obj:
                        obj = {**obj, "title": title}
                    return obj
            except json.JSONDecodeError:
                pass

        return {"title": title or "User-described incident", "events": [{"msg": incident_text}], "artifacts": {}}

    def _format_reply(self, result: dict[str, Any]) -> str:
        if "error" in result and result["error"]:
            err = result["error"]
            return f"Error: {err.get('code', 'UNKNOWN')}: {err.get('message', 'request failed')}"

        report = result.get("report") or {}
        outputs = report.get("outputs") or {}
        ti = outputs.get("threat_intel", {}) or {}
        anomaly = outputs.get("anomaly", {}) or {}
        compliance = outputs.get("compliance", {}) or {}
        plan = outputs.get("ir_planner", {}) or {}

        lines: list[str] = []
        if result.get("case_id"):
            lines.append(f"Case created: {result['case_id']}")

        lines.append(f"Severity: {report.get('severity', 'low')}")
        if report.get("executive_summary"):
            lines.append(str(report["executive_summary"]))

        lines.append(f"Threat intel matches: {ti.get('match_count', 0)}")
        lines.append(f"Anomaly score: {float(anomaly.get('anomaly_score', 0.0)):.2f}")

        actions = plan.get("proposed_actions", [])
        allowed = compliance.get("allowed", [])
        blocked = compliance.get("blocked", [])
        if actions:
            lines.append(f"Proposed actions: {len(actions)} (allowed={len(allowed)}, blocked={len(blocked)})")
            if blocked:
                lines.append("Note: containment is blocked by policy until approved.")

        recs = report.get("recommendations") or []
        if recs:
            lines.append("Recommendations:")
            for r in recs[:5]:
                lines.append(f"- {r}")

        lines.append("Tip: open the case link to see full A2A message trace + timing alerts.")
        return "\n".join(lines)

    def _summarize_case(self, rec) -> str:
        lines = [f"Case: {rec.case_id}", f"Messages: {len(rec.messages)}", f"Alerts: {len(rec.alerts)}"]
        if rec.final_report:
            lines.append("Final report: available")
        else:
            lines.append("Final report: not set")
        return "\n".join(lines)
