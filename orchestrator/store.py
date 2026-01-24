from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from shared.a2a_types import A2AEnvelope


@dataclass
class CaseRecord:
    case_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    incident_bundle: dict[str, Any] = field(default_factory=dict)
    messages: list[A2AEnvelope] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    agent_outputs: dict[str, Any] = field(default_factory=dict)
    final_report: dict[str, Any] | None = None


class InMemoryStore:
    def __init__(self) -> None:
        self._cases: dict[str, CaseRecord] = {}
        self._lock = Lock()

    def create_case(self, case_id: str, incident_bundle: dict[str, Any]) -> CaseRecord:
        with self._lock:
            rec = CaseRecord(case_id=case_id, incident_bundle=incident_bundle)
            self._cases[case_id] = rec
            return rec

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self._lock:
            return self._cases.get(case_id)

    def list_cases(self) -> list[str]:
        with self._lock:
            return list(self._cases.keys())

    def append_message(self, envelope: A2AEnvelope) -> None:
        with self._lock:
            rec = self._cases.setdefault(envelope.case_id, CaseRecord(case_id=envelope.case_id))
            rec.messages.append(envelope)

    def append_alert(self, case_id: str, alert: dict[str, Any]) -> None:
        with self._lock:
            rec = self._cases.setdefault(case_id, CaseRecord(case_id=case_id))
            rec.alerts.append(alert)

    def set_agent_output(self, case_id: str, agent: str, output: Any) -> None:
        with self._lock:
            rec = self._cases[case_id]
            rec.agent_outputs[agent] = output

    def set_final_report(self, case_id: str, report: dict[str, Any]) -> None:
        with self._lock:
            rec = self._cases[case_id]
            rec.final_report = report

    def patch_incident_bundle(self, case_id: str, patch: dict[str, Any]) -> None:
        if not isinstance(patch, dict) or not patch:
            return
        with self._lock:
            rec = self._cases.get(case_id)
            if rec is None:
                return
            if not isinstance(rec.incident_bundle, dict):
                rec.incident_bundle = {}
            rec.incident_bundle.update(patch)
