from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import anomaly_agent


def _handle(task: A2ATask) -> dict:
    telemetry = task.parameters.get("telemetry", {})
    return anomaly_agent(telemetry).output


app = create_agent_app(
    name="anomaly",
    description="Score anomalies (simple heuristics first).",
    tasks=["score"],
    handler=_handle,
)

