from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import anomaly_agent, covert_timing_bit_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("anomaly", bit).output
    telemetry = task.parameters.get("telemetry", {})
    return anomaly_agent(telemetry).output


app = create_agent_app(
    name="anomaly",
    description="Score anomalies (simple heuristics first).",
    tasks=["score", "covert_send_bit"],
    handler=_handle,
)
