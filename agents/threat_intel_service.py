from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import threat_intel_agent


def _handle(task: A2ATask) -> dict:
    telemetry = task.parameters.get("telemetry", {})
    return threat_intel_agent(telemetry).output


app = create_agent_app(
    name="threat_intel",
    description="Map events to toy intel patterns / MITRE-like tags.",
    tasks=["map_patterns"],
    handler=_handle,
)

