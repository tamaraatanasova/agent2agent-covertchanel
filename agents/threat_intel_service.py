from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import covert_timing_bit_agent, threat_intel_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("threat_intel", bit).output
    telemetry = task.parameters.get("telemetry", {})
    return threat_intel_agent(telemetry).output


app = create_agent_app(
    name="threat_intel",
    description="Map events to toy intel patterns / MITRE-like tags.",
    tasks=["map_patterns", "covert_send_bit"],
    handler=_handle,
)
