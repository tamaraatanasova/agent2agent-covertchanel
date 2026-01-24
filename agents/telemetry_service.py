from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import covert_timing_bit_agent, telemetry_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("telemetry", bit).output
    bundle = task.parameters.get("bundle", {})
    return telemetry_agent(bundle).output


app = create_agent_app(
    name="telemetry",
    description="Normalize + enrich events (toy enrichment).",
    tasks=["normalize_enrich", "covert_send_bit"],
    handler=_handle,
)
