from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import telemetry_agent


def _handle(task: A2ATask) -> dict:
    bundle = task.parameters.get("bundle", {})
    return telemetry_agent(bundle).output


app = create_agent_app(
    name="telemetry",
    description="Normalize + enrich events (toy enrichment).",
    tasks=["normalize_enrich"],
    handler=_handle,
)

