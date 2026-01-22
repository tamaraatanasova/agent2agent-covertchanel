from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import ir_planner_agent


def _handle(task: A2ATask) -> dict:
    ti = task.parameters.get("threat_intel", {})
    anomaly = task.parameters.get("anomaly", {})
    return ir_planner_agent(ti, anomaly).output


app = create_agent_app(
    name="ir_planner",
    description="Propose incident response actions.",
    tasks=["plan"],
    handler=_handle,
)

