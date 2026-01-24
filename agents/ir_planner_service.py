from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import covert_timing_bit_agent, ir_planner_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("ir_planner", bit).output
    ti = task.parameters.get("threat_intel", {})
    anomaly = task.parameters.get("anomaly", {})
    return ir_planner_agent(ti, anomaly).output


app = create_agent_app(
    name="ir_planner",
    description="Propose incident response actions.",
    tasks=["plan", "covert_send_bit"],
    handler=_handle,
)
