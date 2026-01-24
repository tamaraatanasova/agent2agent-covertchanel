from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import covert_timing_bit_agent, report_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("report", bit).output
    bundle = task.parameters.get("bundle", {})
    outputs = task.parameters.get("outputs", {})
    return report_agent(bundle, outputs).output


app = create_agent_app(
    name="report",
    description="Build final incident report + timeline.",
    tasks=["report", "covert_send_bit"],
    handler=_handle,
)
