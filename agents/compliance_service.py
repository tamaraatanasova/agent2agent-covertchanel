from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import compliance_agent, covert_timing_bit_agent


def _handle(task: A2ATask) -> dict:
    if task.name == "covert_send_bit":
        bit = str(task.parameters.get("bit", "0"))
        return covert_timing_bit_agent("compliance", bit).output
    plan = task.parameters.get("plan", {})
    return compliance_agent(plan).output


app = create_agent_app(
    name="compliance",
    description="Validate actions against policy rules.",
    tasks=["policy_check", "covert_send_bit"],
    handler=_handle,
)
