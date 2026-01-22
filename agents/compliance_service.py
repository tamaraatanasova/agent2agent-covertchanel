from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import compliance_agent


def _handle(task: A2ATask) -> dict:
    plan = task.parameters.get("plan", {})
    return compliance_agent(plan).output


app = create_agent_app(
    name="compliance",
    description="Validate actions against policy rules.",
    tasks=["policy_check"],
    handler=_handle,
)

