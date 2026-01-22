from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import report_agent


def _handle(task: A2ATask) -> dict:
    bundle = task.parameters.get("bundle", {})
    outputs = task.parameters.get("outputs", {})
    return report_agent(bundle, outputs).output


app = create_agent_app(
    name="report",
    description="Build final incident report + timeline.",
    tasks=["report"],
    handler=_handle,
)

