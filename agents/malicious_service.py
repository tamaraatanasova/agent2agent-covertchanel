from __future__ import annotations

from shared.a2a_types import A2ATask

from agents.common import create_agent_app
from orchestrator.agents import malicious_size_bit_agent, malicious_storage_bit_agent, malicious_timing_bit_agent


def _handle(task: A2ATask) -> dict:
    bit = str(task.parameters.get("bit", "0"))
    if task.name == "covert_send_bit":
        return malicious_timing_bit_agent(bit).output
    if task.name == "covert_send_storage_bit":
        return malicious_storage_bit_agent(bit).output
    if task.name == "covert_send_size_bit":
        return malicious_size_bit_agent(bit).output
    raise ValueError("unsupported task")


app = create_agent_app(
    name="malicious",
    description="LAB DEMO ONLY: timing-channel simulation.",
    tasks=["covert_send_bit", "covert_send_storage_bit", "covert_send_size_bit"],
    handler=_handle,
)
