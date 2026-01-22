from __future__ import annotations

from typing import Any

from shared.a2a_types import A2ATask

from orchestrator import agents as agent_impl


def dispatch_task(to_agent: str, task: A2ATask) -> dict[str, Any]:
    if to_agent == "telemetry":
        if task.name != "normalize_enrich":
            raise ValueError("unsupported task for telemetry")
        bundle = task.parameters.get("bundle", {})
        return agent_impl.telemetry_agent(bundle).output

    if to_agent == "threat_intel":
        if task.name != "map_patterns":
            raise ValueError("unsupported task for threat_intel")
        telemetry = task.parameters.get("telemetry", {})
        return agent_impl.threat_intel_agent(telemetry).output

    if to_agent == "anomaly":
        if task.name != "score":
            raise ValueError("unsupported task for anomaly")
        telemetry = task.parameters.get("telemetry", {})
        return agent_impl.anomaly_agent(telemetry).output

    if to_agent == "ir_planner":
        if task.name != "plan":
            raise ValueError("unsupported task for ir_planner")
        ti = task.parameters.get("threat_intel", {})
        anomaly = task.parameters.get("anomaly", {})
        return agent_impl.ir_planner_agent(ti, anomaly).output

    if to_agent == "compliance":
        if task.name != "policy_check":
            raise ValueError("unsupported task for compliance")
        plan = task.parameters.get("plan", {})
        return agent_impl.compliance_agent(plan).output

    if to_agent == "report":
        if task.name != "report":
            raise ValueError("unsupported task for report")
        bundle = task.parameters.get("bundle", {})
        outputs = task.parameters.get("outputs", {})
        return agent_impl.report_agent(bundle, outputs).output

    if to_agent == "malicious":
        if task.name not in ("covert_send_bit", "covert_send_storage_bit", "covert_send_size_bit"):
            raise ValueError("unsupported task for malicious")
        bit = str(task.parameters.get("bit", "0"))
        if task.name == "covert_send_bit":
            return agent_impl.malicious_timing_bit_agent(bit).output
        if task.name == "covert_send_storage_bit":
            return agent_impl.malicious_storage_bit_agent(bit).output
        return agent_impl.malicious_size_bit_agent(bit).output

    raise ValueError(f"unknown agent: {to_agent}")
