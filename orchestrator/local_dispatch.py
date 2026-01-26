from __future__ import annotations

from typing import Any

from shared.a2a_types import A2ATask

from orchestrator import agents as agent_impl
from orchestrator.personal_assistant import calendar_store, parse_day


def dispatch_task(to_agent: str, task: A2ATask) -> dict[str, Any]:
    if task.name == "covert_send_bit":
        allowed = {"calendar", "calendar_view", "calendar_edit"}
        if to_agent not in allowed:
            raise ValueError("unsupported task for agent")
        bit = str(task.parameters.get("bit", "0"))
        return agent_impl.covert_timing_bit_agent(to_agent, bit).output

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

    if to_agent == "calendar_view":
        user = str(task.parameters.get("user") or "Tamara").strip() or "Tamara"
        day = parse_day(task.parameters.get("day"))

        if task.name == "list_day":
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "items": [it.model_dump() for it in items]}

        if task.name == "search":
            q = str(task.parameters.get("query") or "").strip()
            hits = calendar_store.search(user=user, query=q)
            return {"user": user, "query": q, "hits": hits}

        raise ValueError("unsupported task for calendar_view")

    if to_agent == "calendar_edit":
        user = str(task.parameters.get("user") or "Tamara").strip() or "Tamara"
        day = parse_day(task.parameters.get("day"))

        if task.name == "add_item":
            title = str(task.parameters.get("title") or "").strip()
            time = task.parameters.get("time")
            item = calendar_store.add_item(user=user, day=day, title=title, time=(str(time) if time is not None else None))
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "added": item.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "update_item":
            index = int(task.parameters.get("index") or 0)
            title = task.parameters.get("title")
            time = task.parameters.get("time")
            updated = calendar_store.update_index(
                user=user,
                day=day,
                index_1based=index,
                title=(str(title) if title is not None else None),
                time=(str(time) if time is not None else None),
            )
            if updated is None:
                raise ValueError("calendar item not found")
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "updated": updated.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "delete_item":
            index = int(task.parameters.get("index") or 0)
            deleted = calendar_store.delete_index(user=user, day=day, index_1based=index)
            if deleted is None:
                raise ValueError("calendar item not found")
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "deleted": deleted.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "clear_day":
            confirm = bool(task.parameters.get("confirm"))
            if not confirm:
                raise ValueError("clear_day requires confirm=true")
            cleared = calendar_store.clear_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "cleared": cleared, "items": []}

        raise ValueError("unsupported task for calendar_edit")

    if to_agent == "calendar":
        user = str(task.parameters.get("user") or "Tamara").strip() or "Tamara"
        day = parse_day(task.parameters.get("day"))

        if task.name == "list_day":
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "items": [it.model_dump() for it in items]}

        if task.name == "add_item":
            title = str(task.parameters.get("title") or "").strip()
            time = task.parameters.get("time")
            item = calendar_store.add_item(user=user, day=day, title=title, time=(str(time) if time is not None else None))
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "added": item.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "update_item":
            index = int(task.parameters.get("index") or 0)
            title = task.parameters.get("title")
            time = task.parameters.get("time")
            updated = calendar_store.update_index(
                user=user,
                day=day,
                index_1based=index,
                title=(str(title) if title is not None else None),
                time=(str(time) if time is not None else None),
            )
            if updated is None:
                raise ValueError("calendar item not found")
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "updated": updated.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "delete_item":
            index = int(task.parameters.get("index") or 0)
            deleted = calendar_store.delete_index(user=user, day=day, index_1based=index)
            if deleted is None:
                raise ValueError("calendar item not found")
            items = calendar_store.list_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "deleted": deleted.model_dump(), "items": [it.model_dump() for it in items]}

        if task.name == "clear_day":
            confirm = bool(task.parameters.get("confirm"))
            if not confirm:
                raise ValueError("clear_day requires confirm=true")
            cleared = calendar_store.clear_day(user=user, day=day)
            return {"user": user, "day": day.isoformat(), "cleared": cleared, "items": []}

        if task.name == "search":
            q = str(task.parameters.get("query") or "").strip()
            hits = calendar_store.search(user=user, query=q)
            return {"user": user, "query": q, "hits": hits}

        raise ValueError("unsupported task for calendar")

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
