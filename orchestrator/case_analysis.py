from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any

from orchestrator.covert_metrics import decode_bits_by_latency
from orchestrator.store import CaseRecord


def analyze_case(rec: CaseRecord) -> dict[str, Any]:
    outputs = rec.agent_outputs or {}
    report = rec.final_report or {}

    telemetry = outputs.get("telemetry", {}) or {}
    ti = outputs.get("threat_intel", {}) or {}
    anomaly = outputs.get("anomaly", {}) or {}
    plan = outputs.get("ir_planner", {}) or {}
    compliance = outputs.get("compliance", {}) or {}

    severity = report.get("severity") or _max_severity([ti.get("severity"), anomaly.get("severity")]) or "low"
    findings = _findings(telemetry=telemetry, threat_intel=ti, anomaly=anomaly)
    actions = _actions(plan=plan, compliance=compliance, report=report)

    trace_stats = _trace_stats(rec)
    covert = _covert_analysis(rec)

    return {
        "severity": severity,
        "findings": findings,
        "actions": actions,
        "trace": trace_stats,
        "covert": covert,
    }


def _findings(*, telemetry: dict[str, Any], threat_intel: dict[str, Any], anomaly: dict[str, Any]) -> dict[str, Any]:
    hosts = telemetry.get("hosts", []) or []
    metrics = {
        "event_count": telemetry.get("event_count") or telemetry.get("count") or 0,
        "unique_hosts": telemetry.get("summary", {}).get("unique_hosts", len(hosts)),
    }

    ti_matches = threat_intel.get("matches", []) or []
    mitre = threat_intel.get("mitre_techniques", []) or []
    iocs = threat_intel.get("iocs", {}) or {}

    signals = anomaly.get("signals", []) or []

    bullets: list[str] = []
    if metrics["event_count"]:
        bullets.append(f"Observed {metrics['event_count']} event(s) across {metrics['unique_hosts']} host(s).")
    if ti_matches:
        bullets.append(f"Threat-intel matched {len(ti_matches)} rule(s).")
    if mitre:
        bullets.append(f"Mapped techniques: {', '.join(mitre)}.")
    if iocs.get("ips"):
        bullets.append(f"Extracted IoC IPs: {', '.join(iocs['ips'][:8])}{'…' if len(iocs['ips']) > 8 else ''}.")
    if signals:
        bullets.append(f"Anomaly signals: {', '.join(s.get('signal', 'signal') for s in signals[:5])}.")

    evidence = {
        "hosts": hosts,
        "mitre_techniques": mitre,
        "iocs": iocs,
        "top_matches": ti_matches[:10],
        "signals": signals,
        "anomaly_score": anomaly.get("anomaly_score"),
    }

    return {"bullets": bullets, "evidence": evidence, "metrics": metrics}


def _actions(*, plan: dict[str, Any], compliance: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    allowed = compliance.get("allowed", []) or []
    blocked = compliance.get("blocked", []) or []
    recs = report.get("recommendations", []) or []

    proposed = plan.get("proposed_actions", []) or []
    return {
        "recommendations": recs[:10],
        "proposed": proposed,
        "allowed": allowed,
        "blocked": blocked,
        "policy": compliance.get("policy") or {},
    }


def _trace_stats(rec: CaseRecord) -> dict[str, Any]:
    msgs = rec.messages or []
    counts = defaultdict(int)
    per_edge_lat: dict[str, list[float]] = defaultdict(list)

    for m in msgs:
        counts[m.type.value] += 1
        if m.type.value == "RESULT" and m.result and isinstance(m.result, dict):
            timing = m.result.get("timing") or {}
            if isinstance(timing, dict) and timing.get("elapsed_ms") is not None:
                edge = f"{m.to_agent}<-{m.from_agent}"
                per_edge_lat[edge].append(float(timing["elapsed_ms"]))

    avg_latency = {k: round(mean(v), 1) for k, v in per_edge_lat.items() if v}

    alert_counts = defaultdict(int)
    for a in rec.alerts or []:
        alert_counts[a.get("type", "UNKNOWN")] += 1

    return {
        "message_counts": dict(counts),
        "avg_latency_ms": avg_latency,
        "alert_counts": dict(alert_counts),
    }


def _covert_analysis(rec: CaseRecord) -> dict[str, Any] | None:
    bundle = rec.incident_bundle or {}
    if bundle.get("demo") != "covert":
        trigger = bundle.get("covert_trigger") if isinstance(bundle, dict) else None
        if isinstance(trigger, dict) and trigger:
            return {
                "channel": trigger.get("channel") or "unknown",
                "topology": trigger.get("topology") or "single",
                "message": trigger.get("sent") or trigger.get("message"),
                "trigger_index": trigger.get("trigger_index"),
                "triggered_at": trigger.get("triggered_at"),
            }
        return None

    bits = str(bundle.get("bits") or "")
    if not bits:
        return {"channel": bundle.get("channel"), "error": "missing_bits"}

    def bits_to_text(decoded_bits: str) -> str:
        buf = bytearray()
        for i in range(0, len(decoded_bits), 8):
            chunk = decoded_bits[i : i + 8]
            if len(chunk) < 8:
                break
            if set(chunk) <= {"0", "1"}:
                buf.append(int(chunk, 2))
            else:
                buf.append(ord("?"))
        try:
            return buf.decode("utf-8", errors="replace")
        except Exception:
            return buf.decode("latin-1", errors="replace")

    # Map task message_id -> (i, bit)
    task_meta: dict[str, dict[str, Any]] = {}
    for m in rec.messages or []:
        if m.type.value == "TASK" and m.task and m.task.name in {"covert_send_bit", "covert_send_storage_bit", "covert_send_size_bit"}:
            params = m.task.parameters or {}
            task_meta[str(m.message_id)] = {"i": params.get("i"), "bit": params.get("bit")}

    # Group observations by mitigation mode from RESULT timing.
    modes: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    for m in rec.messages or []:
        if m.type.value != "RESULT" or not m.result:
            continue
        timing = (m.result.get("timing") or {}) if isinstance(m.result, dict) else {}
        mode = str(timing.get("mitigation_mode") or "unknown")
        parent = str(m.parent_id) if m.parent_id else ""
        meta = task_meta.get(parent) or {}
        i = meta.get("i")
        if i is None:
            continue
        try:
            idx = int(i)
        except Exception:
            continue
        modes[mode][idx] = {
            "total_ms": timing.get("total_ms"),
            "elapsed_ms": timing.get("elapsed_ms"),
            "output_size_bytes": timing.get("output_size_bytes"),
            "alert": timing.get("alert"),
        }

    def series_for(mode: str, key: str) -> list[float | None]:
        out: list[float | None] = [None] * len(bits)
        for idx, row in modes.get(mode, {}).items():
            if 0 <= idx < len(out) and row.get(key) is not None:
                out[idx] = float(row[key])
        return out

    channel = str(bundle.get("channel") or "timing")
    metric_key = "output_size_bytes" if channel == "size" else "total_ms"

    results: dict[str, Any] = {
        "channel": channel,
        "topology": bundle.get("topology") or "single",
        "bits_len": int(bundle.get("bits_len") or len(bits)),
        "bits_hash": bundle.get("bits_hash"),
        "message": bundle.get("message"),
        "modes": sorted(modes.keys()),
    }
    for mode in sorted(modes.keys()):
        vals = series_for(mode, metric_key)
        decoded, metrics = decode_bits_by_latency(bits, vals)
        entry: dict[str, Any] = {"decoded_bits": decoded, "metrics": metrics.__dict__ if metrics else None}
        if bundle.get("message"):
            entry["decoded_message"] = bits_to_text(decoded)
        results[mode] = entry
    return results


def _max_severity(values: list[Any]) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    best = "low"
    for v in values:
        if isinstance(v, str) and v in rank and rank[v] > rank[best]:
            best = v
    return best
