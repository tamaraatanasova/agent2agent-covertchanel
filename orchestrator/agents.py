from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class AgentResult:
    agent: str
    output: dict[str, Any]


def telemetry_agent(bundle: dict[str, Any]) -> AgentResult:
    raw_events = bundle.get("events", []) or []
    normalized: list[dict[str, Any]] = []
    hostnames: set[str] = set()

    for ev in raw_events:
        if not isinstance(ev, dict):
            ev = {"msg": str(ev)}
        msg = str(ev.get("msg") or ev.get("message") or ev)
        host = str(ev.get("host") or ev.get("hostname") or ev.get("device") or "unknown").strip().lower()
        if host:
            hostnames.add(host)

        event_id = ev.get("event_id") or ev.get("id") or str(uuid4())
        norm = {
            "event_id": str(event_id),
            "host": host,
            "source": ev.get("source") or "unknown",
            "msg": msg,
            "tags": _extract_tags(msg),
        }
        normalized.append(norm)

    return AgentResult(
        agent="telemetry",
        output={
            "normalized_events": normalized,
            "event_count": len(normalized),
            "hosts": sorted(hostnames),
            "summary": {"unique_hosts": len(hostnames)},
        },
    )


def threat_intel_agent(telemetry: dict[str, Any]) -> AgentResult:
    matches: list[dict[str, Any]] = []
    mitre_techniques: set[str] = set()
    iocs: set[str] = set()

    for e in telemetry.get("normalized_events", []):
        msg = str(e.get("msg", "")).lower()
        tags = set(e.get("tags", []))

        if "mimikatz" in msg or "lsass" in msg:
            matches.append(_match("toy_rule:credential_dumping", e, mitre="T1003"))
            mitre_techniques.add("T1003")
        if "powershell" in msg or "pwsh" in tags:
            matches.append(_match("toy_rule:powershell_execution", e, mitre="T1059.001"))
            mitre_techniques.add("T1059.001")
        if "rundll32" in msg or "regsvr32" in msg:
            matches.append(_match("toy_rule:lolbin_execution", e, mitre="T1218"))
            mitre_techniques.add("T1218")

        for ip in _extract_ips(msg):
            iocs.add(ip)

    severity = _severity_from_intel(len(matches), len(iocs))
    return AgentResult(
        agent="threat_intel",
        output={
            "match_count": len(matches),
            "matches": matches[:50],
            "mitre_techniques": sorted(mitre_techniques),
            "iocs": {"ips": sorted(iocs)},
            "severity": severity,
        },
    )


def anomaly_agent(telemetry: dict[str, Any]) -> AgentResult:
    events = telemetry.get("normalized_events", [])
    event_count = int(telemetry.get("event_count") or len(events))

    signals: list[dict[str, Any]] = []
    score = 0.0

    if event_count >= 80:
        signals.append({"signal": "high_event_volume", "weight": 0.35, "evidence": {"event_count": event_count}})
        score += 0.35

    failed_logins = sum(1 for e in events if "login failure" in str(e.get("msg", "")).lower())
    if failed_logins >= 10:
        signals.append({"signal": "bruteforce_like", "weight": 0.35, "evidence": {"failed_logins": failed_logins}})
        score += 0.35

    suspicious = sum(1 for e in events if "mimikatz" in str(e.get("msg", "")).lower())
    if suspicious >= 1:
        signals.append({"signal": "known_bad_tooling", "weight": 0.4, "evidence": {"count": suspicious}})
        score += 0.4

    score = min(1.0, score)
    return AgentResult(
        agent="anomaly",
        output={
            "anomaly_score": score,
            "signals": signals,
            "severity": _severity_from_anomaly(score),
        },
    )


def ir_planner_agent(ti: dict[str, Any], anomaly: dict[str, Any]) -> AgentResult:
    ti_sev = ti.get("severity") or "low"
    an_sev = anomaly.get("severity") or "low"
    high_risk = ti_sev in ("high", "critical") or an_sev in ("high", "critical")

    actions: list[dict[str, Any]] = [
        {
            "action": "triage",
            "priority": 2,
            "steps": [
                "validate alert fidelity",
                "scope impacted hosts/users",
                "collect volatile data",
                "preserve logs (EDR, auth, DNS, proxy)",
            ],
        }
    ]

    if high_risk:
        actions.insert(
            0,
            {
                "action": "containment",
                "priority": 1,
                "steps": ["isolate suspected host", "disable compromised accounts", "block IoCs", "rotate credentials"],
            },
        )

    actions.append(
        {
            "action": "eradication_recovery",
            "priority": 3,
            "steps": ["remove persistence", "patch root cause", "reimage if needed", "monitor for recurrence"],
        }
    )

    return AgentResult(
        agent="ir_planner",
        output={"proposed_actions": sorted(actions, key=lambda a: a["priority"]), "risk": {"ti": ti_sev, "anomaly": an_sev}},
    )


def compliance_agent(plan: dict[str, Any]) -> AgentResult:
    allowed: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for item in plan.get("proposed_actions", []):
        action = item.get("action")
        if action == "containment":
            blocked.append({**item, "reason": "requires_approval_for_disruptive_actions"})
        else:
            allowed.append(item)
    return AgentResult(
        agent="compliance",
        output={
            "allowed": allowed,
            "blocked": blocked,
            "policy": {"containment_requires_approval": True},
        },
    )


def report_agent(bundle: dict[str, Any], outputs: dict[str, Any]) -> AgentResult:
    timeline = [
        {"event": "case_created"},
        {"event": "telemetry_enriched"},
        {"event": "intel_mapped"},
        {"event": "anomaly_scored"},
        {"event": "plan_proposed"},
        {"event": "policy_checked"},
        {"event": "report_generated"},
    ]
    telemetry = outputs.get("telemetry", {})
    ti = outputs.get("threat_intel", {})
    anomaly = outputs.get("anomaly", {})
    compliance = outputs.get("compliance", {})
    plan = outputs.get("ir_planner", {})

    severity = _max_severity([ti.get("severity"), anomaly.get("severity")])
    executive = _executive_summary(telemetry, ti, anomaly, severity)

    return AgentResult(
        agent="report",
        output={
            "executive_summary": executive,
            "severity": severity,
            "timeline": timeline,
            "metrics": {
                "event_count": telemetry.get("event_count", 0),
                "unique_hosts": telemetry.get("summary", {}).get("unique_hosts", 0),
                "intel_matches": ti.get("match_count", 0),
            },
            "recommendations": _recommendations(plan, compliance, ti),
            "outputs": outputs,
        },
    )


def malicious_timing_agent(bits: str) -> AgentResult:
    """
    Safe demo agent: encodes bits by delaying before returning.
    short delay=0, long delay=1 (timing channel).
    """

    for b in bits:
        _malicious_delay_bit(b)
    leaked = {"covert_bits_sent": len(bits), "note": "for lab demo only"}
    return AgentResult(agent="malicious", output=leaked)


def malicious_timing_bit_agent(bit: str) -> AgentResult:
    """
    Safe demo agent: encodes ONE bit per request by delaying before returning.
    """

    _malicious_delay_bit(bit)
    return AgentResult(agent="malicious", output={"bit": bit, "note": "for lab demo only"})


def malicious_storage_bit_agent(bit: str) -> AgentResult:
    """
    Safe demo agent: attempts a storage-channel by adding an extra output field.
    A strict gateway should reject/strip unexpected fields.
    """

    if bit not in ("0", "1"):
        raise ValueError("bit must be '0' or '1'")
    return AgentResult(agent="malicious", output={"bit": bit, "note": "for lab demo only", "extra": f"LEAK_{bit}"})


def malicious_size_bit_agent(bit: str) -> AgentResult:
    """
    Safe demo agent: encodes a bit in the length of an allowed string field.
    short note=0, long note=1.
    """

    if bit not in ("0", "1"):
        raise ValueError("bit must be '0' or '1'")
    note = ("X" * 20) if bit == "0" else ("X" * 220)
    return AgentResult(agent="malicious", output={"bit": bit, "note": note})


def _malicious_delay_bit(bit: str) -> None:
    if bit not in ("0", "1"):
        raise ValueError("bit must be '0' or '1'")
    time.sleep(0.05 if bit == "0" else 0.25)


_TAG_RE = re.compile(r"[a-z0-9_.:-]{3,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_tags(msg: str) -> list[str]:
    msg = (msg or "").lower()
    tags = set()
    for tok in _TAG_RE.findall(msg):
        if tok in ("powershell", "pwsh"):
            tags.add("pwsh")
        if tok in ("mimikatz", "lsass"):
            tags.add("cred_dump")
        if tok in ("rundll32", "regsvr32"):
            tags.add("lolbin")
    return sorted(tags)


def _extract_ips(msg: str) -> list[str]:
    return _IP_RE.findall(msg or "")


def _match(rule: str, event: dict[str, Any], *, mitre: str | None = None) -> dict[str, Any]:
    evidence = f"{event.get('host', 'unknown')}: {event.get('msg', '')}"[:220]
    stable = hashlib.sha256((rule + evidence).encode("utf-8")).hexdigest()[:12]
    out = {"id": stable, "rule": rule, "evidence": evidence}
    if mitre:
        out["mitre_technique"] = mitre
    return out


def _severity_from_intel(match_count: int, ioc_count: int) -> str:
    if match_count >= 3 or ioc_count >= 3:
        return "high"
    if match_count >= 1 or ioc_count >= 1:
        return "medium"
    return "low"


def _severity_from_anomaly(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _max_severity(values: list[Any]) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    best = "low"
    for v in values:
        if isinstance(v, str) and v in rank and rank[v] > rank[best]:
            best = v
    return best


def _executive_summary(telemetry: dict[str, Any], ti: dict[str, Any], anomaly: dict[str, Any], severity: str) -> str:
    hosts = telemetry.get("hosts", [])
    lines = [f"Severity: {severity}"]
    lines.append(f"Observed events: {telemetry.get('event_count', 0)} across {len(hosts)} host(s).")
    if ti.get("match_count", 0) > 0:
        lines.append(f"Threat intel matches: {ti.get('match_count')} (MITRE: {', '.join(ti.get('mitre_techniques', [])) or 'n/a'}).")
    lines.append(f"Anomaly score: {anomaly.get('anomaly_score', 0):.2f}.")
    return " ".join(lines)


def _recommendations(plan: dict[str, Any], compliance: dict[str, Any], ti: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    if ti.get("iocs", {}).get("ips"):
        recs.append("Block listed IoC IPs at egress and perimeter controls.")
    if compliance.get("blocked"):
        recs.append("Request approval for disruptive containment steps before execution.")
    if plan.get("proposed_actions"):
        recs.append("Follow triage → containment (if approved) → eradication/recovery playbook.")
    return recs[:8]
