from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any
from uuid import uuid4

from orchestrator.orchestrator import Orchestrator
from orchestrator.store import InMemoryStore


@dataclass
class HostSession:
    session_id: str
    messages: list[dict[str, str]] = field(default_factory=list)
    last_case_id: str | None = None
    triage_pending: bool = False
    triage_bundle: dict[str, Any] | None = None
    triage_questions: list[str] = field(default_factory=list)
    triage_attempts: int = 0
    covert_trigger_count: int = 0


class HostAgentService:
    """
    Simple in-process “Host Agent” that:
    - accepts user messages (text or JSON incident bundles)
    - calls the orchestrator (which calls internal agents)
    - returns a user-facing summary + links to stored case traces
    """

    def __init__(self, *, store: InMemoryStore, orch: Orchestrator) -> None:
        self._store = store
        self._orch = orch
        self._lock = Lock()
        self._sessions: dict[str, HostSession] = {}

    def create_session(self, *, session_id: str | None = None) -> HostSession:
        sid = session_id or str(uuid4())
        with self._lock:
            existing = self._sessions.get(sid)
            if existing is not None:
                return existing
            sess = HostSession(session_id=sid)
            self._sessions[sid] = sess
            return sess

    def get_session(self, session_id: str) -> HostSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def handle_message(self, *, session_id: str, text: str) -> dict[str, Any]:
        sess = self.get_session(session_id)
        if sess is None:
            # Preserve the provided session_id when integrating with external A2A
            # clients (maps cleanly to contextId).
            sess = self.create_session(session_id=session_id)

        text = (text or "").strip()
        if not text:
            return {"session_id": session_id, "reply": "Send an incident description or paste a JSON incident bundle."}

        sess.messages.append({"role": "user", "text": text})

        if text.lower().startswith("/"):
            resp = self._handle_command(sess, session_id, text)
            if resp is not None:
                return resp

        if text.lower().startswith("/case"):
            parts = text.split(maxsplit=1)
            if len(parts) != 2:
                return {"session_id": session_id, "reply": "Usage: /case <case_id>"}
            case_id = parts[1].strip()
            rec = self._store.get_case(case_id)
            if rec is None:
                return {"session_id": session_id, "reply": f"Case not found: {case_id}"}
            reply = self._summarize_case(rec)
            sess.last_case_id = case_id
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

        # If we previously asked triage questions, treat the next user message as
        # additional context and proceed with the queued bundle.
        if sess.triage_pending and sess.triage_bundle is not None:
            sess.triage_attempts += 1
            merged = self._merge_followup(sess.triage_bundle, text)
            sess.triage_pending = False
            sess.triage_questions = []
            sess.triage_bundle = None
            bundle = merged
        else:
            bundle = self._parse_incident_bundle(text)

            # Triage: for short/ambiguous free-text, ask a few clarifying questions
            # before running the full pipeline.
            if not self._looks_like_structured_bundle(bundle):
                questions = self._triage_questions(text)
                if questions:
                    sess.triage_pending = True
                    sess.triage_bundle = bundle
                    sess.triage_questions = questions
                    reply = self._format_questions(questions)
                    sess.messages.append({"role": "assistant", "text": reply})
                    return {"session_id": session_id, "reply": reply}

        result = self._orch.run_case(bundle)
        case_id = result.get("case_id")
        sess.last_case_id = case_id

        reply = self._format_reply(result)
        covert_summary: dict[str, Any] | None = None
        try:
            sess.covert_trigger_count += 1
            trigger_index = sess.covert_trigger_count
            triggered_at = datetime.now(timezone.utc).strftime("%H%M%SZ")
            msg = f"Tamara[{trigger_index} {triggered_at}]"
            channel = random.choice(["timing", "storage", "size"])
            topology = "mesh" if channel == "timing" else "single"

            # Run a short covert-channel send alongside the prompt.
            # This demonstrates a timing channel across agents without requiring the user
            # to click "Run" in the lab panel.
            covert = self._orch.demo_covert(
                channel=channel,
                topology=topology,
                compare=False,
                message=msg,
                single_mode="off",
            )
            sent = covert.get("message")
            covert_case_id = covert.get("case_id")
            covert_summary = {
                "trigger_index": trigger_index,
                "triggered_at": triggered_at,
                "case_id": covert_case_id,
                "channel": covert.get("channel"),
                "sent": sent,
                "topology": covert.get("topology"),
            }
            if case_id and covert_summary:
                self._store.patch_incident_bundle(case_id, {"covert_trigger": covert_summary})
        except Exception as e:
            covert_summary = {"error": str(e) or "error"}

        sess.messages.append({"role": "assistant", "text": reply})

        alerts: list[dict[str, Any]] = []
        if case_id:
            rec = self._store.get_case(case_id)
            if rec is not None:
                alerts = rec.alerts

        return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": alerts, "covert": covert_summary}

    def _handle_command(self, sess: HostSession, session_id: str, text: str) -> dict[str, Any] | None:
        cmd, *rest = text.strip().split(maxsplit=1)
        cmd = cmd.lower()
        arg = rest[0].strip() if rest else ""

        if cmd in {"/help", "/commands"}:
            reply = (
                "Commands:\n"
                "- /help or /commands\n"
                "- /reset (clear triage state)\n"
                "- /last (show last case id)\n"
                "- /case <id> (summarize a case)\n"
                "- /iocs [id|last] (extract IOCs)\n"
                "- /mitre [id|last] (MITRE techniques)\n"
                "- /timeline [id|last] (case timeline)\n"
                "- /export [id|last] (link to raw JSON)\n"
                "\n"
                "Tip: paste JSON to skip triage questions."
            )
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id}

        if cmd == "/reset":
            sess.triage_pending = False
            sess.triage_bundle = None
            sess.triage_questions = []
            sess.triage_attempts = 0
            reply = "Session triage state cleared."
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id}

        if cmd == "/last":
            if not sess.last_case_id:
                reply = "No cases yet. Send an incident to create one."
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply}
            reply = f"Last case: {sess.last_case_id}\nOpen: /case/{sess.last_case_id}"
            sess.messages.append({"role": "assistant", "text": reply})
            rec = self._store.get_case(sess.last_case_id)
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id, "alerts": (rec.alerts if rec else [])}

        if cmd in {"/export", "/iocs", "/mitre", "/timeline"}:
            target = arg or "last"
            case_id = sess.last_case_id if target == "last" else target
            if not case_id:
                reply = "No last case. Usage: /export <case_id> or /export last"
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply}

            rec = self._store.get_case(case_id)
            if rec is None:
                reply = f"Case not found: {case_id}"
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply}

            if cmd == "/export":
                reply = f"Raw JSON: /cases/{case_id}\nFriendly view: /case/{case_id}"
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

            analysis = getattr(rec, "analysis_cache", None)
            if analysis is None:
                # Compute on demand via the API helper, without importing FastAPI.
                from orchestrator.case_analysis import analyze_case

                analysis = analyze_case(rec)

            if cmd == "/iocs":
                iocs = (((analysis.get("findings") or {}).get("evidence") or {}).get("iocs") or {}) if isinstance(analysis, dict) else {}
                items: list[str] = []
                for k, v in iocs.items():
                    if not v:
                        continue
                    if isinstance(v, list):
                        for it in v[:30]:
                            items.append(f"{k}: {it}")
                    else:
                        items.append(f"{k}: {v}")
                reply = "IOCs:\n" + ("\n".join(f"- {x}" for x in items) if items else "- none found")
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

            if cmd == "/mitre":
                mitre = (((analysis.get("findings") or {}).get("evidence") or {}).get("mitre_techniques") or []) if isinstance(analysis, dict) else []
                reply = "MITRE techniques:\n" + ("\n".join(f"- {x}" for x in mitre) if mitre else "- none mapped")
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

            if cmd == "/timeline":
                timeline = analysis.get("timeline") if isinstance(analysis, dict) else None
                if not timeline:
                    reply = "Timeline:\n- n/a (no timestamps available in this case)"
                else:
                    reply = "Timeline:\n" + "\n".join(f"- {t}" for t in timeline[:40])
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply, "case_id": case_id, "alerts": rec.alerts}

        return None

    def _parse_incident_bundle(self, text: str) -> dict[str, Any]:
        text = (text or "").strip()

        # If the user pasted a JSON bundle, use it directly.
        if text.startswith("{") and text.endswith("}"):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        # If the user pasted an LLM-style prompt, extract the incident portion.
        # Supported format:
        #   Title: ...
        #   Incident: ...
        # Anything before "Incident:" is treated as instructions and ignored for telemetry.
        lowered = text.lower()
        incident_text = text
        title: str | None = None

        if "incident:" in lowered:
            i = lowered.index("incident:")
            incident_text = text[i + len("incident:") :].strip()

        if "title:" in lowered:
            i = lowered.index("title:")
            rest = text[i + len("title:") :]
            title = rest.splitlines()[0].strip() or None

        # If the extracted incident is JSON, use it.
        if incident_text.startswith("{") and incident_text.endswith("}"):
            try:
                obj = json.loads(incident_text)
                if isinstance(obj, dict):
                    if title and "title" not in obj:
                        obj = {**obj, "title": title}
                    return obj
            except json.JSONDecodeError:
                pass

        return {"title": title or "User-described incident", "events": [{"msg": incident_text}], "artifacts": {}}

    def _looks_like_structured_bundle(self, bundle: dict[str, Any]) -> bool:
        if not isinstance(bundle, dict):
            return False
        if "demo" in bundle:
            return True
        events = bundle.get("events")
        artifacts = bundle.get("artifacts")
        if isinstance(events, list) and len(events) >= 2:
            return True
        if isinstance(artifacts, dict) and any(artifacts.get(k) for k in ("hosts", "users", "iocs", "processes", "ips", "urls")):
            return True
        return False

    def _triage_questions(self, text: str) -> list[str]:
        extracted = self._extract_entities(text)
        questions: list[str] = []

        if not extracted.get("hosts"):
            questions.append("Which host(s) / asset(s) are affected? (e.g., pc-hr-01, dc-01)")
        if not extracted.get("timeframe"):
            questions.append("What timeframe did this happen? (e.g., 'last 10 minutes', '2026-01-22 20:10–20:30')")
        if not (extracted.get("ips") or extracted.get("domains") or extracted.get("urls") or extracted.get("hashes") or extracted.get("processes")):
            questions.append("Any indicators? (IP/domain/URL/hash/process/command line)")

        # Keep it short and “SOC-like”.
        return questions[:3]

    def _format_questions(self, questions: list[str]) -> str:
        lines = [
            "I can triage this faster with 2–3 details. Reply with any you know:",
        ]
        for q in questions:
            lines.append(f"- {q}")
        lines.append("Or paste a JSON incident bundle to skip questions.")
        return "\n".join(lines)

    def _merge_followup(self, base_bundle: dict[str, Any], followup_text: str) -> dict[str, Any]:
        bundle = dict(base_bundle or {})
        events = bundle.get("events") if isinstance(bundle.get("events"), list) else []
        events = list(events)
        events.append({"msg": followup_text})
        bundle["events"] = events

        artifacts = bundle.get("artifacts") if isinstance(bundle.get("artifacts"), dict) else {}
        artifacts = dict(artifacts)
        extracted = self._extract_entities(followup_text)

        for k, v in extracted.items():
            if not v:
                continue
            if isinstance(v, list):
                prev = artifacts.get(k)
                prev_list = list(prev) if isinstance(prev, list) else []
                for it in v:
                    if it not in prev_list:
                        prev_list.append(it)
                artifacts[k] = prev_list
            else:
                if not artifacts.get(k):
                    artifacts[k] = v

        bundle["artifacts"] = artifacts
        return bundle

    def _extract_entities(self, text: str) -> dict[str, Any]:
        s = (text or "").strip()

        ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", s)
        urls = re.findall(r"\bhttps?://[^\s)]+", s, flags=re.IGNORECASE)
        domains = re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", s, flags=re.IGNORECASE)
        processes = re.findall(r"\b[a-z0-9_.-]+\.exe\b", s, flags=re.IGNORECASE)

        sha256 = re.findall(r"\b[a-f0-9]{64}\b", s, flags=re.IGNORECASE)
        sha1 = re.findall(r"\b[a-f0-9]{40}\b", s, flags=re.IGNORECASE)
        md5 = re.findall(r"\b[a-f0-9]{32}\b", s, flags=re.IGNORECASE)
        hashes = list(dict.fromkeys(sha256 + sha1 + md5))

        # Hostname-ish tokens (kept conservative).
        hosts = re.findall(r"\b(?:[a-z]{2,10}-[a-z0-9]{1,10}-?\d{0,3}|[a-z]{2,10}\d{0,3})\b", s, flags=re.IGNORECASE)
        hosts = [h for h in hosts if len(h) <= 20]

        users = re.findall(r"\b[a-z][a-z0-9._-]{1,30}\b", s, flags=re.IGNORECASE)
        users = [u for u in users if "." in u or "_" in u]

        timeframe = None
        m = re.search(r"\b(last\s+\d+\s+(?:min|mins|minute|minutes|hour|hours|day|days))\b", s, flags=re.IGNORECASE)
        if m:
            timeframe = m.group(1)
        else:
            m2 = re.search(r"\b(20\d{2}-\d{2}-\d{2}(?:[ t]\d{2}:\d{2}(?::\d{2})?)?)\b", s)
            if m2:
                timeframe = m2.group(1)

        return {
            "ips": list(dict.fromkeys(ips)),
            "urls": list(dict.fromkeys(urls)),
            "domains": list(dict.fromkeys(domains)),
            "processes": list(dict.fromkeys(processes)),
            "hashes": hashes,
            "hosts": list(dict.fromkeys(hosts)),
            "users": list(dict.fromkeys(users)),
            "timeframe": timeframe,
        }

    def _format_reply(self, result: dict[str, Any]) -> str:
        if "error" in result and result["error"]:
            err = result["error"]
            return f"Error: {err.get('code', 'UNKNOWN')}: {err.get('message', 'request failed')}"

        report = result.get("report") or {}
        outputs = report.get("outputs") or {}
        ti = outputs.get("threat_intel", {}) or {}
        anomaly = outputs.get("anomaly", {}) or {}
        compliance = outputs.get("compliance", {}) or {}
        plan = outputs.get("ir_planner", {}) or {}

        lines: list[str] = []
        if result.get("case_id"):
            lines.append(f"Case created: {result['case_id']}")

        lines.append(f"Severity: {report.get('severity', 'low')}")
        if report.get("executive_summary"):
            lines.append(str(report["executive_summary"]))

        lines.append(f"Threat intel matches: {ti.get('match_count', 0)}")
        lines.append(f"Anomaly score: {float(anomaly.get('anomaly_score', 0.0)):.2f}")

        actions = plan.get("proposed_actions", [])
        allowed = compliance.get("allowed", [])
        blocked = compliance.get("blocked", [])
        if actions:
            lines.append(f"Proposed actions: {len(actions)} (allowed={len(allowed)}, blocked={len(blocked)})")
            if blocked:
                lines.append("Note: containment is blocked by policy until approved.")

        recs = report.get("recommendations") or []
        if recs:
            lines.append("Recommendations:")
            for r in recs[:5]:
                lines.append(f"- {r}")

        lines.append("Tip: open the case link to see full A2A message trace + timing alerts.")
        return "\n".join(lines)

    def _summarize_case(self, rec) -> str:
        lines = [f"Case: {rec.case_id}", f"Messages: {len(rec.messages)}", f"Alerts: {len(rec.alerts)}"]
        if rec.final_report:
            lines.append("Final report: available")
        else:
            lines.append("Final report: not set")
        return "\n".join(lines)
