from __future__ import annotations

import time
from typing import Any
from uuid import uuid4
from threading import Lock
import json
import copy
import hashlib
import secrets
from dataclasses import dataclass
from time import time as wall_time

from orchestrator.config import AGENT_URLS, USE_REMOTE_AGENTS
from orchestrator.local_dispatch import dispatch_task as local_dispatch_task
from orchestrator.remote_a2a import send_envelope, RemoteAgentError
from orchestrator.output_policy import OutputPolicy, enforce_malicious_output
from orchestrator.covert_metrics import decode_bits_by_latency
from orchestrator.mitigation import MitigationConfig, TimingMitigator
from orchestrator.rate_limit import RateLimitConfig, TokenBucket
from orchestrator.store import InMemoryStore
from shared.a2a_keys import KeyRegistry, load_private_key_b64, security_enabled
from shared.a2a_types import A2AEnvelope, A2ATask, MessageType, A2ASecurity
from shared.latency_detector import LatencyDetector
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


class RateLimitError(RuntimeError):
    def __init__(self, edge: str) -> None:
        super().__init__(f"rate limited: {edge}")
        self.edge = edge


@dataclass(frozen=True)
class CircuitBreakerState:
    failures: int = 0
    open_until_s: float | None = None


class Orchestrator:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store
        self._detector = LatencyDetector()
        self._mitigator = TimingMitigator(MitigationConfig())
        self._rl_cfg = RateLimitConfig()
        self._rate_limits: dict[str, TokenBucket] = {}
        self._rate_limits_lock = Lock()
        self._output_policy = OutputPolicy()
        self._require_sig = bool(security_enabled() and USE_REMOTE_AGENTS)
        self._key_registry: KeyRegistry | None = None
        self._orchestrator_priv_b64: str | None = None
        if self._require_sig:
            self._key_registry = KeyRegistry.load()
            self._orchestrator_priv_b64 = load_private_key_b64("orchestrator")

        self._cb: dict[str, CircuitBreakerState] = {}
        self._cb_lock = Lock()

    def set_output_policy(self, policy: OutputPolicy) -> None:
        self._output_policy = policy

    def _rate_limit_key(self, from_agent: str, to_agent: str) -> str:
        return f"{from_agent}->{to_agent}"

    def _check_rate_limit(self, *, case_id: str, from_agent: str, to_agent: str) -> None:
        key = self._rate_limit_key(from_agent, to_agent)
        with self._rate_limits_lock:
            bucket = self._rate_limits.get(key)
            if bucket is None:
                bucket = TokenBucket(self._rl_cfg)
                self._rate_limits[key] = bucket
            allowed = bucket.allow()

        if not allowed:
            self._store.append_alert(case_id, {"type": "RATE_LIMIT", "edge": key, "reason": "token_bucket_exhausted"})
            raise RateLimitError(key)

    def _append_degraded_alert(self, case_id: str, *, agent: str, reason: str) -> None:
        self._store.append_alert(case_id, {"type": "DEGRADED_MODE", "agent": agent, "reason": reason})

    @retry(
        retry=retry_if_exception_type(RemoteAgentError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.4, min=0.4, max=2.0),
        reraise=True,
    )
    def _send_remote_with_retry(self, url: str, env: A2AEnvelope) -> dict[str, Any]:
        return send_envelope(url, env)

    def _circuit_is_open(self, agent: str) -> bool:
        with self._cb_lock:
            st = self._cb.get(agent)
            if st is None or st.open_until_s is None:
                return False
            if wall_time() >= st.open_until_s:
                self._cb[agent] = CircuitBreakerState()
                return False
            return True

    def _circuit_on_success(self, agent: str) -> None:
        with self._cb_lock:
            self._cb[agent] = CircuitBreakerState()

    def _circuit_on_failure(self, agent: str) -> None:
        with self._cb_lock:
            st = self._cb.get(agent) or CircuitBreakerState()
            failures = st.failures + 1
            open_until = st.open_until_s
            if failures >= 3:
                open_until = wall_time() + 30.0
            self._cb[agent] = CircuitBreakerState(failures=failures, open_until_s=open_until)

    def _call_agent(
        self,
        *,
        case_id: str,
        from_agent: str,
        to_agent: str,
        task: A2ATask,
        mitigation_mode: str = "on_alert",  # off | on_alert | always
        rate_limit: bool = True,
    ) -> dict[str, Any]:
        if rate_limit:
            try:
                self._check_rate_limit(case_id=case_id, from_agent=from_agent, to_agent=to_agent)
            except RateLimitError as e:
                err_env = A2AEnvelope(
                    case_id=case_id,
                    from_agent="gateway",
                    to_agent=from_agent,
                    type=MessageType.ERROR,
                    error={"code": "RATE_LIMIT", "message": str(e), "edge": e.edge},
                )
                self._store.append_message(err_env)
                return {"error": err_env.error}

        env = A2AEnvelope(
            case_id=case_id,
            from_agent=from_agent,
            to_agent=to_agent,
            type=MessageType.TASK,
            task=task,
        )
        if self._require_sig and self._orchestrator_priv_b64:
            env.security = A2ASecurity.sign_envelope(env, private_key_b64=self._orchestrator_priv_b64)
        env.trace.add_hop(from_agent)
        self._store.append_message(env)

        start = time.perf_counter()
        try:
            if USE_REMOTE_AGENTS:
                url = AGENT_URLS.get(to_agent)
                if not url:
                    raise RuntimeError(f"agent not configured: {to_agent}")
                if self._circuit_is_open(to_agent):
                    self._append_degraded_alert(case_id, agent=to_agent, reason="circuit_open")
                    raise RuntimeError(f"circuit_open: {to_agent}")

                upstream = self._send_remote_with_retry(url, env)
                upstream_env = A2AEnvelope.model_validate(upstream)
                if self._require_sig:
                    if upstream_env.security is None:
                        raise RuntimeError("missing agent signature")
                    pub = self._key_registry.public_key_for(upstream_env.from_agent) if self._key_registry else None
                    if not pub:
                        raise RuntimeError(f"unknown agent public key: {upstream_env.from_agent}")
                    upstream_env.security.verify_envelope(upstream_env, public_key_b64=pub)
                if upstream_env.type == MessageType.ERROR:
                    raise RuntimeError(upstream_env.error.get("message", "agent error"))
                output = (upstream_env.result or {}).get("output", {})
                self._circuit_on_success(to_agent)
            else:
                output = local_dispatch_task(to_agent, task)

            if to_agent == "malicious":
                output = enforce_malicious_output(task.name, dict(output), policy=self._output_policy)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
        except Exception as e:
            if USE_REMOTE_AGENTS:
                self._circuit_on_failure(to_agent)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            err_env = A2AEnvelope(
                case_id=case_id,
                parent_id=env.message_id,
                from_agent=to_agent,
                to_agent=from_agent,
                type=MessageType.ERROR,
                error={"code": "AGENT_ERROR", "message": str(e)},
            )
            err_env.trace = env.trace
            err_env.trace.add_hop(to_agent, latency_ms=elapsed_ms)
            self._store.append_message(err_env)
            return {"error": err_env.error, "timing": {"elapsed_ms": elapsed_ms}}

        alert = self._detector.observe(f"{from_agent}->{to_agent}", elapsed_ms)
        mitigation_extra_ms = 0.0
        apply_mitigation = mitigation_mode == "always" or (mitigation_mode == "on_alert" and alert is not None)
        if alert is not None:
            self._store.append_alert(case_id, {"type": "TIMING", **alert.__dict__, "latency_ms": elapsed_ms})
        if apply_mitigation:
            mitigation_extra_ms = self._mitigator.apply(elapsed_ms)

        result_env = A2AEnvelope(
            case_id=case_id,
            parent_id=env.message_id,
            from_agent=to_agent,
            to_agent=from_agent,
            type=MessageType.RESULT,
            result={
                "output": output,
                "timing": {
                    "elapsed_ms": elapsed_ms,
                    "mitigation_extra_ms": mitigation_extra_ms,
                    "total_ms": elapsed_ms + mitigation_extra_ms,
                    "mitigation_mode": mitigation_mode,
                    "alert": alert.__dict__ if alert else None,
                },
            },
        )
        result_env.trace = env.trace
        result_env.trace.add_hop(to_agent, latency_ms=elapsed_ms)
        self._store.append_message(result_env)
        # Include a compact observer-visible size signal (helps size-channel analysis in demos).
        try:
            size_bytes = len(json.dumps(output, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        except Exception:
            size_bytes = None
        out = result_env.result or {}
        if "timing" in out and isinstance(out["timing"], dict):
            out["timing"]["output_size_bytes"] = size_bytes
        return out

    def run_case(self, incident_bundle: dict[str, Any]) -> dict[str, Any]:
        case_id = str(uuid4())
        self._store.create_case(case_id, incident_bundle)

        telemetry_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="telemetry",
            task=A2ATask(name="normalize_enrich", parameters={"bundle": incident_bundle}),
        )
        if "error" in telemetry_r:
            self._store.set_final_report(case_id, {"error": telemetry_r["error"]})
            return {"case_id": case_id, "error": telemetry_r["error"]}
        telemetry = telemetry_r["output"]
        self._store.set_agent_output(case_id, "telemetry", telemetry)

        ti_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="threat_intel",
            task=A2ATask(name="map_patterns", parameters={"telemetry": telemetry}),
        )
        ti = ti_r.get("output") if isinstance(ti_r, dict) else None
        if not isinstance(ti, dict):
            self._append_degraded_alert(case_id, agent="threat_intel", reason=str((ti_r.get("error") or {}).get("code", "error")))
            ti = {}
        self._store.set_agent_output(case_id, "threat_intel", ti)

        anomaly_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="anomaly",
            task=A2ATask(name="score", parameters={"telemetry": telemetry}),
        )
        anomaly = anomaly_r.get("output") if isinstance(anomaly_r, dict) else None
        if not isinstance(anomaly, dict):
            self._append_degraded_alert(case_id, agent="anomaly", reason=str((anomaly_r.get("error") or {}).get("code", "error")))
            anomaly = {}
        self._store.set_agent_output(case_id, "anomaly", anomaly)

        plan_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="ir_planner",
            task=A2ATask(name="plan", parameters={"threat_intel": ti, "anomaly": anomaly}),
        )
        plan = plan_r.get("output") if isinstance(plan_r, dict) else None
        if not isinstance(plan, dict):
            self._append_degraded_alert(case_id, agent="ir_planner", reason=str((plan_r.get("error") or {}).get("code", "error")))
            plan = {}
        self._store.set_agent_output(case_id, "ir_planner", plan)

        compliance_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="compliance",
            task=A2ATask(name="policy_check", parameters={"plan": plan}),
        )
        compliance = compliance_r.get("output") if isinstance(compliance_r, dict) else None
        if not isinstance(compliance, dict):
            self._append_degraded_alert(case_id, agent="compliance", reason=str((compliance_r.get("error") or {}).get("code", "error")))
            compliance = {}
        self._store.set_agent_output(case_id, "compliance", compliance)

        # Snapshot outputs to avoid circular references:
        # storing `report.outputs` pointing at the live `agent_outputs` dict would create a self-reference.
        outputs_snapshot = copy.deepcopy(self._store.get_case(case_id).agent_outputs)
        report_r = self._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent="report",
            task=A2ATask(name="report", parameters={"bundle": incident_bundle, "outputs": outputs_snapshot}),
        )
        report = report_r.get("output") if isinstance(report_r, dict) else None
        if not isinstance(report, dict):
            self._append_degraded_alert(case_id, agent="report", reason=str((report_r.get("error") or {}).get("code", "error")))
            report = self._fallback_report(case_id, incident_bundle, outputs_snapshot)
        self._store.set_agent_output(case_id, "report", report)
        self._store.set_final_report(case_id, report)

        return {"case_id": case_id, "report": report}

    def _fallback_report(self, case_id: str, bundle: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
        telemetry = outputs.get("telemetry") or {}
        ti = outputs.get("threat_intel") or {}
        anomaly = outputs.get("anomaly") or {}
        plan = outputs.get("ir_planner") or {}
        compliance = outputs.get("compliance") or {}

        sev = "low"
        for s in (ti.get("severity"), anomaly.get("severity")):
            if s in ("critical", "high"):
                sev = "high"
            elif s == "medium" and sev == "low":
                sev = "medium"

        summary = (
            f"Severity: {sev}\n"
            f"Degraded mode: one or more agents failed; report is partial.\n"
            f"Event count: {telemetry.get('event_count', 0)}\n"
            f"MITRE: {', '.join(ti.get('mitre_techniques', []) or []) or 'n/a'}\n"
        )
        recs: list[str] = []
        if plan.get("proposed_actions"):
            recs.append("Follow triage → containment (if approved) → eradication/recovery playbook.")
        if compliance.get("blocked"):
            recs.append("Request approval for blocked containment actions.")
        return {
            "executive_summary": summary,
            "severity": sev,
            "timeline": [],
            "metrics": {
                "event_count": telemetry.get("event_count", 0),
                "unique_hosts": telemetry.get("summary", {}).get("unique_hosts", 0),
                "intel_matches": ti.get("match_count", 0),
            },
            "recommendations": recs[:8],
            "outputs": outputs,
        }

    def configure_mitigation(self, cfg: MitigationConfig) -> None:
        self._mitigator = TimingMitigator(cfg)

    def demo_covert(
        self,
        *,
        bits: str | None = None,
        bits_len: int = 64,
        server_generate_bits: bool = True,
        channel: str = "timing",  # timing | storage | size
        compare: bool = True,
        topology: str = "single",  # single | mesh
        message: str | None = None,
        single_mode: str = "always",  # off | on_alert | always
        mitigation: MitigationConfig | None = None,
    ) -> dict[str, Any]:
        if topology == "mesh" and channel != "timing":
            raise ValueError("mesh topology is supported for timing channel only")
        if single_mode not in ("off", "on_alert", "always"):
            raise ValueError("invalid single_mode (expected off|on_alert|always)")

        def bytes_to_bits(data: bytes) -> str:
            return "".join(f"{b:08b}" for b in data)

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

        msg: str | None = message.strip() if isinstance(message, str) else None
        want_message = bool(msg) or topology == "mesh"

        if want_message:
            nbits = max(8, min(256, int(bits_len)))
            max_bytes = max(1, min(32, nbits // 8))
            if msg:
                msg_bytes = msg.encode("utf-8")
                if len(msg_bytes) > 32:
                    raise ValueError("message too long (max 32 UTF-8 bytes)")
            else:
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                msg = "".join(secrets.choice(alphabet) for _ in range(max_bytes))
                msg_bytes = msg.encode("utf-8")
            bits = bytes_to_bits(msg_bytes)
        else:
            if server_generate_bits or not bits:
                n = max(8, min(256, int(bits_len)))
                bits = "".join("1" if (b & 1) else "0" for b in secrets.token_bytes(n))
                bits = bits[:n]

        bits_hash = hashlib.sha256(bits.encode("utf-8")).hexdigest()[:16]
        case_id = str(uuid4())
        # Store the bits in the case record for analysis, but the API will redact them for display.
        self._store.create_case(
            case_id,
            {
                "demo": "covert",
                "channel": channel,
                "topology": topology,
                "bits": bits,
                "bits_len": len(bits),
                "bits_hash": bits_hash,
                "message": msg,
            },
        )

        if mitigation is not None:
            self.configure_mitigation(mitigation)

        # Keep the covert-channel demo scoped to SOC agents (avoid pulling in unrelated assistant agents).
        covert_demo_agents = ("telemetry", "threat_intel", "anomaly", "ir_planner", "compliance", "report", "malicious")
        agents = [a for a in covert_demo_agents if a in AGENT_URLS]
        mesh_edges = [(a, b) for a in agents for b in agents if a != b]
        use_full_mesh = topology == "mesh" and bool(mesh_edges) and not self._require_sig

        def route_bit(i: int) -> tuple[str, str]:
            if topology != "mesh":
                return ("orchestrator", "malicious")
            if use_full_mesh:
                return mesh_edges[i % len(mesh_edges)]
            if not agents:
                return ("orchestrator", "malicious")
            return ("orchestrator", agents[i % len(agents)])

        def run_once(mode: str, *, task_name: str, size_defense: bool) -> dict[str, Any]:
            per_bit: list[dict[str, Any]] = []
            lat_total: list[float | None] = []
            lat_elapsed: list[float | None] = []
            sizes: list[float | None] = []
            for idx, bit in enumerate(bits):
                if channel == "size":
                    self.set_output_policy(OutputPolicy(normalize_note_len=96 if size_defense else None))
                else:
                    self.set_output_policy(OutputPolicy())

                from_a, to_a = route_bit(idx)
                r = self._call_agent(
                    case_id=case_id,
                    from_agent=from_a,
                    to_agent=to_a,
                    task=A2ATask(name=task_name, parameters={"i": idx, "bit": bit, "dummy": {"n": idx}}),
                    mitigation_mode=mode,
                    rate_limit=False,
                )
                timing = r.get("timing") or {}
                per_bit.append({"i": idx, "from_agent": from_a, "to_agent": to_a, **timing, "output": r.get("output"), "error": r.get("error")})
                lat_total.append(float(timing["total_ms"])) if timing.get("total_ms") is not None else lat_total.append(None)
                lat_elapsed.append(float(timing["elapsed_ms"])) if timing.get("elapsed_ms") is not None else lat_elapsed.append(None)
                sizes.append(float(timing["output_size_bytes"])) if timing.get("output_size_bytes") is not None else sizes.append(None)

            decoded_total, metrics_total = decode_bits_by_latency(bits, lat_total)
            decoded_elapsed, metrics_elapsed = decode_bits_by_latency(bits, lat_elapsed)
            decoded_size, metrics_size = decode_bits_by_latency(bits, sizes)
            out = {
                "mode": mode,
                "per_bit": per_bit,
                "decode": {
                    "observer_total_ms": {
                        "decoded_bits": decoded_total,
                        "metrics": metrics_total.__dict__ if metrics_total else None,
                    },
                    "observer_size_bytes": {
                        "decoded_bits": decoded_size,
                        "metrics": metrics_size.__dict__ if metrics_size else None,
                    },
                    "agent_elapsed_ms": {
                        "decoded_bits": decoded_elapsed,
                        "metrics": metrics_elapsed.__dict__ if metrics_elapsed else None,
                    },
                },
            }
            if msg:
                out["decoded_message"] = {
                    "observer_total_ms": bits_to_text(decoded_total),
                    "observer_size_bytes": bits_to_text(decoded_size),
                    "agent_elapsed_ms": bits_to_text(decoded_elapsed),
                }
            return out

        if channel == "timing":
            task_name = "covert_send_bit"
            if compare:
                baseline = run_once("off", task_name=task_name, size_defense=False)
                defended = run_once("always", task_name=task_name, size_defense=False)
                return {
                    "case_id": case_id,
                    "bits_len": len(bits),
                    "bits_hash": bits_hash,
                    "channel": channel,
                    "topology": topology,
                    "agents": agents,
                    "message": msg,
                    "baseline": baseline,
                    "defended": defended,
                }
            single = run_once(single_mode, task_name=task_name, size_defense=False)
            return {
                "case_id": case_id,
                "bits_len": len(bits),
                "bits_hash": bits_hash,
                "channel": channel,
                "topology": topology,
                "agents": agents,
                "message": msg,
                **single,
            }

        if channel == "storage":
            # Storage channel attempt should be blocked by output enforcement.
            single = run_once("off", task_name="covert_send_storage_bit", size_defense=False)
            blocked = sum(1 for r in single["per_bit"] if r.get("error"))
            return {
                "case_id": case_id,
                "bits_len": len(bits),
                "bits_hash": bits_hash,
                "channel": channel,
                "topology": topology,
                "agents": agents,
                "message": msg,
                "blocked": blocked,
                **single,
            }

        if channel == "size":
            task_name = "covert_send_size_bit"
            if compare:
                baseline = run_once("off", task_name=task_name, size_defense=False)
                defended = run_once("off", task_name=task_name, size_defense=True)
                return {
                    "case_id": case_id,
                    "bits_len": len(bits),
                    "bits_hash": bits_hash,
                    "channel": channel,
                    "topology": topology,
                    "agents": agents,
                    "message": msg,
                    "baseline": baseline,
                    "defended": defended,
                }
            single = run_once("off", task_name=task_name, size_defense=True)
            return {
                "case_id": case_id,
                "bits_len": len(bits),
                "bits_hash": bits_hash,
                "channel": channel,
                "topology": topology,
                "agents": agents,
                "message": msg,
                **single,
            }

        raise ValueError("unknown channel")
