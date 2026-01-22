from __future__ import annotations

import os


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


USE_REMOTE_AGENTS = env_bool("A2A_REMOTE_AGENTS", False)

# Defaults mirror the “multi-terminal” demo style (one port per agent).
AGENT_URLS: dict[str, str] = {
    "telemetry": os.getenv("A2A_TELEMETRY_URL", "http://127.0.0.1:11001"),
    "threat_intel": os.getenv("A2A_THREAT_INTEL_URL", "http://127.0.0.1:11002"),
    "anomaly": os.getenv("A2A_ANOMALY_URL", "http://127.0.0.1:11003"),
    "ir_planner": os.getenv("A2A_IR_PLANNER_URL", "http://127.0.0.1:11004"),
    "compliance": os.getenv("A2A_COMPLIANCE_URL", "http://127.0.0.1:11005"),
    "report": os.getenv("A2A_REPORT_URL", "http://127.0.0.1:11006"),
    "malicious": os.getenv("A2A_MALICIOUS_URL", "http://127.0.0.1:11007"),
}

