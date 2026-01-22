# AI-SOC (A2A Gateway + Orchestrator)

Minimal, research-style starter for an “Autonomous AI‑SOC” with a safe timing covert‑channel demo + detection/mitigation.

## Quickstart

```bat
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs`.
Open the UI at `http://127.0.0.1:8000/`.

### Example incident bundle

```bat
curl -X POST http://127.0.0.1:8000/cases -H "content-type: application/json" -d "{\"title\":\"Demo\",\"events\":[{\"msg\":\"powershell spawned\"},{\"msg\":\"login failure\"}]}"
```

## Demo flow

- `POST /cases` with an incident bundle (JSON) → orchestrator routes through local “agents” and returns a final report + timeline.
- `GET /cases/{case_id}` shows stored messages + timing alerts.
- `GET /cases` lists known case IDs. `GET /health` is a simple liveness check.
- `POST /demo/covert` runs a safe timing-channel simulation (short/long delays) and shows whether the detector triggers and what mitigation was applied.
- Covert lab options: `/demo/covert` supports `compare=true` (baseline vs defended), and mitigation knobs (`min_response_ms`, `jitter_ms_low`, `jitter_ms_high`).
- UI: `GET /` (chat-style Host Agent) calls `/host/sessions/...` endpoints.
- Agents: `GET /agents` lists agent “cards”, and each agent exposes `POST /agents/{name}/a2a` for A2A TASK→RESULT exchange.
- A2A activation: `POST /agents/{name}/a2a` also supports `HEARTBEAT` envelopes to verify agent connectivity.

## Host Agent tips (UI)

- You can paste plain text (not just JSON). If key details are missing, the Host Agent asks 2–3 triage questions (host/timeframe/indicators).
- Built-in commands:
  - `/help` or `/commands`
  - `/last`, `/case <id>`
  - `/iocs [id|last]`, `/mitre [id|last]`, `/timeline [id|last]`
  - `/export [id|last]`, `/reset`

## Multi-process (agent-to-agent over HTTP)

By default, the gateway runs agents in-process. To run each agent as a separate service (multi-terminal demo style):

1) Start agent services (each in its own terminal):

```bat
uvicorn agents.telemetry_service:app --port 11001
uvicorn agents.threat_intel_service:app --port 11002
uvicorn agents.anomaly_service:app --port 11003
uvicorn agents.ir_planner_service:app --port 11004
uvicorn agents.compliance_service:app --port 11005
uvicorn agents.report_service:app --port 11006
uvicorn agents.malicious_service:app --port 11007
```

2) Start the gateway in remote mode:

```bat
set A2A_REMOTE_AGENTS=1
uvicorn main:app --reload
```

In the UI, the Agents panel shows online/offline dots based on agent connectivity.

### Convenience script

- Command Prompt: `run_all_agents.bat`
- PowerShell: `.\run_all_agents.bat`
