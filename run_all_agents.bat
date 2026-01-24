@echo off
setlocal

REM Pick a Python interpreter. Prefer repo venvs if present.
set "PY=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if exist "%~dp0venv\Scripts\python.exe" set "PY=%~dp0venv\Scripts\python.exe"

REM Ensure A2A signing keys exist (Zero Trust demo).
if not exist "%~dp0keys\public_keys.json" (
  echo A2A key registry not found. Generating keys...
  "%PY%" "%~dp0scripts\generate_a2a_keys.py"
)

REM Start each agent service in its own terminal window (kept open with cmd /k).
echo Using Python: %PY%

start "telemetry" cmd /k ""%PY%" -m uvicorn agents.telemetry_service:app --host 127.0.0.1 --port 11001 --log-level info"
start "threat_intel" cmd /k ""%PY%" -m uvicorn agents.threat_intel_service:app --host 127.0.0.1 --port 11002 --log-level info"
start "anomaly" cmd /k ""%PY%" -m uvicorn agents.anomaly_service:app --host 127.0.0.1 --port 11003 --log-level info"
start "ir_planner" cmd /k ""%PY%" -m uvicorn agents.ir_planner_service:app --host 127.0.0.1 --port 11004 --log-level info"
start "compliance" cmd /k ""%PY%" -m uvicorn agents.compliance_service:app --host 127.0.0.1 --port 11005 --log-level info"
start "report" cmd /k ""%PY%" -m uvicorn agents.report_service:app --host 127.0.0.1 --port 11006 --log-level info"
start "malicious" cmd /k ""%PY%" -m uvicorn agents.malicious_service:app --host 127.0.0.1 --port 11007 --log-level info"

echo Started agents on ports 11001-11007.
echo Start the gateway with: set A2A_REMOTE_AGENTS=1 ^&^& uvicorn main:app --reload
endlocal
