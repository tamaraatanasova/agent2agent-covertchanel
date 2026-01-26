from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_ROOT = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> None:
    """
    Minimal .env loader (no external dependency).
    - Parses KEY=VALUE lines
    - Ignores blank lines and # comments
    - Does not override existing environment variables
    """

    if not path.exists() or not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ[key] = value


_load_env_file(_ROOT / ".env")

from orchestrator.api import router as orchestrator_router  # noqa: E402

app = FastAPI(title="AI-SOC (A2A Gateway + Orchestrator)")
app.include_router(orchestrator_router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request, exc: Exception) -> JSONResponse:
    # Ensure the frontend always gets JSON (prevents res.json() parse errors).
    return JSONResponse(status_code=500, content={"error": {"code": "INTERNAL", "message": str(exc) or "error"}})

_STATIC_DIR = _ROOT / "web" / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def ui_index() -> FileResponse:
    return FileResponse(_ROOT / "web" / "index.html")


@app.get("/case/{case_id}", include_in_schema=False)
def ui_case(case_id: str) -> FileResponse:
    # Client-side app fetches the JSON from /cases/{case_id}.
    return FileResponse(_ROOT / "web" / "case.html")
