from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from orchestrator.api import router as orchestrator_router

app = FastAPI(title="AI-SOC (A2A Gateway + Orchestrator)")
app.include_router(orchestrator_router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request, exc: Exception) -> JSONResponse:
    # Ensure the frontend always gets JSON (prevents res.json() parse errors).
    return JSONResponse(status_code=500, content={"error": {"code": "INTERNAL", "message": str(exc) or "error"}})

_ROOT = Path(__file__).resolve().parent
_STATIC_DIR = _ROOT / "web" / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def ui_index() -> FileResponse:
    return FileResponse(_ROOT / "web" / "index.html")


@app.get("/case/{case_id}", include_in_schema=False)
def ui_case(case_id: str) -> FileResponse:
    # Client-side app fetches the JSON from /cases/{case_id}.
    return FileResponse(_ROOT / "web" / "case.html")
