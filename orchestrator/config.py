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
    "calendar": os.getenv("A2A_CALENDAR_URL", "http://127.0.0.1:11008"),
    "calendar_view": os.getenv("A2A_CALENDAR_VIEW_URL", "http://127.0.0.1:11009"),
    "calendar_edit": os.getenv("A2A_CALENDAR_EDIT_URL", "http://127.0.0.1:11010"),
}
