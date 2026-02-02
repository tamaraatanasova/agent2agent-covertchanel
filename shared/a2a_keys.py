from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def _keys_dir() -> str:
    return os.getenv("A2A_KEYS_DIR", "keys")


def _registry_path() -> str:
    return os.getenv("A2A_PUBLIC_KEY_REGISTRY", os.path.join(_keys_dir(), "public_keys.json"))


def _private_key_path(agent: str) -> str:
    return os.getenv("A2A_PRIVATE_KEY_PATH", os.path.join(_keys_dir(), f"{agent}.ed25519"))

def _auto_generate() -> bool:
    return os.getenv("A2A_AUTO_GENERATE_KEYS", "1").strip().lower() in ("1", "true", "yes", "y", "on")


DEFAULT_AGENTS = [
    "orchestrator",
    "telemetry",
    "threat_intel",
    "anomaly",
    "ir_planner",
    "compliance",
    "report",
    "malicious",
    "calendar",
    "calendar_view",
    "calendar_edit",
]


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _ensure_keys_exist() -> None:
    os.makedirs(_keys_dir(), exist_ok=True)

    reg_path = _registry_path()
    registry: dict[str, str] = {}
    if os.path.exists(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                registry = {str(k): str(v) for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
        except Exception:
            registry = {}

    changed = False
    for agent in DEFAULT_AGENTS:
        priv_path = _private_key_path(agent)
        if os.path.exists(priv_path) and agent in registry:
            continue

        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(_b64e(priv_bytes))
        registry[agent] = _b64e(pub_bytes)
        changed = True

    if changed or not os.path.exists(reg_path):
        with open(reg_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(registry, indent=2, sort_keys=True) + "\n")


@dataclass(frozen=True)
class KeyRegistry:
    public_keys_b64: dict[str, str]

    @classmethod
    def load(cls) -> "KeyRegistry":
        path = _registry_path()
        if not os.path.exists(path):
            if _auto_generate():
                _ensure_keys_exist()
            else:
                raise FileNotFoundError(
                    f"Missing public key registry: {path}. Run `python scripts/generate_a2a_keys.py` to generate keys."
                )
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("public key registry must be a JSON object mapping agent->public_key_b64")
        out: dict[str, str] = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, str) and v.strip():
                out[k] = v.strip()
        if not out:
            raise ValueError("public key registry is empty")
        return cls(public_keys_b64=out)

    def public_key_for(self, agent: str) -> str | None:
        return self.public_keys_b64.get(agent)


def load_private_key_b64(agent: str) -> str:
    path = _private_key_path(agent)
    if not os.path.exists(path):
        if _auto_generate():
            _ensure_keys_exist()
        else:
            raise FileNotFoundError(f"Missing private key for {agent}: {path}. Run `python scripts/generate_a2a_keys.py`.")
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def security_enabled() -> bool:
    return os.getenv("A2A_REQUIRE_SIGNATURES", "1").strip() not in ("0", "false", "False", "no", "NO")


def keys_status() -> dict[str, Any]:
    return {
        "enabled": security_enabled(),
        "keys_dir": _keys_dir(),
        "public_registry": _registry_path(),
    }
