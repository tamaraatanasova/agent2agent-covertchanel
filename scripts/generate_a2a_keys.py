from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


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


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Ed25519 keys for AI-SOC A2A signing (local demo).")
    ap.add_argument("--dir", default=os.getenv("A2A_KEYS_DIR", "keys"), help="Keys directory (default: keys/)")
    ap.add_argument("--agents", nargs="*", default=DEFAULT_AGENTS, help="Agent names to generate keys for")
    ap.add_argument("--force", action="store_true", help="Overwrite existing keys")
    args = ap.parse_args()

    keys_dir = Path(args.dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    registry_path = keys_dir / "public_keys.json"
    registry: dict[str, str] = {}
    if registry_path.exists() and not args.force:
        try:
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            if not isinstance(registry, dict):
                registry = {}
        except Exception:
            registry = {}

    for agent in args.agents:
        priv_path = keys_dir / f"{agent}.ed25519"
        if priv_path.exists() and not args.force:
            # Keep existing.
            continue

        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        priv_path.write_text(b64e(priv_bytes), encoding="utf-8")
        registry[agent] = b64e(pub_bytes)

    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote public registry: {registry_path}")
    print(f"Wrote private keys to: {keys_dir}")
    print("Set A2A_KEYS_DIR if you want a different location. Keep private keys secret.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
