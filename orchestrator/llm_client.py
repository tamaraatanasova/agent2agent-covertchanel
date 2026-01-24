from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        provider = os.getenv("LLM_PROVIDER", "none").strip().lower()
        model = os.getenv("LLM_MODEL", "").strip()
        if not model:
            model = "llama3.1:8b" if provider == "ollama" else "gpt-4o-mini"
        base_url = os.getenv("LLM_BASE_URL", "").strip() or None
        api_key = os.getenv("OPENAI_API_KEY", "").strip() or None
        return cls(provider=provider, model=model, base_url=base_url, api_key=api_key)

    def enabled(self) -> bool:
        if self.provider in ("", "none", "off", "disabled"):
            return False
        if self.provider == "openai":
            return bool(self.api_key)
        return True


class LLMError(RuntimeError):
    pass


def _post_json(url: str, payload: dict[str, Any], *, headers: dict[str, str] | None = None, timeout_s: float = 25.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        raise LLMError(str(e)) from e


def chat_completion(messages: list[dict[str, str]], *, temperature: float = 0.2, max_tokens: int = 900) -> str:
    cfg = LLMConfig.from_env()
    if not cfg.enabled():
        raise LLMError("LLM is disabled (set LLM_PROVIDER=ollama or LLM_PROVIDER=openai + OPENAI_API_KEY).")

    if cfg.provider == "ollama":
        base = cfg.base_url or "http://127.0.0.1:11434"
        data = _post_json(
            base.rstrip("/") + "/api/chat",
            {
                "model": cfg.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            },
        )
        msg = ((data.get("message") or {}).get("content")) if isinstance(data, dict) else None
        if not isinstance(msg, str) or not msg.strip():
            raise LLMError("ollama: empty response")
        return msg.strip()

    if cfg.provider == "openai":
        base = cfg.base_url or "https://api.openai.com/v1"
        data = _post_json(
            base.rstrip("/") + "/chat/completions",
            {
                "model": cfg.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            headers={"authorization": f"Bearer {cfg.api_key}"},
        )
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            raise LLMError("openai: missing choices")
        content = (((choices[0] or {}).get("message") or {}).get("content"))
        if not isinstance(content, str) or not content.strip():
            raise LLMError("openai: empty content")
        return content.strip()

    raise LLMError(f"unsupported LLM_PROVIDER: {cfg.provider}")

