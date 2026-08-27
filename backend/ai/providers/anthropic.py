"""Anthropic Claude provider via direct Messages API."""

import httpx
from typing import AsyncIterator

from .base import LLMConfig, LLMProvider

_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._client = httpx.AsyncClient(timeout=config.timeout)

    def _build_request(self, messages: list[dict], **extra) -> dict:
        system = ""
        filtered: list[dict] = []
        for m in messages:
            if m.get("role") == "system":
                system = m.get("content", "")
            else:
                filtered.append({"role": m["role"], "content": m.get("content", "")})
        payload: dict = {
            "model": self.config.model,
            "max_tokens": extra.get("max_tokens", 1024),
            "messages": filtered,
        }
        if system:
            payload["system"] = system
        return payload

    def _headers(self) -> dict:
        return {
            "x-api-key": self.config.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    async def stream_chat(self, messages: list[dict], **extra) -> AsyncIterator[str]:
        payload = self._build_request(messages, **extra)
        payload["stream"] = True
        async with self._client.stream(
            "POST", _API_URL, headers=self._headers(), json=payload
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if raw == "[DONE]":
                    break
                import json
                try:
                    data = json.loads(raw)
                except Exception:
                    continue
                delta = (
                    data.get("delta", {}).get("text")
                    or data.get("delta", {}).get("content", "")
                )
                if delta:
                    yield delta

    async def complete(self, messages: list[dict], **extra) -> str:
        payload = self._build_request(messages, **extra)
        resp = await self._client.post(_API_URL, headers=self._headers(), json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        if content and isinstance(content, list):
            return content[0].get("text", "")
        return ""

    async def aclose(self) -> None:
        await self._client.aclose()
