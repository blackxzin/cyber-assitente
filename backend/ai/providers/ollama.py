"""Ollama provider: talks to a local ollama server over HTTP.

Uses the /api/chat endpoint (native tool-calling and streaming).
"""

import json
from typing import AsyncIterator

import httpx

from .base import LLMConfig, LLMProvider


class OllamaProvider(LLMProvider):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=config.timeout,
        )

    async def stream_chat(self, messages: list[dict[str, str]], **extra: object) -> AsyncIterator[str]:
        params = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.context_tokens,
            },
        }
        if extra.pop("json_mode", False):
            params["format"] = "json"
        max_tokens = extra.pop("max_tokens", None)
        if max_tokens is not None:
            params["options"]["num_predict"] = max_tokens
        params.update(extra)
        async with self._client.stream("POST", "/api/chat", json=params) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                data = json.loads(line)
                if data.get("error"):
                    raise RuntimeError(data["error"])
                if not data.get("done"):
                    yield data.get("message", {}).get("content", "")

    async def complete(self, messages: list[dict[str, str]], **extra) -> str:
        out: list[str] = []
        async for delta in self.stream_chat(messages, **extra):
            out.append(delta)
        return "".join(out)

    async def aclose(self) -> None:
        await self._client.aclose()
