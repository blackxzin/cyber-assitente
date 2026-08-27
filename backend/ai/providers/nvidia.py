"""NVIDIA NIM provider: OpenAI-compatible /chat/completions with vision.

Used for the "see the screen" capability: the overlay captures the desktop
and the backend sends it (base64) with a prompt; the model describes what it
sees. Text-only chat still goes through the local Ollama provider.
"""

import json

import httpx

from .base import LLMConfig, LLMProvider


class NvidiaProvider(LLMProvider):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout,
        )

    async def complete(self, messages: list[dict], **extra) -> str:
        """Non-streaming chat completion (vision text responses are short)."""
        params = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": extra.pop("max_tokens", 300),
        }
        if extra.pop("json_mode", False):
            params["response_format"] = {"type": "json_object"}
        params.update(extra)
        resp = await self._client.post("/chat/completions", json=params)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def stream_chat(self, messages: list[dict], **extra):
        # Streaming vision: collect the full completion, yield it once.
        yield await self.complete(messages, **extra)

    async def aclose(self) -> None:
        await self._client.aclose()
