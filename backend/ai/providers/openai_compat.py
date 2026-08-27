"""OpenAI-compatible provider: works with the OpenAI API itself and with
any server that mirrors its /chat/completions schema (LM Studio, vLLM,
text-generation-webui...). Registered as both "openai" and "lmstudio".
"""

import json
from typing import AsyncIterator

import httpx

from .base import LLMConfig, LLMProvider


class OpenAICompatProvider(LLMProvider):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            headers=headers,
            timeout=config.timeout,
        )

    async def stream_chat(self, messages: list[dict[str, str]], **extra: object) -> AsyncIterator[str]:
        params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "stream": True,
        }
        if extra.pop("json_mode", False):
            params["response_format"] = {"type": "json_object"}
        params.update(extra)
        async with self._client.stream("POST", "/chat/completions", json=params) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                chunk = line[len("data:"):].strip()
                if chunk == "[DONE]":
                    break
                data = json.loads(chunk)
                delta = data["choices"][0].get("delta", {})
                content = delta.get("content")
                if content:
                    yield content

    async def complete(self, messages: list[dict[str, str]], **extra) -> str:
        out: list[str] = []
        async for delta in self.stream_chat(messages, **extra):
            out.append(delta)
        return "".join(out)

    async def aclose(self) -> None:
        await self._client.aclose()
