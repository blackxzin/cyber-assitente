"""Testes dos providers de IA (backend/ai/providers/*) — garantem que o
kwarg genérico 'json_mode' vira o parâmetro nativo certo em cada API
(Ollama usa 'format', OpenAI-compatible usa 'response_format'), e que
'max_tokens' é traduzido pro formato do Ollama ('options.num_predict').
Sem rede real: usa httpx.MockTransport."""

import json

import httpx

from ai.providers.base import LLMConfig
from ai.providers.ollama import OllamaProvider
from ai.providers.openai_compat import OpenAICompatProvider


def _capture_transport(captured: dict, body: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content)
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


async def test_ollama_json_mode_maps_to_format_field():
    captured: dict = {}
    provider = OllamaProvider(LLMConfig(model="dolphin-llama3", base_url="http://x"))
    provider._client = httpx.AsyncClient(
        base_url="http://x",
        transport=_capture_transport(captured, {"message": {"content": "{}"}, "done": True}),
    )
    await provider.complete([{"role": "user", "content": "hi"}], json_mode=True)
    assert captured["json"]["format"] == "json"


async def test_ollama_max_tokens_maps_to_num_predict():
    captured: dict = {}
    provider = OllamaProvider(LLMConfig(model="dolphin-llama3", base_url="http://x"))
    provider._client = httpx.AsyncClient(
        base_url="http://x",
        transport=_capture_transport(captured, {"message": {"content": "ok"}, "done": True}),
    )
    await provider.complete([{"role": "user", "content": "hi"}], max_tokens=30)
    assert captured["json"]["options"]["num_predict"] == 30
    assert "max_tokens" not in captured["json"]


async def test_openai_compat_json_mode_maps_to_response_format():
    captured: dict = {}
    body = {"choices": [{"delta": {"content": "{}"}}]}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content)
        return httpx.Response(
            200,
            content=b'data: {"choices":[{"delta":{"content":"{}"}}]}\n\ndata: [DONE]\n\n',
            headers={"content-type": "text/event-stream"},
        )

    provider = OpenAICompatProvider(LLMConfig(model="gpt-x", base_url="http://x"))
    provider._client = httpx.AsyncClient(base_url="http://x", transport=httpx.MockTransport(handler))
    await provider.complete([{"role": "user", "content": "hi"}], json_mode=True)
    assert captured["json"]["response_format"] == {"type": "json_object"}
