"""Testes do resolvedor de provider (backend/ai/providers/__init__.py).

Garante que cada nome aceito em AI_PROVIDER resolve pra classe certa
(inclusive os aliases OpenAI-compatible: openai/lmstudio/openrouter todos
usam o mesmo client, só mudando base_url/model/api_key) e que um nome
desconhecido falha alto em vez de silenciosamente cair num provider errado.
"""

import pytest

from ai.providers import build_provider, build_research_provider
from ai.providers.anthropic import AnthropicProvider
from ai.providers.nvidia import NvidiaProvider
from ai.providers.ollama import OllamaProvider
from ai.providers.openai_compat import OpenAICompatProvider
from config.settings import settings


@pytest.mark.parametrize(
    "name, expected_cls",
    [
        ("ollama", OllamaProvider),
        ("nvidia", NvidiaProvider),
        ("openai", OpenAICompatProvider),
        ("lmstudio", OpenAICompatProvider),
        ("openrouter", OpenAICompatProvider),
        ("anthropic", AnthropicProvider),
        ("OPENROUTER", OpenAICompatProvider),  # case-insensitive
    ],
)
def test_build_provider_resolves_known_names(name, expected_cls):
    provider = build_provider(name)
    assert isinstance(provider, expected_cls)


def test_build_provider_rejects_unknown_name():
    with pytest.raises(ValueError, match="Unknown AI provider"):
        build_provider("nao-existe")


# --- build_research_provider: 2° modelo opcional (Planner/Validator) ---

def test_research_provider_falls_back_to_main_when_unset(monkeypatch):
    monkeypatch.setattr(settings, "research_provider", "")
    monkeypatch.setattr(settings, "ai_provider", "ollama")
    provider = build_research_provider()
    assert isinstance(provider, OllamaProvider)
    assert provider.config.model == settings.ai_model


def test_research_provider_uses_dedicated_config_when_set(monkeypatch):
    monkeypatch.setattr(settings, "research_provider", "anthropic")
    monkeypatch.setattr(settings, "research_model", "claude-sonnet-4-5-20250929")
    monkeypatch.setattr(settings, "research_api_key", "dummy-test-key-not-real")
    provider = build_research_provider()
    assert isinstance(provider, AnthropicProvider)
    assert provider.config.model == "claude-sonnet-4-5-20250929"
    assert provider.config.api_key == "dummy-test-key-not-real"


def test_research_provider_rejects_unknown_name(monkeypatch):
    monkeypatch.setattr(settings, "research_provider", "nao-existe")
    with pytest.raises(ValueError, match="Unknown research provider"):
        build_research_provider()
