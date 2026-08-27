"""Testes do resolvedor de provider (backend/ai/providers/__init__.py).

Garante que cada nome aceito em AI_PROVIDER resolve pra classe certa
(inclusive os aliases OpenAI-compatible: openai/lmstudio/openrouter todos
usam o mesmo client, só mudando base_url/model/api_key) e que um nome
desconhecido falha alto em vez de silenciosamente cair num provider errado.
"""

import pytest

from ai.providers import (
    available_providers,
    build_provider,
    build_research_provider,
    get_research_provider_override,
    set_research_provider_override,
)
from ai.providers.anthropic import AnthropicProvider
from ai.providers.nvidia import NvidiaProvider
from ai.providers.ollama import OllamaProvider
from ai.providers.openai_compat import OpenAICompatProvider
from config.settings import settings
from database import db


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


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


# --- override salvo via UI (GET/POST /api/provider/research) ---

def test_available_providers_lists_all_registered_names():
    names = available_providers()
    assert {"ollama", "openai", "anthropic", "openrouter", "nvidia", "lmstudio"} <= set(names)
    assert names == sorted(names)


def test_no_override_by_default():
    assert get_research_provider_override() is None


def test_set_override_persists_and_round_trips():
    set_research_provider_override("openrouter", "https://openrouter.ai/api/v1",
                                    "anthropic/claude-sonnet-4.5", "sk-or-dummy-test-key")
    override = get_research_provider_override()
    assert override == {
        "provider": "openrouter",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "anthropic/claude-sonnet-4.5",
        "api_key": "sk-or-dummy-test-key",
    }


def test_set_override_empty_provider_clears_it():
    set_research_provider_override("openrouter", api_key="sk-or-dummy")
    set_research_provider_override("")
    assert get_research_provider_override() is None


def test_set_override_omitted_api_key_keeps_existing():
    set_research_provider_override("openrouter", "https://openrouter.ai/api/v1",
                                    "model-a", "sk-or-original-key")
    set_research_provider_override("openrouter", "https://openrouter.ai/api/v1", "model-b")
    override = get_research_provider_override()
    assert override["model"] == "model-b"
    assert override["api_key"] == "sk-or-original-key"


def test_build_research_provider_uses_override_when_set(monkeypatch):
    monkeypatch.setattr(settings, "research_provider", "")  # .env sem nada configurado
    set_research_provider_override("openrouter", "https://openrouter.ai/api/v1",
                                    "anthropic/claude-sonnet-4.5", "sk-or-dummy-test-key")
    provider = build_research_provider()
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.config.model == "anthropic/claude-sonnet-4.5"
    assert provider.config.base_url == "https://openrouter.ai/api/v1"
    assert provider.config.api_key == "sk-or-dummy-test-key"


def test_build_research_provider_override_takes_priority_over_env(monkeypatch):
    monkeypatch.setattr(settings, "research_provider", "anthropic")
    monkeypatch.setattr(settings, "research_model", "claude-do-env")
    set_research_provider_override("openrouter", model="modelo-do-override")
    provider = build_research_provider()
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.config.model == "modelo-do-override"


def test_build_research_provider_rejects_unknown_override_name():
    set_research_provider_override("nao-existe")
    with pytest.raises(ValueError, match="Unknown research provider"):
        build_research_provider()
