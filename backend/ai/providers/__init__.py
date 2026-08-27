"""Provider registry: resolve the configured provider by name."""

import json

from config.settings import settings
from database import db as database

from .anthropic import AnthropicProvider
from .base import LLMConfig, LLMProvider
from .nvidia import NvidiaProvider
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatProvider

_REGISTRY: dict[str, type[LLMProvider]] = {
    "ollama": OllamaProvider,
    "nvidia": NvidiaProvider,
    "openai": OpenAICompatProvider,
    "lmstudio": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
    # OpenRouter: gateway único (API OpenAI-compatible) pra várias IAs de
    # vários fabricantes (Claude, GPT, Llama, Deepseek...) — troca só
    # AI_MODEL pra escolher o modelo por trás, sem trocar de provider. Uma
    # chave só (openrouter.ai/keys) em vez de uma chave por fabricante.
    "openrouter": OpenAICompatProvider,
}

_RESEARCH_OVERRIDE_KEY = "research_provider_override"


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


def get_research_provider_override() -> dict | None:
    """Config do research provider salva via UI (GET/POST /api/provider/research)
    — tem prioridade sobre RESEARCH_PROVIDER do .env. None = sem override,
    usa .env (comportamento de sempre)."""
    raw = database.get_setting(_RESEARCH_OVERRIDE_KEY)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if data.get("provider") else None


def set_research_provider_override(
    provider: str, base_url: str = "", model: str = "", api_key: str | None = None,
) -> None:
    """provider='' remove o override (volta pro .env). api_key=None mantém
    a chave já salva (evita ter que reenviar a chave só pra trocar modelo)."""
    provider = provider.strip()
    if not provider:
        database.set_setting(_RESEARCH_OVERRIDE_KEY, "")
        return
    existing = get_research_provider_override() or {}
    payload = {
        "provider": provider,
        "base_url": base_url.strip(),
        "model": model.strip(),
        "api_key": existing.get("api_key", "") if api_key is None else api_key,
    }
    database.set_setting(_RESEARCH_OVERRIDE_KEY, json.dumps(payload))


def build_provider(name: str | None = None) -> LLMProvider:
    provider = (name or settings.ai_provider).lower()
    cls = _REGISTRY.get(provider)
    if cls is None:
        raise ValueError(f"Unknown AI provider: {provider}")
    cfg = LLMConfig(
        model=settings.ai_model,
        base_url=settings.ai_base_url,
        api_key=settings.ai_api_key,
        temperature=settings.ai_temperature,
        context_tokens=settings.ai_context_tokens,
        timeout=settings.ai_timeout,
    )
    return cls(cfg)


def build_research_provider() -> LLMProvider:
    """Provider de pesquisa/planejamento (Planner monta o plano, Validator
    avalia o resultado) — separado do provider principal de execução
    (build_provider(), o DeepHat). Ordem de resolução: override salvo via
    UI (GET/POST /api/provider/research) > RESEARCH_PROVIDER do .env >
    nenhum 2° modelo (cai no provider principal) — comportamento igual a
    antes desse recurso existir se nada estiver configurado."""
    override = get_research_provider_override()
    if override:
        cls = _REGISTRY.get(override["provider"].lower())
        if cls is None:
            raise ValueError(f"Unknown research provider: {override['provider']}")
        cfg = LLMConfig(
            model=override.get("model") or settings.ai_model,
            base_url=override.get("base_url") or "",
            api_key=override.get("api_key") or "",
            temperature=settings.ai_temperature,
            context_tokens=settings.ai_context_tokens,
            timeout=settings.research_timeout,
        )
        return cls(cfg)
    if not settings.research_provider:
        return build_provider()
    cls = _REGISTRY.get(settings.research_provider.lower())
    if cls is None:
        raise ValueError(f"Unknown research provider: {settings.research_provider}")
    cfg = LLMConfig(
        model=settings.research_model or settings.ai_model,
        base_url=settings.research_base_url,
        api_key=settings.research_api_key,
        temperature=settings.ai_temperature,
        context_tokens=settings.ai_context_tokens,
        timeout=settings.research_timeout,
    )
    return cls(cfg)


def build_vision_provider() -> LLMProvider:
    """Provider para a personagem "ver" a tela (NVIDIA NIM por padrão)."""
    cls = _REGISTRY.get(settings.vision_provider.lower())
    if cls is None:
        raise ValueError(f"Unknown vision provider: {settings.vision_provider}")
    cfg = LLMConfig(
        model=settings.vision_model,
        base_url=settings.vision_base_url,
        api_key=settings.vision_api_key,
        temperature=settings.ai_temperature,
        context_tokens=settings.ai_context_tokens,
        timeout=settings.vision_timeout,
    )
    return cls(cfg)
