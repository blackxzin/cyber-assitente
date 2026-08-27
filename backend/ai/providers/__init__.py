"""Provider registry: resolve the configured provider by name."""

from config.settings import settings

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
    (build_provider(), o DeepHat). Se RESEARCH_PROVIDER não estiver
    configurado no .env, cai no mesmo provider/modelo principal: nenhum
    2° modelo, comportamento igual a antes desse recurso existir."""
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
