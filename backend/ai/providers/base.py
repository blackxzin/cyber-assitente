"""Provider-agnostic LLM interface.

Every provider (ollama, openai, anthropic, lmstudio...) implements this
contract so the rest of the app never depends on a concrete model vendor.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator


@dataclass
class LLMConfig:
    model: str
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.6
    context_tokens: int = 4096
    timeout: float = 60.0


class LLMProvider(ABC):
    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    @abstractmethod
    async def stream_chat(
        self, messages: list[dict[str, str]], **extra
    ) -> AsyncIterator[str]:
        """Yield text deltas from a chat completion."""
        raise NotImplementedError

    @abstractmethod
    async def complete(self, messages: list[dict[str, str]], **extra) -> str:
        """Non-streaming convenience wrapper returning full text."""
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release provider resources (HTTP client, etc). Default no-op."""
