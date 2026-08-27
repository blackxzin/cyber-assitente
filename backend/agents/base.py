"""Agent contracts.

An Agent inspects a request and decides which tools it needs. Tools are
resolved by name through the ToolRegistry, so agents stay decoupled from
concrete implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AgentContext:
    prompt: str
    history: list[dict[str, str]] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    llm_notes: str = ""


class Agent(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    async def run(self, ctx: AgentContext) -> str:
        """Return the agent's final answer text."""
        raise NotImplementedError
