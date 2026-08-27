"""Tool registry: central catalogue and executor for all tools."""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable

ToolFn = Callable[[dict], Awaitable[str]]


@dataclass
class ToolSpec:
    name: str
    description: str
    fn: ToolFn
    risk: str = "info"  # info | moderate | dangerous
    requires_confirmation: bool = False
    # Arg keys the LLM must fill before this tool is called. Checked by the
    # orchestrator before confirmation/execution so a bad tool-selection
    # JSON turns into a clarifying question instead of a wasted confirm
    # round-trip or a tool call that fails on missing input.
    required_args: tuple[str, ...] = ()


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, description: str, fn: ToolFn, **meta) -> None:
        self._tools[name] = ToolSpec(name, description, fn, **meta)

    def list(self) -> list[ToolSpec]:
        return sorted(self._tools.values(), key=lambda t: t.name)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    async def run(self, name: str, args: dict) -> str:
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"Ferramenta desconhecida: {name}")
        result = tool.fn(args)
        if asyncio.iscoroutine(result):
            return await result
        return result


def read_only(name: str, description: str, fn: ToolFn):
    """Decorator shorthand to register a read-only tool."""

    def wrapper(registry: ToolRegistry) -> None:
        registry.register(name, description, fn, risk="info", requires_confirmation=False)

    return wrapper
