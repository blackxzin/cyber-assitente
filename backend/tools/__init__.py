"""Tool factory: builds the registry with all registered tools."""

from tools.registry import ToolRegistry

from tools import (
    burp, crypto, diagnostics, memory, network, osint, pentest, reverse, system, web,
)


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    system.register(registry)
    network.register(registry)
    diagnostics.register(registry)
    pentest.register(registry)
    osint.register(registry)
    reverse.register(registry)
    burp.register(registry)
    memory.register(registry)
    crypto.register(registry)
    web.register(registry)
    return registry
