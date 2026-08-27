"""Tool factory: builds the registry with all registered tools."""

from tools.registry import ToolRegistry

from tools import burp, diagnostics, memory, network, pentest, reverse, system


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    system.register(registry)
    network.register(registry)
    diagnostics.register(registry)
    pentest.register(registry)
    reverse.register(registry)
    burp.register(registry)
    memory.register(registry)
    return registry
