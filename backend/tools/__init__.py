"""Tool factory: builds the registry with all registered tools."""

from tools.registry import ToolRegistry

from tools import (
    burp, crypto, diagnostics, enum, exploit, memory, network, osint, pentest,
    pipeline, recon_api, reporting, reverse, system, web, webscan,
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
    webscan.register(registry)
    enum.register(registry)
    exploit.register(registry)
    recon_api.register(registry)
    reporting.register(registry)
    pipeline.register(registry)
    return registry
