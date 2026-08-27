"""System agent: analyzes the user's own machine.

Runs read-only diagnostics tools, then the LLM explains the results.
"""

from agents.base import Agent, AgentContext
from ai.providers.base import LLMProvider
from security.errors import describe_exception
from tools.registry import ToolRegistry


class SystemAgent(Agent):
    name = "system"
    description = "Analisa o próprio computador: CPU, RAM, disco, rede, processos."

    def __init__(self, provider: LLMProvider, registry: ToolRegistry) -> None:
        self.provider = provider
        self.registry = registry

    async def run(self, ctx: AgentContext) -> str:
        # tools that are pure reads on this machine
        tool_names = [
            "system_info",
            "memory_info",
            "disk_info",
            "network_interfaces",
            "process_list",
        ]
        results: list[str] = []
        for name in tool_names:
            try:
                out = await self.registry.run(name, {})
                results.append(f"[{name}]\n{out}")
            except Exception as exc:
                results.append(f"[{name}] erro: {describe_exception(exc)}")

        combined = "\n\n".join(results)
        messages = [
            {"role": "system", "content": (
                "Você analisou o computador do usuário com ferramentas de leitura. "
                "Resuma em português claro: o que foi encontrado, o que está normal, "
                "o que merece atenção (alto uso, muitos processos, etc). Não invente "
                "dados que não estejam nos resultados."
            )},
            {"role": "user", "content": f"Pergunta: {ctx.prompt}\n\nDados coletados:\n{combined[:8000]}"},
        ]
        return (await self.provider.complete(messages)).strip()
