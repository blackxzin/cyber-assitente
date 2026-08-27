"""Testes do SystemAgent (backend/agents/system_agent.py) — zero cobertura
antes desta sessão. Registry e provider são fakes; nenhum tool real roda."""

from agents.base import AgentContext
from agents.system_agent import SystemAgent


class _FakeRegistry:
    def __init__(self, results: dict[str, str], failing: set[str] = frozenset()) -> None:
        self.results = results
        self.failing = failing
        self.called: list[str] = []

    async def run(self, name: str, args: dict) -> str:
        self.called.append(name)
        if name in self.failing:
            raise RuntimeError(f"{name} falhou de propósito")
        return self.results.get(name, "")


class _FakeProvider:
    def __init__(self, reply: str = "resumo do sistema") -> None:
        self.reply = reply
        self.calls: list[dict] = []

    async def complete(self, messages, **extra) -> str:
        self.calls.append({"messages": messages, "extra": extra})
        return self.reply


async def test_runs_all_five_read_only_tools_in_order():
    registry = _FakeRegistry({})
    agent = SystemAgent(_FakeProvider(), registry)
    await agent.run(AgentContext(prompt="como tá minha máquina?"))
    assert registry.called == [
        "system_info", "memory_info", "disk_info", "network_interfaces", "process_list",
    ]


async def test_feeds_real_tool_output_into_synthesis_prompt():
    registry = _FakeRegistry({"system_info": "Linux arch, uptime 3d", "memory_info": "8GB/16GB"})
    provider = _FakeProvider()
    agent = SystemAgent(provider, registry)
    await agent.run(AgentContext(prompt="tudo bem com a RAM?"))
    sent = provider.calls[0]["messages"][-1]["content"]
    assert "8GB/16GB" in sent
    assert "Linux arch, uptime 3d" in sent
    assert "tudo bem com a RAM?" in sent


async def test_tool_failure_is_captured_inline_not_raised():
    registry = _FakeRegistry(
        {"system_info": "ok"}, failing={"memory_info"},
    )
    provider = _FakeProvider()
    agent = SystemAgent(provider, registry)
    result = await agent.run(AgentContext(prompt="status"))
    sent = provider.calls[0]["messages"][-1]["content"]
    assert "[memory_info] erro:" in sent
    assert "falhou de propósito" in sent
    assert result == "resumo do sistema"  # síntese ainda roda mesmo com 1 tool falhando


async def test_returns_stripped_synthesis_text():
    provider = _FakeProvider(reply="  resposta com espaço em volta  \n")
    agent = SystemAgent(provider, _FakeRegistry({}))
    result = await agent.run(AgentContext(prompt="oi"))
    assert result == "resposta com espaço em volta"


async def test_combined_output_truncated_to_8000_chars():
    huge = "X" * 9000
    registry = _FakeRegistry({"system_info": huge})
    provider = _FakeProvider()
    agent = SystemAgent(provider, registry)
    await agent.run(AgentContext(prompt="oi"))
    sent = provider.calls[0]["messages"][-1]["content"]
    assert len(sent) < 8500  # prompt fixo + até 8000 de dados, não 9000+
