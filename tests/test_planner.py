"""Testes do TaskPlanner (backend/agents/planner.py): detecção de tarefa
complexa e geração/validação do plano JSON devolvido pelo LLM."""

from agents.planner import TaskPlanner, is_complex_task
from tools.registry import ToolRegistry


class _ScriptedProvider:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.calls: list[dict] = []

    async def complete(self, messages: list[dict], **extra) -> str:
        self.calls.append({"messages": messages, "extra": extra})
        return self.reply


def _registry_with_tools() -> ToolRegistry:
    reg = ToolRegistry()

    async def _fn(args: dict) -> str:
        return "ok"

    reg.register("nmap_scan", "Escaneia um host.", _fn,
                  risk="moderate", requires_confirmation=True, required_args=("host",))
    reg.register("connectivity", "Testa conectividade.", _fn,
                  risk="info", requires_confirmation=False, required_args=("host",))
    return reg


def test_is_complex_task_matches_multi_step_language():
    assert is_complex_task("faz uma auditoria completa e depois um relatório")
    assert is_complex_task("investiga tudo nesse host")


def test_is_complex_task_rejects_simple_requests():
    assert not is_complex_task("oi, tudo bem?")
    assert not is_complex_task("qual a hora")


async def test_plan_parses_valid_json_steps():
    provider = _ScriptedProvider(
        '{"steps": [{"id": 1, "description": "testa conexão", "tool": "connectivity", "args": {"host": "8.8.8.8"}},'
        ' {"id": 2, "description": "escaneia", "tool": "nmap_scan", "args": {"host": "8.8.8.8"}}]}'
    )
    planner = TaskPlanner(provider, _registry_with_tools())
    steps = await planner.plan("investiga tudo sobre 8.8.8.8")
    assert [s["tool"] for s in steps] == ["connectivity", "nmap_scan"]
    assert steps[0]["args"] == {"host": "8.8.8.8"}


async def test_plan_requests_json_mode():
    provider = _ScriptedProvider('{"steps": []}')
    planner = TaskPlanner(provider, _registry_with_tools())
    await planner.plan("faz tudo")
    assert provider.calls[0]["extra"].get("json_mode") is True


async def test_plan_unwraps_markdown_code_fence():
    provider = _ScriptedProvider(
        '```json\n{"steps": [{"id": 1, "description": "d", "tool": null, "args": {}}]}\n```'
    )
    planner = TaskPlanner(provider, _registry_with_tools())
    steps = await planner.plan("faz tudo")
    assert steps == [{"id": 1, "description": "d", "tool": None, "args": {}}]


async def test_plan_drops_steps_with_hallucinated_tool_names():
    provider = _ScriptedProvider(
        '{"steps": [{"id": 1, "description": "d1", "tool": "port_scanner", "args": {}},'
        ' {"id": 2, "description": "d2", "tool": "connectivity", "args": {"host": "1.1.1.1"}}]}'
    )
    planner = TaskPlanner(provider, _registry_with_tools())
    steps = await planner.plan("faz tudo")
    assert len(steps) == 1
    assert steps[0]["tool"] == "connectivity"


async def test_plan_returns_empty_list_on_garbled_output():
    provider = _ScriptedProvider("não sei o que você quer dizer")
    planner = TaskPlanner(provider, _registry_with_tools())
    steps = await planner.plan("faz tudo")
    assert steps == []


async def test_plan_returns_empty_list_when_steps_is_not_a_list():
    provider = _ScriptedProvider('{"steps": "oops"}')
    planner = TaskPlanner(provider, _registry_with_tools())
    steps = await planner.plan("faz tudo")
    assert steps == []
