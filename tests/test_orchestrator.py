"""Testes do Orchestrator (backend/agents/__init__.py) — decisão de qual
ferramenta usar, validação de argumentos obrigatórios, e retry quando o
LLM erra o formato JSON ou cita uma ferramenta inexistente."""

from agents import Orchestrator
from config.settings import settings
from tools.confirm import ConfirmationStore
from tools.registry import ToolRegistry


class _ScriptedProvider:
    """Provider fake: devolve as respostas da lista, uma por chamada a
    complete(); a última resposta se repete se a lista acabar."""

    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.calls: list[dict] = []

    async def complete(self, messages: list[dict], **extra) -> str:
        self.calls.append({"messages": messages, "extra": extra})
        idx = min(len(self.calls) - 1, len(self.replies) - 1)
        return self.replies[idx]

    @property
    def decide_calls(self) -> list[dict]:
        """Only the tool-selection calls, excluding confirmation-summary
        and final-synthesis calls that also go through complete()."""
        return [c for c in self.calls if "You decide which tool" in c["messages"][0]["content"]]


async def _echo(args: dict) -> str:
    return f"ok {args}"


def _registry_with_nmap() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(
        "nmap_scan", "Escaneia um host (informe 'host').", _echo,
        risk="moderate", requires_confirmation=True, required_args=("host",),
    )
    return reg


async def test_valid_json_decision_runs_tool_directly():
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert "preciso da sua autorização" in result.lower()
    assert orch.last_pending["tool"] == "nmap_scan"


async def test_missing_required_arg_asks_for_clarification_without_confirming():
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("faz um scan", [])
    assert "host" in result.lower()
    assert orch.last_pending is None  # never reached confirmation


async def test_hallucinated_tool_name_triggers_one_retry_then_recovers():
    provider = _ScriptedProvider([
        '{"tool": "port_scanner", "args": {"host": "10.0.0.5"}}',  # doesn't exist
        '{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}',
    ])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert len(provider.decide_calls) == 2
    assert orch.last_pending["tool"] == "nmap_scan"
    assert "autorização" in result.lower()


async def test_garbled_non_json_output_triggers_retry():
    provider = _ScriptedProvider([
        "sure, I'll use the nmap tool for that!",  # not JSON at all
        '{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}',
    ])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert len(provider.decide_calls) == 2
    assert orch.last_pending["tool"] == "nmap_scan"


async def test_deliberate_null_tool_does_not_retry():
    provider = _ScriptedProvider(['{"tool": null}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    await orch._run_with_tools("oi, tudo bem?", [])
    assert len(provider.decide_calls) == 1  # no retry burned on a legitimate no-tool decision


async def test_decide_tool_requests_json_mode():
    provider = _ScriptedProvider(['{"tool": null}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    await orch._run_with_tools("oi", [])
    assert provider.calls[0]["extra"].get("json_mode") is True


class _SynthesisFailsProvider:
    """decide call succeeds normally; the final-synthesis call (the one
    whose prompt embeds the real tool output) raises with a blank
    exception message, mirroring httpx.ReadTimeout in production."""

    def __init__(self, decision: str) -> None:
        self.decision = decision
        self.calls: list[dict] = []

    async def complete(self, messages: list[dict], **extra) -> str:
        self.calls.append({"messages": messages, "extra": extra})
        if "You decide which tool" in messages[0]["content"]:
            return self.decision
        raise TimeoutError()  # str(TimeoutError()) == "" — the exact bug reproduced live


def _registry_with_no_confirm_tool(result_text: str) -> ToolRegistry:
    reg = ToolRegistry()

    async def _fn(args: dict) -> str:
        return result_text

    reg.register("connectivity", "Testa conectividade (informe 'host').", _fn,
                  risk="info", requires_confirmation=False, required_args=("host",))
    return reg


async def test_synthesis_failure_preserves_real_tool_result():
    provider = _SynthesisFailsProvider('{"tool": "connectivity", "args": {"host": "8.8.8.8"}}')
    reg = _registry_with_no_confirm_tool("conectou em 7.3 ms")
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("testa 8.8.8.8", [])
    assert "conectou em 7.3 ms" in result  # real result survives, not swallowed
    assert "síntese indisponível" in result
    assert "TimeoutError" in result  # blank str(exc) still names the exception type


async def test_huge_tool_result_truncated_before_synthesis_prompt():
    huge = "X" * 10_000
    provider = _ScriptedProvider([
        '{"tool": "connectivity", "args": {"host": "8.8.8.8"}}',
        "resposta sintetizada",
    ])
    reg = _registry_with_no_confirm_tool(huge)
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("testa 8.8.8.8", [])
    assert result == "resposta sintetizada"
    synth_call = provider.calls[-1]
    sent_content = synth_call["messages"][-1]["content"]
    assert len(sent_content) < 4000  # capped, not the full 10k blob
    assert "truncado" in sent_content


# --- safe_mode=advanced: ferramentas confirmáveis rodam direto (pentest automático) ---

async def test_advanced_safe_mode_runs_confirmable_tool_without_asking(monkeypatch):
    monkeypatch.setattr(settings, "safe_mode", "advanced")
    provider = _ScriptedProvider([
        '{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}',
        "resposta sintetizada",
    ])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert orch.last_pending is None  # nunca pediu aprovação
    assert result == "resposta sintetizada"
    assert orch.last_tool_calls[0]["status"] == "ok"


async def test_assisted_safe_mode_still_asks_for_confirmation(monkeypatch):
    monkeypatch.setattr(settings, "safe_mode", "assisted")
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert orch.last_pending["tool"] == "nmap_scan"
    assert "autorização" in result.lower()


# --- research_provider: Planner/Validator usam o 2° modelo quando configurado ---

async def test_research_provider_defaults_to_main_provider_when_not_given():
    provider = _ScriptedProvider(["ok"])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    assert orch.research_provider is provider


async def test_research_provider_used_for_planning_when_given():
    main_provider = _ScriptedProvider(["não deveria ser chamado pro plano"])
    research_provider = _ScriptedProvider([
        '{"steps": [{"id": 1, "description": "scan", "tool": "nmap_scan", '
        '"args": {"host": "10.0.0.5"}}]}',
    ])
    reg = _registry_with_nmap()
    orch = Orchestrator(main_provider, reg, ConfirmationStore(), research_provider)
    assert orch.research_provider is research_provider
    result = await orch._run_pipeline("faça um pentest completo em 10.0.0.5", [])
    assert research_provider.calls  # planner chamou o provider de pesquisa
    assert not main_provider.calls  # não o principal (parou em confirmação)
    assert result is not None
    assert "autorização" in result.lower()
