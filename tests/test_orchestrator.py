"""Testes do Orchestrator (backend/agents/__init__.py) — decisão de qual
ferramenta usar, validação de argumentos obrigatórios, e retry quando o
LLM erra o formato JSON ou cita uma ferramenta inexistente."""

import pytest

from agents import Orchestrator
from config.settings import settings
from database import db
from security import scope
from tools.confirm import ConfirmationStore
from tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Each test gets its own throwaway SQLite file — orchestrator calls
    _memory_snippet(), which hits the real DB_PATH if this isn't set."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


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
        target_arg="host",
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


async def test_tool_error_result_skips_synthesis_to_avoid_hallucination():
    # Regressão observada ao vivo: "erro: ..." (convenção usada por toda
    # ferramenta em tools/*.py) foi mandado pro prompt de síntese ("cite
    # dados reais"), e o LLM local inventou versão de software, SO e lista
    # de extensões que não existiam em lugar nenhum do resultado real.
    provider = _ScriptedProvider([
        '{"tool": "connectivity", "args": {"host": "8.8.8.8"}}',
        "não deveria ser chamado pra sintetizar um erro",
    ])
    reg = _registry_with_no_confirm_tool("erro: Não consegui conectar no MCP Server do Burp")
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("roda a ferramenta", [])
    assert result == "⚠️ erro: Não consegui conectar no MCP Server do Burp"
    assert len(provider.calls) == 1  # só a decisão, síntese nunca chamada


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


# --- escopo autorizado: bloqueia alvo fora de escopo antes de pedir confirmação ---

async def test_out_of_scope_target_blocked_before_confirmation():
    scope.set_scope(["10.0.0.0/24"])
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {"host": "8.8.8.8"}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 8.8.8.8", [])
    assert "fora do escopo" in result
    assert orch.last_pending is None  # nunca chegou a pedir confirmação


async def test_in_scope_target_still_asks_for_confirmation():
    scope.set_scope(["10.0.0.0/24"])
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {"host": "10.0.0.5"}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 10.0.0.5", [])
    assert orch.last_pending["tool"] == "nmap_scan"
    assert "autorização" in result.lower()


async def test_out_of_scope_target_blocked_even_in_advanced_mode(monkeypatch):
    monkeypatch.setattr(settings, "safe_mode", "advanced")
    scope.set_scope(["10.0.0.0/24"])
    provider = _ScriptedProvider(['{"tool": "nmap_scan", "args": {"host": "8.8.8.8"}}'])
    reg = _registry_with_nmap()
    orch = Orchestrator(provider, reg, ConfirmationStore())
    result = await orch._run_with_tools("scaneia 8.8.8.8", [])
    assert "fora do escopo" in result
    assert orch.last_tool_calls == []  # ferramenta nunca executou


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


# --- synthesize_approved: erro do próprio resultado não vira alucinação ---
# (mesmo bug do teste acima, mas no caminho de ação confirmada — o resultado
# chega envolto em "✅ Ação N aprovada.\n\n{result}" por tools/confirm.py,
# então a detecção de erro precisa desembrulhar isso primeiro.)

async def test_synthesize_approved_skips_synthesis_for_tool_error():
    provider = _ScriptedProvider(["não deveria ser chamado pra sintetizar um erro"])
    reg = ToolRegistry()

    async def _fail(args: dict) -> str:
        return "erro: Não consegui conectar no MCP Server do Burp (http://127.0.0.1:9876/)"

    reg.register("burp_find_vulnerabilities", "Varre vulnerabilidades.", _fail,
                  risk="moderate", requires_confirmation=True)
    store = ConfirmationStore()
    orch = Orchestrator(provider, reg, store)
    action = await store.register("burp_find_vulnerabilities", {}, "acha vulns no burp", "resumo")
    await store.resolve(action, True, reg)

    result = await orch.synthesize_approved(action.id)
    assert result == (
        "✅ Ação 1 aprovada.\n\n"
        "erro: Não consegui conectar no MCP Server do Burp (http://127.0.0.1:9876/)"
    )
    assert not provider.calls  # síntese nunca chamada


class _StreamingDecideProvider:
    """complete() devolve a decisão de ferramenta (JSON); stream_chat() emite
    a síntese final em pedaços — pra provar que o on_delta é repassado ponta a
    ponta pelo caminho de ferramenta."""

    def __init__(self, decision: str, synth_chunks: list[str]) -> None:
        self.decision = decision
        self.synth_chunks = synth_chunks
        self.stream_calls = 0

    async def complete(self, messages: list[dict], **extra) -> str:
        return self.decision

    async def stream_chat(self, messages: list[dict], **extra):
        self.stream_calls += 1
        for c in self.synth_chunks:
            yield c


def _registry_with_read_tool() -> ToolRegistry:
    reg = ToolRegistry()

    async def _fn(args: dict) -> str:
        return "Interfaces: lo, enp6s0"

    reg.register(
        "network_interfaces", "Lista interfaces de rede.", _fn,
        risk="info", requires_confirmation=False, required_args=(),
    )
    return reg


async def test_run_streams_synthesis_via_on_delta():
    provider = _StreamingDecideProvider(
        '{"tool": "network_interfaces", "args": {}}',
        ["As ", "interfaces ", "sao lo e enp6s0"],
    )
    orch = Orchestrator(provider, _registry_with_read_tool(), ConfirmationStore())
    seen: list[str] = []

    async def on_delta(text: str) -> None:
        seen.append(text)

    result = await orch.run("lista minhas interfaces de rede", [], on_delta=on_delta)
    assert provider.stream_calls == 1
    assert seen == ["As ", "As interfaces ", "As interfaces sao lo e enp6s0"]
    assert result == "As interfaces sao lo e enp6s0"
    assert orch.last_tool_calls[0]["tool"] == "network_interfaces"


def _registry_mixed_categories() -> ToolRegistry:
    reg = ToolRegistry()

    async def _fn(args: dict) -> str:
        return "ok"

    reg.register("network_interfaces", "rede.", _fn, category="rede")
    reg.register("system_info", "sistema.", _fn, category="sistema")
    reg.register("nmap_scan", "scan.", _fn, category="ofensivo",
                 requires_confirmation=True, required_args=("host",), target_arg="host")
    reg.register("recall", "memoria.", _fn, category="memória")
    return reg


def test_tool_block_filters_by_bucket():
    orch = Orchestrator(_ScriptedProvider([""]), _registry_mixed_categories(),
                        ConfirmationStore())
    sysblock = orch._tool_block("system")
    assert "system_info" in sysblock and "recall" in sysblock  # sistema + memória
    assert "nmap_scan" not in sysblock  # ofensivo fica de fora do bucket system
    # full=True traz tudo, inclusive o ofensivo
    assert "nmap_scan" in orch._tool_block("system", full=True)


def test_tool_block_unknown_bucket_returns_all():
    orch = Orchestrator(_ScriptedProvider([""]), _registry_mixed_categories(),
                        ConfirmationStore())
    block = orch._tool_block(None)
    for name in ("network_interfaces", "system_info", "nmap_scan", "recall"):
        assert name in block


async def test_run_emits_progress_events():
    provider = _StreamingDecideProvider(
        '{"tool": "network_interfaces", "args": {}}',
        ["pronto"],
    )
    reg = ToolRegistry()

    async def _fn(args: dict) -> str:
        return "Interfaces: lo"

    reg.register("network_interfaces", "Lista interfaces.", _fn,
                 category="rede", requires_confirmation=False)
    orch = Orchestrator(provider, reg, ConfirmationStore())
    progress: list[str] = []

    async def on_progress(msg: str) -> None:
        progress.append(msg)

    await orch.run("lista interfaces de rede", [], on_progress=on_progress)
    assert any("escolhendo ferramenta" in p for p in progress)
    assert any("executando" in p and "network_interfaces" in p for p in progress)
