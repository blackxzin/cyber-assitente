"""Testes do ResultValidator (backend/agents/validator.py): parsing da
resposta JSON do LLM e fallback determinístico quando ela falha."""

from agents.executor import StepResult
from agents.validator import ResultValidator


class _ScriptedProvider:
    def __init__(self, reply: str) -> None:
        self.reply = reply

    async def complete(self, messages: list[dict], **extra) -> str:
        return self.reply


async def test_validate_parses_success_and_gaps_from_json():
    provider = _ScriptedProvider('{"success": true, "summary": "tudo certo", "gaps": []}')
    validator = ResultValidator(provider)
    results = [StepResult(1, "d", "connectivity", "ok", "conectou")]
    validation = await validator.validate("testa host", results)
    assert validation.success is True
    assert validation.summary == "tudo certo"
    assert validation.gaps == []


async def test_validate_reports_gaps_when_llm_flags_them():
    provider = _ScriptedProvider(
        '{"success": false, "summary": "faltou o scan", "gaps": ["nmap_scan não rodou"]}'
    )
    validator = ResultValidator(provider)
    results = [StepResult(1, "d", "connectivity", "ok", "conectou")]
    validation = await validator.validate("faz tudo", results)
    assert validation.success is False
    assert validation.gaps == ["nmap_scan não rodou"]


async def test_validate_empty_results_short_circuits_without_calling_llm():
    validator = ResultValidator(_ScriptedProvider("não deveria ser chamado"))
    validation = await validator.validate("faz tudo", [])
    assert validation.success is False
    assert validation.gaps == ["plano vazio"]


async def test_validate_falls_back_to_step_status_on_garbled_llm_output():
    provider = _ScriptedProvider("resposta que não é JSON")
    validator = ResultValidator(provider)
    results = [
        StepResult(1, "d1", "connectivity", "ok", "conectou"),
        StepResult(2, "d2", "nmap_scan", "ok", "3 portas abertas"),
    ]
    validation = await validator.validate("faz tudo", results)
    assert validation.success is True  # all tool steps were "ok"
    assert validation.gaps == []


async def test_validate_fallback_reports_failure_when_a_step_errored():
    provider = _ScriptedProvider("não é JSON")
    validator = ResultValidator(provider)
    results = [
        StepResult(1, "d1", "connectivity", "ok", "conectou"),
        StepResult(2, "d2", "nmap_scan", "error", "erro: timeout"),
    ]
    validation = await validator.validate("faz tudo", results)
    assert validation.success is False


async def test_validate_unwraps_markdown_code_fence():
    provider = _ScriptedProvider('```json\n{"success": true, "summary": "ok", "gaps": []}\n```')
    validator = ResultValidator(provider)
    results = [StepResult(1, "d", "connectivity", "ok", "conectou")]
    validation = await validator.validate("testa", results)
    assert validation.success is True
