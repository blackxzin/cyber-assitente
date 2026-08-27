"""Result Validator: checks if a completed plan met the user's goal."""

import re
from typing import TYPE_CHECKING

from security.logging import log_event

if TYPE_CHECKING:
    from ai.providers.base import LLMProvider
    from agents.executor import StepResult


class ValidationResult:
    def __init__(self, success: bool, summary: str, gaps: list[str]) -> None:
        self.success = success
        self.summary = summary
        self.gaps = gaps


class ResultValidator:
    def __init__(self, provider: "LLMProvider") -> None:
        self.provider = provider

    async def validate(self, prompt: str, results: list["StepResult"]) -> ValidationResult:
        if not results:
            return ValidationResult(False, "Nenhum passo executado.", ["plano vazio"])

        steps_block = "\n".join(
            f"Passo {r.step_id} ({r.tool or 'llm'}): status={r.status}\n"
            f"Saída: {r.output[:400] if r.output else '(vazio)'}"
            for r in results
        )
        messages = [
            {"role": "system", "content": (
                "Você é um validador de resultados. "
                "Dado o pedido original e os resultados dos passos executados, "
                "responda em JSON: "
                '{"success": true/false, "summary": "breve explicação", '
                '"gaps": ["lacuna1", ...]}\n'
                "success=true se o objetivo foi atingido. "
                "gaps = lista de itens que faltaram ou falharam (vazio se ok)."
            )},
            {"role": "user", "content": (
                f"Pedido: {prompt}\n\nResultados:\n{steps_block}"
            )},
        ]
        try:
            raw = (await self.provider.complete(messages, json_mode=True, max_tokens=250)).strip()
            fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
            if fence:
                raw = fence.group(1)
            import json
            data = json.loads(raw)
            return ValidationResult(
                success=bool(data.get("success", False)),
                summary=str(data.get("summary", "")),
                gaps=list(data.get("gaps", [])),
            )
        except Exception as exc:
            log_event("warning", "validator", f"validação falhou: {exc}")
            all_ok = all(r.status == "ok" for r in results if r.tool)
            return ValidationResult(
                success=all_ok,
                summary="Validação automática não disponível.",
                gaps=[],
            )
