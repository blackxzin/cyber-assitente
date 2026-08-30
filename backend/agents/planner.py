"""Task Planner: decomposes complex requests into multi-step execution plans."""

import json
import re
from typing import TYPE_CHECKING

from security.logging import log_event

if TYPE_CHECKING:
    from ai.providers.base import LLMProvider
    from tools.registry import ToolRegistry


# Só dispara o pipeline caro (planner+executor+validator+síntese = 3+ chamadas
# ao LLM) quando o pedido é MESMO multi-passo. Sinais fracos e gulosos foram
# removidos de propósito: `lista.*e` casava "lista minhas intErfaces" (qualquer
# "e" na frase), `precis.*de` casava "preciso de ajuda", e `todas/todos` casava
# "mostra todos os processos" — todos leituras de 1 ferramenta que não podem
# pagar 90s de pipeline. Sequência real é capturada por "e depois"/"em seguida"/
# "primeiro...depois"/"passo a passo".
_COMPLEX_RE = re.compile(
    r"\b(?:completo|completa|full|"
    r"analis[ae]\w*|investig\w+|auditoria|report|relat[oó]rio|"
    r"varredura|pentest|diagnos\w*|"
    r"passo a passo|e depois|em seguida|"
    r"v[aá]rios|v[aá]rias|m[uú]ltipl[oa]s?)\b"
    r"|\btudo\b(?!\s+(?:bem|bom|certo|ok|tranquilo))"
    r"|\bprimeiro\b.{0,40}\bdepois\b",
    re.IGNORECASE,
)


def is_complex_task(prompt: str) -> bool:
    return bool(_COMPLEX_RE.search(prompt))


class TaskPlanner:
    def __init__(self, provider: "LLMProvider", registry: "ToolRegistry") -> None:
        self.provider = provider
        self.registry = registry

    async def plan(self, prompt: str) -> list[dict]:
        tools = self.registry.list()
        tool_block = "\n".join(
            f"- {t.name}: {t.description} [confirmacao={t.requires_confirmation}]"
            for t in tools
        )
        system = (
            "Você é um planejador de tarefas de segurança e sysadmin. "
            "Dado um pedido, crie um plano com no máximo 5 passos sequenciais "
            "usando as ferramentas disponíveis. "
            "Responda APENAS JSON válido no formato:\n"
            '{"steps": [{"id": 1, "description": "...", "tool": "nome", "args": {...}}, ...]}\n'
            "Se um passo não precisa de ferramenta, use tool=null. "
            "Nunca invente ferramentas — use APENAS as listadas abaixo. "
            "Os args devem conter todos os valores necessários extraídos do pedido do usuário.\n\n"
            f"Ferramentas:\n{tool_block}"
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Pedido: {prompt}"},
        ]
        try:
            raw = (await self.provider.complete(messages, json_mode=True, max_tokens=600)).strip()
            fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
            if fence:
                raw = fence.group(1)
            data = json.loads(raw)
            steps = data.get("steps", [])
            if not isinstance(steps, list):
                return []
            valid_names = {t.name for t in tools}
            cleaned: list[dict] = []
            for step in steps:
                tool = step.get("tool")
                if tool and tool not in valid_names:
                    log_event("warning", "planner", f"passo com ferramenta inexistente ignorado: {tool}")
                    continue
                cleaned.append({
                    "id": step.get("id", len(cleaned) + 1),
                    "description": str(step.get("description", "")),
                    "tool": tool,
                    "args": step.get("args") if isinstance(step.get("args"), dict) else {},
                })
            log_event("info", "planner", f"plano criado: {len(cleaned)} passo(s)")
            return cleaned
        except Exception as exc:
            log_event("warning", "planner", f"falhou ao criar plano: {exc}")
            return []
