"""Learning agent: structured explanations for security/sysadmin concepts.

Every question routed here is logged in `learning_progress` (SQLite) so
repeated questions about the same topic are recognized and the explanation
adapts instead of repeating itself verbatim.
"""

import re

from agents.base import Agent, AgentContext
from ai.providers.base import LLMProvider
from database import db as database

_STOPWORDS = {
    "o", "a", "os", "as", "de", "da", "do", "dos", "das", "que", "é", "e",
    "um", "uma", "como", "pra", "para", "me", "sobre", "explica", "explique",
    "ensina", "ensinar", "aprender", "aprend", "conceito", "tutorial",
    "professor", "the", "what", "is", "explain",
}
_MAX_CONCEPT_CHARS = 80
_MAX_CONCEPT_WORDS = 6


def _extract_concept(prompt: str) -> str:
    """Best-effort topic key for progress tracking — no LLM round-trip, just
    a stopword-filtered slug of the prompt so repeats of the same question
    collapse onto the same `learning_progress` row."""
    words = re.findall(r"[a-zA-ZÀ-ÿ0-9_-]+", prompt.lower())
    kept = [w for w in words if w not in _STOPWORDS and len(w) > 2]
    concept = " ".join(kept[:_MAX_CONCEPT_WORDS]) or prompt.strip().lower()
    return concept[:_MAX_CONCEPT_CHARS]


class LearningAgent(Agent):
    name = "learning"
    description = "Ensina conceitos de segurança e Linux de forma estruturada, guardando seu progresso."

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def run(self, ctx: AgentContext) -> str:
        concept = _extract_concept(ctx.prompt)
        seen_before = any(
            row["concept"] == concept for row in database.learning_progress(limit=500)
        )
        database.touch_learning_progress(concept)

        review_note = (
            "O usuário já perguntou sobre isso antes — reforce com um ângulo "
            "novo ou um exemplo mais avançado, sem repetir a explicação anterior."
            if seen_before else
            "Primeira vez que o usuário pergunta sobre isso — comece do básico."
        )
        messages = [
            {"role": "system", "content": (
                "Você é o Cyber, professor de pentest, hacking ofensivo e Linux. "
                f"{review_note} "
                "Estruture SEMPRE a resposta em 4 partes com esses títulos exatos:\n"
                "**Conceito**: definição curta e clara.\n"
                "**Exemplo prático**: comando ou cenário real (Linux/segurança).\n"
                "**Cuidado**: um risco ou erro comum relacionado.\n"
                "**Pergunta pra fixar**: uma pergunta curta pro usuário testar o entendimento.\n"
                "Responda em português, didático, sem inventar fatos técnicos incorretos."
            )},
            *ctx.history[-4:],
            {"role": "user", "content": ctx.prompt},
        ]
        return (await self.provider.complete(messages)).strip()
