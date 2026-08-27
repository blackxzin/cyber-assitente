"""Long-term memory tools: let the assistant remember facts across sessions.

Facts are plain text saved verbatim in SQLite (`memory` table) and surfaced
back in two ways: explicitly via the `recall` tool, and ambiently — the
Orchestrator injects the most recent facts into its system prompts so the
assistant references them without the user having to ask.
"""

from database import db as database
from security.sanitize import sanitize_text
from tools.registry import ToolRegistry

_MAX_CONTENT_CHARS = 500


async def tool_remember(args: dict) -> str:
    content = str(args.get("content") or "").strip()
    if not content:
        return "Nada para lembrar: conteúdo vazio."
    # Same invariant as every other persisted string in this app (see
    # services/chat.py): redact secrets BEFORE writing to disk, not after —
    # this fact gets replayed into future LLM prompts and exposed via
    # GET /api/memory, so a raw secret here leaks on every future turn.
    content = sanitize_text(content)[:_MAX_CONTENT_CHARS]
    database.insert_memory(content)
    return f"Anotado: {content}"


async def tool_recall(args: dict) -> str:
    query = str(args.get("query") or "").strip().lower()
    facts = database.list_memory(limit=50)
    if query:
        facts = [f for f in facts if query in f["content"].lower()]
    if not facts:
        return f"Nada salvo sobre '{query}'." if query else "Nenhum fato salvo ainda."
    lines = [f"- {f['content']} ({f['created_at'][:10]})" for f in facts[:20]]
    return "\n".join(lines)


def register(registry: ToolRegistry) -> None:
    registry.register(
        "remember",
        "Guarda um fato pra lembrar depois, entre sessões (informe 'content').",
        tool_remember,
        risk="info",
        requires_confirmation=False,
        required_args=("content",),
        category="memória",
    )
    registry.register(
        "recall",
        "Lista fatos guardados anteriormente (opcional 'query' pra filtrar).",
        tool_recall,
        risk="info",
        requires_confirmation=False,
        category="memória",
    )
