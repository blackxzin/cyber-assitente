"""Chat orchestration: turns user input into a streamed assistant answer.

Flow: sanitize → route through agents → (tools via Safety Layer) →
LLM synthesis → stream tokens to the client while persisting history.
"""

import json

from ai.prompts import SYSTEM_PROMPT
from ai.providers.base import LLMProvider
from database import db as database
from security.logging import log_event
from security.sanitize import sanitize_text
from tools.confirm import ConfirmationStore
from tools.registry import ToolRegistry

from agents import Orchestrator


class ChatService:
    def __init__(self, provider: LLMProvider, registry: ToolRegistry,
                 store: ConfirmationStore | None = None,
                 research_provider: LLMProvider | None = None) -> None:
        self.provider = provider
        self.registry = registry
        self.store = store or ConfirmationStore()
        self.orchestrator = Orchestrator(provider, registry, self.store, research_provider)

    async def stream(self, user_message: str) -> dict[str, object]:
        """Process one message and persist everything.

        Returns metadata plus the final assistant text (the caller streams
        it to the client as it is produced).
        """
        clean = sanitize_text(user_message.strip())
        if not clean:
            raise ValueError("Mensagem vazia.")

        # History for context (kept out of the loop on first message).
        history = database.history(limit=8)

        try:
            result = await self.orchestrator.run(clean, history)
        except (TimeoutError, RuntimeError) as exc:
            log_event("danger", "chat", f"erro não tratado: {exc}")
            raise

        # Persist each tool call for the audit trail.
        for call in self.orchestrator.last_tool_calls:
            database.log_tool_call(
                call.get("tool", "?"),
                {},
                call.get("result", ""),
                risk="info",
                status=call.get("status", "ok"),
            )

        final = sanitize_text(result)
        conversation_id = database.save_messages(
            [
                {"role": "user", "content": clean},
                {"role": "assistant", "content": final},
            ]
        )
        return {
            "conversation_id": conversation_id,
            "content": final,
            "tool_calls": self.orchestrator.last_tool_calls,
            "pending": self.orchestrator.last_pending,
        }
