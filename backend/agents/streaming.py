"""Shared LLM generation helper.

`stream_or_complete` is the single seam every user-facing final answer goes
through. With no callback it behaves exactly like `provider.complete` (used
by tests and non-streaming callers). With an `on_delta` callback it streams
tokens from `provider.stream_chat`, invoking the callback with the FULL text
accumulated so far after each token — the SSE layer forwards that straight to
the browser, which repaints the growing answer live instead of waiting for the
whole completion (critical on slow local CPU models where a single answer can
take a minute).
"""

from typing import Awaitable, Callable

from ai.providers.base import LLMProvider

OnDelta = Callable[[str], Awaitable[None]]


async def stream_or_complete(
    provider: LLMProvider,
    messages: list[dict[str, str]],
    on_delta: OnDelta | None = None,
    **extra: object,
) -> str:
    """Return the final answer text; stream it live when on_delta is given."""
    if on_delta is None:
        return (await provider.complete(messages, **extra)).strip()
    acc = ""
    async for delta in provider.stream_chat(messages, **extra):
        if not delta:
            continue
        acc += delta
        try:
            await on_delta(acc)
        except Exception:
            # A dropped client must never crash generation.
            pass
    return acc.strip()
