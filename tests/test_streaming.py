"""Testa o seam de geração (backend/agents/streaming.py): sem callback vira
`complete`; com callback, faz streaming e entrega snapshots ACUMULADOS."""

import pytest
from agents.streaming import stream_or_complete


class _StreamingProvider:
    def __init__(self, chunks):
        self.chunks = chunks
        self.stream_calls = 0
        self.complete_calls = 0

    async def stream_chat(self, messages, **extra):
        self.stream_calls += 1
        for c in self.chunks:
            yield c

    async def complete(self, messages, **extra):
        self.complete_calls += 1
        return "".join(self.chunks)


async def test_without_callback_uses_complete():
    p = _StreamingProvider(["Olá", " mundo"])
    out = await stream_or_complete(p, [{"role": "user", "content": "oi"}])
    assert out == "Olá mundo"
    assert p.complete_calls == 1 and p.stream_calls == 0


async def test_with_callback_streams_growing_snapshots():
    p = _StreamingProvider(["Con", "ce", "ito"])
    seen: list[str] = []

    async def on_delta(text_so_far: str) -> None:
        seen.append(text_so_far)

    out = await stream_or_complete(p, [{"role": "user", "content": "oi"}], on_delta)
    assert out == "Conceito"
    assert p.stream_calls == 1 and p.complete_calls == 0
    # cada snapshot é o texto ACUMULADO até ali (o que o frontend repinta)
    assert seen == ["Con", "Conce", "Conceito"]


async def test_callback_errors_do_not_crash_generation():
    p = _StreamingProvider(["a", "b", "c"])

    async def bad_delta(_):
        raise RuntimeError("cliente caiu")

    out = await stream_or_complete(p, [{"role": "user", "content": "x"}], bad_delta)
    assert out == "abc"  # geração completa mesmo com callback quebrado


async def test_empty_deltas_are_skipped():
    p = _StreamingProvider(["", "a", "", "b"])
    seen: list[str] = []

    async def on_delta(t):
        seen.append(t)

    out = await stream_or_complete(p, [{"role": "user", "content": "x"}], on_delta)
    assert out == "ab"
    assert seen == ["a", "ab"]
