"""Testes do LearningAgent (backend/agents/learning_agent.py): extração de
conceito, tracking de progresso e adaptação da explicação em repetições."""

import pytest

from agents.base import AgentContext
from agents.learning_agent import LearningAgent, _extract_concept
from database import db


class _ScriptedProvider:
    def __init__(self, reply: str = "explicação estruturada") -> None:
        self.reply = reply
        self.calls: list[dict] = []

    async def complete(self, messages: list[dict], **extra) -> str:
        self.calls.append({"messages": messages, "extra": extra})
        return self.reply


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_extract_concept_drops_stopwords_and_keeps_the_topic():
    concept = _extract_concept("o que é um firewall?")
    assert "firewall" in concept
    assert "que" not in concept.split()


async def test_first_question_logs_progress_and_flags_basico():
    provider = _ScriptedProvider()
    agent = LearningAgent(provider)
    await agent.run(AgentContext(prompt="explica o que é firewall"))

    progress = db.learning_progress()
    assert len(progress) == 1
    assert progress[0]["times_asked"] == 1
    sent = provider.calls[0]["messages"][0]["content"]
    assert "comece do básico" in sent


async def test_repeated_question_bumps_counter_and_flags_review():
    provider = _ScriptedProvider()
    agent = LearningAgent(provider)
    await agent.run(AgentContext(prompt="explica o que é firewall"))
    await agent.run(AgentContext(prompt="explica o que é firewall"))

    progress = db.learning_progress()
    assert len(progress) == 1
    assert progress[0]["times_asked"] == 2
    sent = provider.calls[1]["messages"][0]["content"]
    assert "já perguntou sobre isso antes" in sent


async def test_prompt_structure_requests_all_four_sections():
    provider = _ScriptedProvider()
    agent = LearningAgent(provider)
    await agent.run(AgentContext(prompt="explica o que é vpn"))
    sent = provider.calls[0]["messages"][0]["content"]
    for section in ("**Conceito**", "**Exemplo prático**", "**Cuidado**", "**Pergunta pra fixar**"):
        assert section in sent
