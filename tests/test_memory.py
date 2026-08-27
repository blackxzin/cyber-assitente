"""Testes da memória longa: persistência (backend/database/db.py) e as
tools 'remember'/'recall' (backend/tools/memory.py)."""

import pytest

from database import db
from tools.memory import tool_recall, tool_remember


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_insert_and_list_memory_roundtrip():
    db.insert_memory("usuário prefere respostas curtas")
    facts = db.list_memory()
    assert len(facts) == 1
    assert facts[0]["content"] == "usuário prefere respostas curtas"
    assert facts[0]["kind"] == "fact"


def test_list_memory_respects_limit_and_newest_first():
    for i in range(5):
        db.insert_memory(f"fato {i}")
    facts = db.list_memory(limit=3)
    assert len(facts) == 3
    assert facts[0]["content"] == "fato 4"  # newest first


def test_delete_memory_removes_row_and_reports_result():
    memory_id = db.insert_memory("fato descartável")
    assert db.delete_memory(memory_id) is True
    assert db.list_memory() == []
    assert db.delete_memory(memory_id) is False  # already gone


async def test_tool_remember_stores_content_and_confirms():
    result = await tool_remember({"content": "host de produção é 10.0.0.5"})
    assert "10.0.0.5" in result
    assert len(db.list_memory()) == 1


async def test_tool_remember_redacts_secrets_before_persisting():
    await tool_remember({"content": "a chave da api é sk-ant-api03-abcdefghijklmnopqrstuvwxyz"})
    stored = db.list_memory()[0]["content"]
    assert "sk-ant-api03" not in stored
    assert "REDACTED" in stored


async def test_tool_remember_rejects_empty_content():
    result = await tool_remember({"content": "   "})
    assert "vazio" in result.lower()
    assert db.list_memory() == []


async def test_tool_recall_lists_saved_facts():
    await tool_remember({"content": "host de produção é 10.0.0.5"})
    await tool_remember({"content": "backup roda às 3h"})
    result = await tool_recall({})
    assert "10.0.0.5" in result
    assert "backup" in result


async def test_tool_recall_filters_by_query():
    await tool_remember({"content": "host de produção é 10.0.0.5"})
    await tool_remember({"content": "backup roda às 3h"})
    result = await tool_recall({"query": "backup"})
    assert "backup" in result
    assert "10.0.0.5" not in result


async def test_tool_recall_reports_when_nothing_saved():
    result = await tool_recall({})
    assert "nenhum fato" in result.lower()
