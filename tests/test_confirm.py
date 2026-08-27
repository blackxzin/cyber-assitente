"""Testes do fluxo de aprovação humana (backend/tools/confirm.py)."""

import asyncio

import pytest

from database import db
from security import scope
from tools.confirm import ConfirmationStore
from tools.registry import ToolSpec


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


class _FakeRegistry:
    def __init__(self, target_arg: str | None = None) -> None:
        self.called = False
        self._target_arg = target_arg

    async def run(self, tool, args):
        self.called = True
        return f"executado {tool} com {args}"

    def get(self, tool):
        return ToolSpec(tool, "desc", self.run, target_arg=self._target_arg)


async def _register(store: ConfirmationStore, timeout: float = 60):
    return await store.register(
        "nmap_scan", {"host": "10.0.0.5"}, "prompt", "summary", timeout=timeout
    )


async def test_register_creates_pending_action():
    store = ConfirmationStore()
    action = await _register(store)
    assert action.status == "pending"
    assert store.get(action.id) is action


async def test_resolve_approve_runs_tool_and_resolves_future():
    store = ConfirmationStore()
    action = await _register(store)
    text = await store.resolve(action, approve=True, registry=_FakeRegistry())
    assert action.status == "approved"
    assert "executado nmap_scan" in text
    assert action.future.done()


async def test_resolve_deny_does_not_run_tool():
    store = ConfirmationStore()
    action = await _register(store)
    registry = _FakeRegistry()
    text = await store.resolve(action, approve=False, registry=registry)
    assert action.status == "denied"
    assert "negada" in text.lower()
    assert registry.called is False


async def test_resolve_twice_is_noop_on_second_call():
    store = ConfirmationStore()
    action = await _register(store)
    await store.resolve(action, approve=True, registry=_FakeRegistry())
    second = await store.resolve(action, approve=True, registry=_FakeRegistry())
    assert "não está pendente" in second


async def test_pending_action_expires_after_timeout():
    store = ConfirmationStore()
    action = await _register(store, timeout=0.05)
    await asyncio.sleep(0.15)
    assert action.status == "expired"
    assert store.get(action.id) is None


# --- escopo autorizado: re-checado no momento da aprovação (defesa em profundidade) ---

async def test_resolve_blocks_when_scope_narrowed_after_request():
    scope.set_scope(["10.0.0.0/24"])
    store = ConfirmationStore()
    action = await _register(store)  # host 10.0.0.5, dentro do escopo no momento do register
    scope.set_scope(["192.168.0.0/24"])  # escopo mudou antes da aprovação
    registry = _FakeRegistry(target_arg="host")
    text = await store.resolve(action, approve=True, registry=registry)
    assert "fora do escopo" in text
    assert registry.called is False
    assert action.future.result() == text


async def test_resolve_allows_when_target_stays_in_scope():
    scope.set_scope(["10.0.0.0/24"])
    store = ConfirmationStore()
    action = await _register(store)
    registry = _FakeRegistry(target_arg="host")
    text = await store.resolve(action, approve=True, registry=registry)
    assert registry.called is True
    assert "executado nmap_scan" in text
