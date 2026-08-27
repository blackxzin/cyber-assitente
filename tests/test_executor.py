"""Testes do PlanExecutor (backend/agents/executor.py): execução sequencial
de passos, parada em confirmação pendente, e tratamento de erros/args
faltantes por passo."""

import pytest

from agents.executor import PlanExecutor
from config.settings import settings
from database import db
from security import scope
from tools.confirm import ConfirmationStore
from tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def _registry() -> ToolRegistry:
    reg = ToolRegistry()

    async def _ok(args: dict) -> str:
        return f"ok:{args}"

    async def _boom(args: dict) -> str:
        raise RuntimeError("falhou de propósito")

    reg.register("connectivity", "Testa conectividade.", _ok,
                  risk="info", requires_confirmation=False, required_args=("host",),
                  target_arg="host")
    reg.register("nmap_scan", "Escaneia um host.", _ok,
                  risk="moderate", requires_confirmation=True, required_args=("host",),
                  target_arg="host")
    reg.register("flaky", "Sempre falha.", _boom,
                  risk="info", requires_confirmation=False)
    return reg


async def test_executes_all_steps_when_none_need_confirmation():
    steps = [
        {"id": 1, "description": "d1", "tool": "connectivity", "args": {"host": "8.8.8.8"}},
        {"id": 2, "description": "d2", "tool": "connectivity", "args": {"host": "1.1.1.1"}},
    ]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert pending is None
    assert [r.status for r in results] == ["ok", "ok"]
    assert "8.8.8.8" in results[0].output


async def test_stops_and_returns_pending_on_confirmable_step():
    steps = [
        {"id": 1, "description": "d1", "tool": "connectivity", "args": {"host": "8.8.8.8"}},
        {"id": 2, "description": "escaneia", "tool": "nmap_scan", "args": {"host": "8.8.8.8"}},
        {"id": 3, "description": "d3", "tool": "connectivity", "args": {"host": "1.1.1.1"}},
    ]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert len(results) == 1  # step 3 never runs — executor stopped at step 2
    assert pending is not None
    assert pending["tool"] == "nmap_scan"
    assert pending["step_id"] == 2


async def test_step_without_tool_is_marked_skipped():
    steps = [{"id": 1, "description": "só um comentário", "tool": None, "args": {}}]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert pending is None
    assert results[0].status == "skipped"


async def test_unknown_tool_name_produces_error_result():
    steps = [{"id": 1, "description": "d", "tool": "does_not_exist", "args": {}}]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert results[0].status == "error"
    assert "não encontrada" in results[0].output


async def test_missing_required_args_produces_missing_args_result_without_running():
    steps = [{"id": 1, "description": "d", "tool": "connectivity", "args": {}}]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert results[0].status == "missing_args"
    assert "host" in results[0].output


async def test_tool_exception_is_captured_as_error_result_not_raised():
    steps = [{"id": 1, "description": "d", "tool": "flaky", "args": {}}]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert results[0].status == "error"
    assert "falhou de propósito" in results[0].output


async def test_advanced_safe_mode_runs_confirmable_step_without_stopping(monkeypatch):
    monkeypatch.setattr(settings, "safe_mode", "advanced")
    steps = [
        {"id": 1, "description": "escaneia", "tool": "nmap_scan", "args": {"host": "8.8.8.8"}},
        {"id": 2, "description": "d2", "tool": "connectivity", "args": {"host": "1.1.1.1"}},
    ]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert pending is None  # plano inteiro roda sem parar pra aprovação humana
    assert [r.status for r in results] == ["ok", "ok"]


# --- escopo autorizado ---

async def test_step_out_of_scope_marked_blocked_and_execution_continues():
    scope.set_scope(["10.0.0.0/24"])
    steps = [
        {"id": 1, "description": "escaneia fora do escopo", "tool": "nmap_scan", "args": {"host": "8.8.8.8"}},
        {"id": 2, "description": "d2", "tool": "connectivity", "args": {"host": "10.0.0.5"}},
    ]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert pending is None
    assert results[0].status == "blocked"
    assert "fora do escopo" in results[0].output
    assert results[1].status == "ok"  # próximo passo (in-scope) roda normalmente


async def test_step_out_of_scope_blocked_even_in_advanced_mode(monkeypatch):
    monkeypatch.setattr(settings, "safe_mode", "advanced")
    scope.set_scope(["10.0.0.0/24"])
    steps = [{"id": 1, "description": "d", "tool": "nmap_scan", "args": {"host": "8.8.8.8"}}]
    executor = PlanExecutor(_registry(), ConfirmationStore())
    results, pending = await executor.execute(steps)
    assert results[0].status == "blocked"
