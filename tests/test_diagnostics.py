"""Testes de backend/tools/diagnostics.py — 0% de cobertura de tool antes
desta sessão (só o resultado de local_ports aparecia indiretamente via
watcher). local_ports/systemd_services mockam run_safe_command;
connectivity usa socket real contra 127.0.0.1 (sem DNS, hermético);
recent_logs usa DB isolado."""

import socket

import pytest

from database import db
from tools import diagnostics
from tools.diagnostics import (
    tool_connectivity,
    tool_local_ports,
    tool_recent_logs,
    tool_systemd_services,
)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


async def test_local_ports_formats_ss_output(monkeypatch):
    async def fake(argv):
        assert argv == ["ss", "-tulnp"]
        return "tcp LISTEN 0 128 0.0.0.0:22 *:*\n", ""

    monkeypatch.setattr(diagnostics, "run_safe_command", fake)
    out = await tool_local_ports({})
    assert "Portas locais em escuta" in out
    assert "0.0.0.0:22" in out


async def test_local_ports_returns_error_on_stderr_with_no_stdout(monkeypatch):
    async def fake(argv):
        return "", "ss: comando falhou"

    monkeypatch.setattr(diagnostics, "run_safe_command", fake)
    out = await tool_local_ports({})
    assert out == "erro: ss: comando falhou"


async def test_systemd_services_formats_output(monkeypatch):
    async def fake(argv):
        assert argv[0] == "systemctl"
        assert "--state=running" in argv
        return "sshd.service loaded active running OpenSSH\n", ""

    monkeypatch.setattr(diagnostics, "run_safe_command", fake)
    out = await tool_systemd_services({})
    assert "Serviços systemd em execução" in out
    assert "sshd.service" in out


async def test_connectivity_requires_host():
    result = await tool_connectivity({})
    assert result.startswith("Uso:")


async def test_connectivity_reports_dns_failure(monkeypatch):
    def fake_getaddrinfo(*a, **kw):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = await tool_connectivity({"host": "nao-resolve.invalid"})
    assert "Falha de resolução de DNS" in result


async def test_connectivity_succeeds_against_local_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        result = await tool_connectivity({"host": "127.0.0.1", "port": port})
        assert "conectou em" in result
        assert f"127.0.0.1:{port}" in result
    finally:
        srv.close()


async def test_connectivity_reports_refused_connection():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()  # fecha sem escutar — porta livre, ninguém aceita conexão

    result = await tool_connectivity({"host": "127.0.0.1", "port": port})
    assert "sem resposta" in result


async def test_recent_logs_empty_by_default():
    result = await tool_recent_logs({})
    assert result == "Nenhum evento de segurança registrado ainda."


async def test_recent_logs_lists_recent_events_newest_first():
    db.insert_security_event("info", "terminal", "comando executado: ip addr")
    db.insert_security_event("warning", "scope", "alvo fora do escopo")
    result = await tool_recent_logs({})
    idx_scope = result.index("alvo fora do escopo")
    idx_terminal = result.index("comando executado")
    assert idx_scope < idx_terminal  # o mais recente (scope) vem primeiro


async def test_recent_logs_respects_limit():
    for i in range(5):
        db.insert_security_event("info", "test", f"evento {i}")
    result = await tool_recent_logs({"limit": 2})
    # "eventos" no cabeçalho contém "evento" como substring — conta linha, não substring solta.
    assert len(result.splitlines()) == 1 + 2  # cabeçalho + 2 linhas de evento
    assert "evento 4" in result and "evento 3" in result
    assert "evento 2" not in result
