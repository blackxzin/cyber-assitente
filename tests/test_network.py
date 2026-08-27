"""Testes de backend/tools/network.py — 26% de cobertura antes desta
sessão. `ip addr`/`ip route` mockam run_safe_command; dns_servers lê
/etc/resolv.conf real (formato estável, sem mock necessário)."""

import pytest

from tools import network
from tools.network import tool_dns_servers, tool_network_interfaces, tool_network_routes


async def test_network_interfaces_parses_ip_brief_output(monkeypatch):
    async def fake(argv):
        assert argv == ["ip", "-brief", "addr"]
        return "eth0 UP 10.0.0.5/24\nlo UNKNOWN 127.0.0.1/8\n", ""

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_interfaces({})
    assert "eth0: UP — 10.0.0.5/24" in out
    assert "lo: UNKNOWN — 127.0.0.1/8" in out


async def test_network_interfaces_handles_missing_ip(monkeypatch):
    async def fake(argv):
        return "wg0 DOWN\n", ""  # sem IP nenhum atribuído

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_interfaces({})
    assert "wg0: DOWN — sem IP" in out


async def test_network_interfaces_reports_error_on_stderr(monkeypatch):
    async def fake(argv):
        return "", "ip: comando não encontrado"

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_interfaces({})
    assert out == "erro: ip: comando não encontrado"


async def test_network_interfaces_skips_blank_lines(monkeypatch):
    async def fake(argv):
        return "eth0 UP 10.0.0.5/24\n\n   \n", ""

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_interfaces({})
    assert out.count("eth0") == 1


async def test_network_routes_formats_output(monkeypatch):
    async def fake(argv):
        assert argv == ["ip", "route"]
        return "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0\n", ""

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_routes({})
    assert "Rotas:" in out
    assert "default via 10.0.0.1 dev eth0" in out


async def test_network_routes_reports_error_on_stderr(monkeypatch):
    async def fake(argv):
        return "", "erro de permissão"

    monkeypatch.setattr(network, "run_safe_command", fake)
    out = await tool_network_routes({})
    assert out == "erro: erro de permissão"


async def test_dns_servers_reads_resolv_conf(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("# comentário\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    import builtins
    real_open = builtins.open

    def fake_open(path, *a, **kw):
        if path == "/etc/resolv.conf":
            return real_open(resolv, *a, **kw)
        return real_open(path, *a, **kw)

    monkeypatch.setattr(builtins, "open", fake_open)
    out = await tool_dns_servers({})
    assert "1.1.1.1" in out
    assert "8.8.8.8" in out


async def test_dns_servers_reports_error_when_resolv_conf_missing(tmp_path, monkeypatch):
    import builtins
    real_open = builtins.open

    def fake_open(path, *a, **kw):
        if path == "/etc/resolv.conf":
            raise OSError("arquivo não existe")
        return real_open(path, *a, **kw)

    monkeypatch.setattr(builtins, "open", fake_open)
    out = await tool_dns_servers({})
    assert out.startswith("erro:")
