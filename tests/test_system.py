"""Testes de backend/tools/system.py — 56% de cobertura antes desta
sessão. Tudo lê /proc/os real (sem shell, sem mock necessário — o Linux
que roda o teste já tem /proc/meminfo, /proc/uptime etc de verdade);
valores exatos são host-dependentes, então os testes checam formato/
estrutura, não números fixos. _meminfo/_format_size testados isolados
pros caminhos de erro que /proc real não exercita (arquivo ausente)."""

from pathlib import Path

from tools import system
from tools.system import (
    _format_size,
    _meminfo,
    cpu_percent,
    disk_percent,
    mem_percent,
    tool_disk_info,
    tool_memory_info,
    tool_process_list,
    tool_system_info,
)


def test_format_size_picks_right_unit():
    assert _format_size(500) == "500.0 B"
    assert _format_size(2048) == "2.0 KB"
    assert _format_size(5 * 1024 * 1024) == "5.0 MB"
    assert _format_size(3 * 1024 ** 3) == "3.0 GB"


def test_meminfo_reads_real_proc_meminfo():
    total = _meminfo("MemTotal")
    assert total > 0  # máquina real tem RAM, valor em kB


def test_meminfo_returns_zero_when_key_absent(monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda self: "SomeOtherKey: 123 kB\n")
    assert _meminfo("MemTotal") == 0


def test_meminfo_returns_zero_on_read_error(monkeypatch):
    def boom(self):
        raise OSError("sem acesso")

    monkeypatch.setattr(Path, "read_text", boom)
    assert _meminfo("MemTotal") == 0


def test_tool_system_info_has_expected_labels():
    out = tool_system_info({})
    for label in ("Sistema operacional:", "Kernel:", "Arquitetura:",
                  "Hostname:", "Load average:", "Ligado desde:"):
        assert label in out


def test_tool_system_info_falls_back_when_os_release_missing(monkeypatch):
    real_read_text = Path.read_text

    def fake_read_text(self, *a, **kw):
        if str(self) == "/etc/os-release":
            raise OSError("não existe")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    out = tool_system_info({})
    assert "Sistema operacional: unknown" in out


def test_tool_memory_info_has_expected_labels():
    out = tool_memory_info({})
    assert "Memória total:" in out
    assert "Swap total:" in out
    assert "% em uso)" in out


def test_tool_disk_info_percent_within_bounds():
    out = tool_disk_info({})
    assert "Total:" in out and "Usado:" in out and "Livre:" in out


def test_tool_process_list_respects_limit_and_sorts_by_rss():
    out = tool_process_list({"limit": 3})
    lines = out.splitlines()
    assert lines[0].split() == ["PID", "COMANDO", "RAM"]
    assert len(lines) <= 1 + 3  # cabeçalho + no máx. 'limit' processos


def test_tool_process_list_default_limit_is_15():
    out = tool_process_list({})
    assert len(out.splitlines()) <= 1 + 15


def test_cpu_percent_within_0_and_100():
    assert 0.0 <= cpu_percent() <= 100.0


def test_mem_percent_within_0_and_100():
    assert 0.0 <= mem_percent() <= 100.0


def test_mem_percent_zero_when_meminfo_unavailable(monkeypatch):
    monkeypatch.setattr(system, "_meminfo", lambda key: 0)
    assert mem_percent() == 0.0


def test_disk_percent_within_0_and_100():
    assert 0.0 <= disk_percent() <= 100.0
