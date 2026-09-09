"""Testes de tools/enum.py (smb_enum, subfinder_scan, enum4linux_scan).
`_run` mockado via monkeypatch — nunca toca smbclient/subfinder reais."""

import pytest

from tools import enum
from tools.enum import _validate_domain, tool_enum4linux, tool_smb_enum, tool_subfinder


@pytest.mark.parametrize("domain", ["exemplo.com", "sub.exemplo.com.br"])
def test_validate_domain_ok(domain):
    assert _validate_domain(domain) is None


@pytest.mark.parametrize("domain", ["", "-flag", "bad domain", "a"*300])
def test_validate_domain_bad(domain):
    assert _validate_domain(domain) is not None


@pytest.mark.asyncio
async def test_smb_enum_null_session_argv(monkeypatch):
    cap = {}
    async def fake_run(argv, timeout=90):
        cap["argv"] = argv
        return "Sharename\tType\tComment"
    monkeypatch.setattr(enum, "_run", fake_run)
    out = await tool_smb_enum({"host": "10.0.0.5"})
    assert "-N" in cap["argv"]
    assert "//10.0.0.5/" in cap["argv"]
    assert "Sharename" in out


@pytest.mark.asyncio
async def test_smb_enum_authenticated_argv(monkeypatch):
    cap = {}
    async def fake_run(argv, timeout=90):
        cap["argv"] = argv
        return "ok"
    monkeypatch.setattr(enum, "_run", fake_run)
    await tool_smb_enum({"host": "10.0.0.5", "username": "admin", "password": "pass"})
    assert "-U" in cap["argv"]
    assert "admin%pass" in cap["argv"]
    assert "-N" not in cap["argv"]


@pytest.mark.asyncio
async def test_smb_enum_rejects_flag_host(monkeypatch):
    async def fake_run(argv, timeout=90):
        return "ok"
    monkeypatch.setattr(enum, "_run", fake_run)
    out = await tool_smb_enum({"host": "-L//evil"})
    assert "inválido" in out.lower()


@pytest.mark.asyncio
async def test_subfinder_lists_subs(monkeypatch):
    async def fake_run(argv, timeout=90):
        return "a.exemplo.com\nb.exemplo.com\n"
    monkeypatch.setattr(enum, "_run", fake_run)
    out = await tool_subfinder({"domain": "exemplo.com"})
    assert "2 subdomínio" in out
    assert "a.exemplo.com" in out


@pytest.mark.asyncio
async def test_subfinder_empty(monkeypatch):
    async def fake_run(argv, timeout=90):
        return ""
    monkeypatch.setattr(enum, "_run", fake_run)
    out = await tool_subfinder({"domain": "exemplo.com"})
    assert "nenhum subdomínio" in out.lower()


@pytest.mark.asyncio
async def test_enum4linux_passes_host(monkeypatch):
    cap = {}
    async def fake_run(argv, timeout=90):
        cap["argv"] = argv
        return "enum output"
    monkeypatch.setattr(enum, "_run", fake_run)
    await tool_enum4linux({"host": "10.0.0.5"})
    assert cap["argv"] == ["enum4linux", "-a", "10.0.0.5"]
