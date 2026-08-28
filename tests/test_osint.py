"""Testes de validação de entrada e execução em backend/tools/osint.py.

`_run` (holehe/sherlock) e a chamada de rede (crt.sh)/whois são sempre
mockadas — nenhum teste aqui toca binário real ou rede externa.
"""

import json

import httpx
import pytest

from tools import osint
from tools.osint import (
    _validate_domain,
    _validate_email,
    _validate_username,
    tool_domain_whois,
    tool_email_osint,
    tool_subdomain_enum,
    tool_username_osint,
)


# --- validators ---

@pytest.mark.parametrize("email", ["a@b.com", "nome.sobrenome@dominio.com.br", "x+tag@sub.dominio.io"])
def test_validate_email_accepts_valid(email):
    assert _validate_email(email) is None


@pytest.mark.parametrize("email", ["", "   ", "-T", "nao-e-email", "@dominio.com", "a@b"])
def test_validate_email_rejects_invalid(email):
    assert _validate_email(email) is not None


@pytest.mark.parametrize("username", ["fulano", "fulano_123", "fulano.beltrano", "a-b-c"])
def test_validate_username_accepts_valid(username):
    assert _validate_username(username) is None


@pytest.mark.parametrize("username", ["", "   ", "-print-all", "nome com espaco", "a" * 40])
def test_validate_username_rejects_invalid(username):
    assert _validate_username(username) is not None


@pytest.mark.parametrize("domain", ["exemplo.com", "sub.exemplo.com.br", "a-b.io"])
def test_validate_domain_accepts_valid(domain):
    assert _validate_domain(domain) is None


@pytest.mark.parametrize("domain", ["", "   ", "-q", "dominio com espaco"])
def test_validate_domain_rejects_invalid(domain):
    assert _validate_domain(domain) is not None


# --- email_osint ---

async def test_email_osint_rejects_invalid_email():
    result = await tool_email_osint({"email": "nao-e-email"})
    assert result.startswith("email inválido") or result.startswith("Uso:")


async def test_email_osint_runs_holehe(monkeypatch):
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return "holehe output"

    monkeypatch.setattr(osint, "_run", fake_run)
    result = await tool_email_osint({"email": "alvo@exemplo.com"})
    assert result == "holehe output"
    assert captured["argv"][1:] == ["alvo@exemplo.com", "--no-color", "--no-clear", "-T", "20"]
    assert captured["timeout"] == 120


# --- username_osint ---

async def test_username_osint_rejects_invalid_username():
    result = await tool_username_osint({"username": "-print-all"})
    assert result.startswith("username inválido") or result.startswith("Uso:")


async def test_username_osint_runs_sherlock(monkeypatch):
    captured = {}

    async def fake_run(argv, timeout=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return "sherlock output"

    monkeypatch.setattr(osint, "_run", fake_run)
    result = await tool_username_osint({"username": "fulano123"})
    assert result == "sherlock output"
    assert captured["argv"][1:] == ["fulano123", "--print-found", "--no-color", "--timeout", "15"]
    assert captured["timeout"] == 150


# --- domain_whois ---

async def test_domain_whois_rejects_invalid_domain():
    result = await tool_domain_whois({"domain": "-q"})
    assert result.startswith("domain inválido") or result.startswith("Uso:")


async def test_domain_whois_formats_known_fields(monkeypatch):
    class FakeWhois(dict):
        pass

    fake_data = FakeWhois(domain_name="EXEMPLO.COM", registrar="Registrar Inc", org=None)

    class FakePyWhois:
        @staticmethod
        def whois(domain):
            assert domain == "exemplo.com"
            return fake_data

    monkeypatch.setitem(__import__("sys").modules, "whois", FakePyWhois)
    result = await tool_domain_whois({"domain": "exemplo.com"})
    assert "WHOIS exemplo.com:" in result
    assert "domain_name: EXEMPLO.COM" in result
    assert "registrar: Registrar Inc" in result
    assert "org:" not in result


async def test_domain_whois_handles_lookup_failure(monkeypatch):
    class FakePyWhois:
        @staticmethod
        def whois(domain):
            raise ConnectionError("boom")

    monkeypatch.setitem(__import__("sys").modules, "whois", FakePyWhois)
    result = await tool_domain_whois({"domain": "exemplo.com"})
    assert result.startswith("erro:")


# --- subdomain_enum ---

async def test_subdomain_enum_rejects_invalid_domain():
    result = await tool_subdomain_enum({"domain": ""})
    assert result.startswith("domain inválido") or result.startswith("Uso:")


async def test_subdomain_enum_dedupes_and_filters(monkeypatch):
    payload = [
        {"name_value": "www.exemplo.com\napi.exemplo.com"},
        {"name_value": "*.exemplo.com"},
        {"name_value": "www.exemplo.com"},
        {"name_value": "outro.com"},
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return payload

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await tool_subdomain_enum({"domain": "exemplo.com"})
    assert "www.exemplo.com" in result
    assert "api.exemplo.com" in result
    assert "exemplo.com" in result  # from bare wildcard entry
    assert "outro.com" not in result
    assert result.count("www.exemplo.com") == 1


async def test_subdomain_enum_handles_http_error(monkeypatch):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            raise httpx.ConnectTimeout("timeout")

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await tool_subdomain_enum({"domain": "exemplo.com"})
    assert result.startswith("erro:")


async def test_subdomain_enum_handles_non_200(monkeypatch):
    class FakeResponse:
        status_code = 503

        def json(self):
            return []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await tool_subdomain_enum({"domain": "exemplo.com"})
    assert result.startswith("erro:")
