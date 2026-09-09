"""Testes de tools/recon_api.py (shodan_host). httpx mockado via monkeypatch
no cliente — nunca bate na API real do Shodan."""

import pytest

from config.settings import settings
from tools import recon_api
from tools.recon_api import _format_shodan, _validate_ip, tool_shodan_host


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_validate_ip_ok(ip):
    assert _validate_ip(ip) is None


@pytest.mark.parametrize("ip", ["", "exemplo.com", "999.999.1.1", "-flag"])
def test_validate_ip_bad(ip):
    assert _validate_ip(ip) is not None


def test_format_shodan_summary():
    data = {"ip_str": "8.8.8.8", "org": "Google", "ports": [53, 443],
            "vulns": ["CVE-2021-1234"],
            "data": [{"port": 443, "product": "nginx", "version": "1.0", "transport": "tcp"}]}
    out = _format_shodan(data)
    assert "8.8.8.8" in out and "Google" in out
    assert "53, 443" in out
    assert "CVE-2021-1234" in out
    assert "nginx" in out


@pytest.mark.asyncio
async def test_shodan_no_key(monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", "")
    out = await tool_shodan_host({"ip": "8.8.8.8"})
    assert "SHODAN_API_KEY" in out


@pytest.mark.asyncio
async def test_shodan_success(monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", "fake-key")

    class FakeResp:
        status_code = 200
        def json(self):
            return {"ip_str": "8.8.8.8", "org": "Google", "ports": [443], "data": []}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None):
            return FakeResp()

    monkeypatch.setattr(recon_api.httpx, "AsyncClient", FakeClient)
    out = await tool_shodan_host({"ip": "8.8.8.8"})
    assert "Google" in out


@pytest.mark.asyncio
async def test_shodan_404(monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", "fake-key")

    class FakeResp:
        status_code = 404
        def json(self): return {}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None): return FakeResp()

    monkeypatch.setattr(recon_api.httpx, "AsyncClient", FakeClient)
    out = await tool_shodan_host({"ip": "1.2.3.4"})
    assert "nenhuma informação" in out.lower()
