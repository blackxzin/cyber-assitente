"""Testes de recon web passivo (headers, TLS, DNS).

http_headers/dns_lookup: httpx sempre mockado — nenhum teste toca rede.
tls_inspect: testa o analisador puro `analyze_cert` com um certificado
self-signed gerado em memória (sem abrir socket).
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tools import web
from tools.web import analyze_cert, analyze_http, tool_dns_lookup, tool_http_headers, tool_tls_inspect


# --- analyze_http (puro) ---

def test_analyze_http_lists_missing_security_headers():
    out = analyze_http(200, {"Server": "nginx"}, [], "http://x/", [])
    assert "FALTANDO" in out
    assert "strict-transport-security" in out
    assert "content-security-policy" in out


def test_analyze_http_reports_banner():
    out = analyze_http(200, {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4"}, [], "http://x/", [])
    assert "Apache/2.4.49" in out
    assert "PHP/7.4" in out


def test_analyze_http_all_headers_present():
    hdrs = {h: "v" for h, _ in web._SECURITY_HEADERS}
    out = analyze_http(200, hdrs, [], "https://x/", [])
    assert "todos os auditados presentes" in out


def test_analyze_http_flags_insecure_cookie():
    out = analyze_http(200, {}, ["session=abc; Path=/"], "http://x/", [])
    assert "sem Secure" in out
    assert "sem HttpOnly" in out
    assert "sem SameSite" in out


def test_analyze_http_secure_cookie_ok():
    out = analyze_http(200, {}, ["session=abc; Secure; HttpOnly; SameSite=Strict"], "https://x/", [])
    assert "[ok]" in out


def test_analyze_http_shows_redirect_chain():
    out = analyze_http(200, {}, [], "https://x/final", ["http://x/", "https://x/"])
    assert "Cadeia de redirect" in out
    assert "https://x/final" in out


# --- http_headers (httpx mockado) ---

class _FakeHeaders(dict):
    def get_list(self, key):
        return self.get("_cookies", [])


def _fake_client(status=200, headers=None, cookies=None, url="http://alvo/"):
    class FakeResp:
        def __init__(self):
            self.status_code = status
            h = _FakeHeaders(headers or {})
            h["_cookies"] = cookies or []
            self.headers = h
            self.history = []
            self.url = url

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return FakeResp()

    return FakeClient


async def test_http_headers_rejects_bad_url():
    assert "Uso:" in await tool_http_headers({"url": ""})
    assert "inválida" in await tool_http_headers({"url": "bad url com espaco"})


async def test_http_headers_runs(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient",
                        _fake_client(200, {"Server": "nginx"}, ["a=b"]))
    out = await tool_http_headers({"url": "alvo.com"})
    assert "HTTP 200" in out
    assert "nginx" in out


async def test_http_headers_handles_network_error(monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            raise httpx.ConnectError("recusou")

    monkeypatch.setattr(httpx, "AsyncClient", Boom)
    out = await tool_http_headers({"url": "alvo.com"})
    assert "erro:" in out


# --- analyze_cert (puro, cert self-signed em memória) ---

def _self_signed(cn="teste.local", days_valid=365):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=days_valid)
    not_before = min(now - timedelta(days=1), not_after - timedelta(days=1))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("alt." + cn)]), False)
        .sign(key, hashes.SHA256())
    )
    return cert


def test_analyze_cert_reports_basics():
    cert = _self_signed()
    out = analyze_cert(cert, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "teste.local", None)
    assert "TLSv1.3" in out
    assert "teste.local" in out
    assert "SHA256 fingerprint" in out
    assert "alt.teste.local" in out  # SAN


def test_analyze_cert_flags_self_signed():
    cert = _self_signed()
    out = analyze_cert(cert, "TLSv1.2", "X", "teste.local", None)
    assert "self-signed" in out


def test_analyze_cert_flags_expired():
    cert = _self_signed(days_valid=-10)
    out = analyze_cert(cert, "TLSv1.2", "X", "teste.local", None)
    assert "EXPIRADO" in out


def test_analyze_cert_shows_verify_error():
    cert = _self_signed()
    out = analyze_cert(cert, "TLSv1.2", "X", "teste.local", "self signed certificate")
    assert "VERIFICAÇÃO FALHOU" in out


async def test_tls_inspect_rejects_bad_host():
    assert "Uso:" in await tool_tls_inspect({"host": "-x"})


async def test_tls_inspect_rejects_bad_port():
    out = await tool_tls_inspect({"host": "exemplo.com", "port": 99999})
    assert "inválido" in out


# --- dns_lookup (httpx mockado) ---

def _fake_dns_client(answer_map):
    class FakeResp:
        def __init__(self, rtype):
            self._rtype = rtype

        def json(self):
            recs = answer_map.get(self._rtype, [])
            return {"Answer": [{"data": r} for r in recs]}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None, headers=None):
            return FakeResp(params["type"])

    return FakeClient


async def test_dns_lookup_rejects_bad_domain():
    assert "Uso:" in await tool_dns_lookup({"domain": "-x"})


async def test_dns_lookup_returns_records(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient",
                        _fake_dns_client({"A": ["1.2.3.4"], "MX": ["10 mail.x."]}))
    out = await tool_dns_lookup({"domain": "exemplo.com"})
    assert "1.2.3.4" in out
    assert "10 mail.x." in out


async def test_dns_lookup_specific_type(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient",
                        _fake_dns_client({"TXT": ["v=spf1 -all"]}))
    out = await tool_dns_lookup({"domain": "exemplo.com", "type": "TXT"})
    assert "v=spf1 -all" in out
    assert "A:" not in out  # só consultou TXT
