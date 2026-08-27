"""Testes das ferramentas de ponte com o Burp Suite (backend/tools/burp.py).

Sem Burp real nem rede: monkeypatch em burp._call_tool, o único ponto que
fala com o MCP Server via SSE. Cobre parsing de request/response cru e os
caminhos de erro (bridge indisponível, request/history negada no Burp).
"""

import pytest

from tools import burp
from tools.burp import BridgeUnavailable


async def test_proxy_history_missing_arg_uses_default_limit(monkeypatch):
    captured = {}

    async def fake_call_tool(name, arguments):
        captured["name"] = name
        captured["arguments"] = arguments
        item = (
            '{"request": "GET /y HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n", '
            '"response": "HTTP/1.1 200 OK\\r\\n\\r\\n", "notes": null}'
        )
        return item

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_proxy_history({})
    assert "[200] GET x/y" in result
    assert captured["name"] == "get_proxy_http_history"
    assert captured["arguments"] == {"count": 50, "offset": 0}


async def test_proxy_history_empty_result_is_friendly(monkeypatch):
    async def fake_call_tool(name, arguments):
        return "Reached end of items"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_proxy_history({})
    assert "vazio" in result


async def test_proxy_history_denied_in_burp_returns_error(monkeypatch):
    async def fake_call_tool(name, arguments):
        return "HTTP history access denied by Burp Suite"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_proxy_history({})
    assert result.startswith("erro:")
    assert "negado no Burp" in result


async def test_send_request_rejects_invalid_url():
    result = await burp.tool_burp_send_request({"url": "not-a-url"})
    assert "url inválida" in result


async def test_send_request_requires_url():
    result = await burp.tool_burp_send_request({})
    assert "Uso" in result


async def test_send_request_success(monkeypatch):
    captured = {}

    async def fake_call_tool(name, arguments):
        captured["name"] = name
        captured["arguments"] = arguments
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_send_request({"url": "https://alvo.example/rota"})
    assert "Resposta HTTP 200" in result
    assert "ok" in result
    assert captured["name"] == "send_http1_request"
    assert captured["arguments"]["targetHostname"] == "alvo.example"
    assert captured["arguments"]["targetPort"] == 443
    assert captured["arguments"]["usesHttps"] is True
    assert captured["arguments"]["content"].startswith("GET /rota HTTP/1.1\n")


async def test_send_request_denied_in_burp_returns_error(monkeypatch):
    async def fake_call_tool(name, arguments):
        return "Send HTTP request denied by Burp Suite"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_send_request({"url": "https://alvo.example/rota"})
    assert result.startswith("erro:")
    assert "negada no Burp" in result


async def test_bridge_unreachable_returns_friendly_error(monkeypatch):
    async def fake_call_tool(name, arguments):
        raise BridgeUnavailable("Não consegui conectar no MCP Server do Burp (x).")

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_proxy_history({})
    assert "erro: Não consegui conectar no MCP Server do Burp" in result


def _item(request_line: str, response: str, host: str = "alvo.example") -> str:
    request = f"{request_line} HTTP/1.1\\r\\nHost: {host}\\r\\n\\r\\n"
    return '{"request": "%s", "response": "%s", "notes": null}' % (
        request, response.replace("\n", "\\r\\n").replace('"', '\\"')
    )


# --- burp_search_history ---

async def test_search_history_requires_query():
    result = await burp.tool_burp_search_history({})
    assert result.startswith("Uso:")


async def test_search_history_finds_match_across_pages(monkeypatch):
    calls = []

    async def fake_call_tool(name, arguments):
        calls.append(arguments)
        if arguments["offset"] == 0:
            return "\n\n".join([_item("GET /a", "HTTP/1.1 200 OK\n\n")] * 100)
        return _item("GET /admin/login", "HTTP/1.1 200 OK\n\n")

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_search_history({"query": "admin"})
    assert "1 resultado" in result
    assert "/admin/login" in result
    assert len(calls) == 2  # paginou até achar


async def test_search_history_no_match_reports_zero(monkeypatch):
    async def fake_call_tool(name, arguments):
        return _item("GET /a", "HTTP/1.1 200 OK\n\n")

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_search_history({"query": "nao-existe-isso"})
    assert "0 resultados" in result


async def test_search_history_denied_in_burp_returns_error(monkeypatch):
    async def fake_call_tool(name, arguments):
        return "HTTP history access denied by Burp Suite"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_search_history({"query": "x"})
    assert result.startswith("erro:")


# --- _scan_item_for_vulns (heurísticas) ---

def test_scan_detects_sqli_error_in_response():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 500\n\nyou have an error in your sql syntax"
    )
    assert any("SQL injection" in f for f in findings)


def test_scan_detects_stack_trace():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 500\n\nTraceback (most recent call last):"
    )
    assert any("stack trace" in f for f in findings)


def test_scan_detects_insecure_cookie():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 200\nSet-Cookie: sess=abc\n\nok"
    )
    assert any("cookie sem flag" in f and "secure" in f and "httponly" in f for f in findings)


def test_scan_ignores_cookie_with_both_flags():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 200\nSet-Cookie: sess=abc; Secure; HttpOnly\n\nok"
    )
    assert not any("cookie sem flag" in f for f in findings)


def test_scan_detects_server_version_banner():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 200\nServer: nginx/1.18.0\n\nok"
    )
    assert any("banner de servidor" in f and "nginx/1.18.0" in f for f in findings)


def test_scan_detects_missing_security_headers_on_html():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1", "HTTP/1.1 200\nContent-Type: text/html\n\n<html></html>"
    )
    assert any("header de segurança" in f for f in findings)


def test_scan_detects_reflected_xss():
    findings = burp._scan_item_for_vulns(
        "GET /search?q=<script>x</script> HTTP/1.1",
        "HTTP/1.1 200\nContent-Type: text/html\n\n<html><script>x</script></html>",
    )
    assert any("refletido" in f and "q" in f for f in findings)


def test_scan_clean_response_has_no_findings():
    findings = burp._scan_item_for_vulns(
        "GET /x HTTP/1.1",
        "HTTP/1.1 200\nContent-Type: application/json\n\n{\"ok\": true}",
    )
    assert findings == []


# --- burp_find_vulnerabilities ---

async def test_find_vulnerabilities_flags_and_reports(monkeypatch):
    async def fake_call_tool(name, arguments):
        return _item(
            "GET /login",
            "HTTP/1.1 500\nSet-Cookie: sess=1\n\nyou have an error in your sql syntax",
        )

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_find_vulnerabilities({"max_pages": 1})
    assert "1 requisição" in result
    assert "SQL injection" in result
    assert "/login" in result


async def test_find_vulnerabilities_clean_history_reports_no_findings(monkeypatch):
    async def fake_call_tool(name, arguments):
        return _item("GET /ping", "HTTP/1.1 200\nContent-Type: application/json\n\n{}")

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_find_vulnerabilities({"max_pages": 1})
    assert "nenhum achado" in result


async def test_find_vulnerabilities_denied_in_burp_returns_error(monkeypatch):
    async def fake_call_tool(name, arguments):
        return "HTTP history access denied by Burp Suite"

    monkeypatch.setattr(burp, "_call_tool", fake_call_tool)
    result = await burp.tool_burp_find_vulnerabilities({})
    assert result.startswith("erro:")
