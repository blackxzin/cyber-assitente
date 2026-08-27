"""Burp Suite bridge: talks to PortSwigger's official "MCP Server" BApp
(https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc) over
the Model Context Protocol (SSE transport). Install it via Burp Suite ->
Extensions -> BApp Store -> "MCP Server", then enable it in the extension's
MCP tab (defaults to listening on 127.0.0.1:9876).

Both tools here require CONFIRMAÇÃO humana on our side (risk=moderate,
requires_confirmation=True), same as the other audit tools. The Burp
extension additionally shows its own Allow Once/Always Allow/Deny dialog
inside Burp for every send_http1_request call and every history read
(unless the target/history type was already auto-approved there) — so a
call here needs both approvals before anything happens.
"""

import json
import re
from urllib.parse import parse_qs, urlsplit

from mcp import ClientSession
from mcp.client.sse import sse_client

from config.settings import settings

_URL_RE = re.compile(r"^https?://[^\s]+$")

# --- Passive vulnerability heuristics (backend/tools/burp.py::tool_burp_find_vulnerabilities) ---
_SQLI_ERROR_RE = re.compile(
    r"sql syntax|mysql_fetch|unclosed quotation mark|sqlstate\[|"
    r"sqlite3\.operationalerror|ora-\d{5}|you have an error in your sql|"
    r"npgsql\.|postgresql.*error|pg_query\(\)",
    re.IGNORECASE,
)
_STACK_TRACE_RE = re.compile(
    r"traceback \(most recent call last\)|exception in thread|"
    r"fatal error:|stack trace:|at [a-z0-9_.]+\([a-z0-9_.]+\.java:\d+\)|"
    r"warning: (?:mysql|pg)_",
    re.IGNORECASE,
)
_SERVER_HEADER_RE = re.compile(r"^server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                      "x-frame-options", "x-content-type-options")


class BridgeUnavailable(RuntimeError):
    pass


def _text_of(result) -> str:
    return "\n".join(
        block.text for block in result.content if getattr(block, "type", None) == "text"
    )


async def _call_tool(name: str, arguments: dict) -> str:
    """Opens a short-lived MCP session against Burp's MCP Server extension,
    calls one tool, and returns its text content."""
    try:
        async with sse_client(settings.burp_mcp_url, timeout=settings.burp_mcp_timeout) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
    except BridgeUnavailable:
        raise
    except Exception as exc:
        raise BridgeUnavailable(
            f"Não consegui conectar no MCP Server do Burp ({settings.burp_mcp_url}). "
            "Confira se o Burp está aberto, a extensão 'MCP Server' (BApp Store) "
            "carregada, e habilitada na aba MCP (Enabled)."
        ) from exc
    text = _text_of(result)
    if result.is_error:
        raise BridgeUnavailable(text or "erro desconhecido do MCP Server do Burp")
    return text


def _parse_request_line(raw: str) -> tuple[str, str]:
    """Extrai (method, url) da 1a linha + header Host de uma requisição HTTP/1.1 crua."""
    lines = (raw or "").replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return "?", "?"
    parts = lines[0].split(" ", 2)
    method = parts[0] if parts else "?"
    path = parts[1] if len(parts) > 1 else "?"
    host = next(
        (line.split(":", 1)[1].strip() for line in lines[1:] if line.lower().startswith("host:")),
        "",
    )
    return method, f"{host}{path}" if host else path


_STATUS_LINE_RE = re.compile(r"HTTP/\d\.\d (\d{3})")
_SEND_RESPONSE_WRAPPER_RE = re.compile(r"httpResponse=(.*), messageAnnotations=", re.DOTALL)


def _parse_status_code(raw: str) -> str:
    match = _STATUS_LINE_RE.search(raw or "")
    return match.group(1) if match else "?"


def _clean_send_response(raw: str) -> str:
    """send_http1_request devolve o toString() do HttpRequestResponse composto
    do Montoya ('HttpRequestResponse{httpRequest=..., httpResponse=...,
    messageAnnotations=...}'), diferente do texto HTTP cru do proxy history.
    Extrai só a parte da resposta quando reconhece o formato."""
    match = _SEND_RESPONSE_WRAPPER_RE.search(raw or "")
    return match.group(1) if match else raw


async def tool_burp_proxy_history(args: dict) -> str:
    """Últimas requisições capturadas pelo Proxy history do Burp."""
    try:
        limit = max(1, min(int(args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        return "Uso: 'limit' precisa ser um número (ex: limit=50)."
    try:
        text = await _call_tool("get_proxy_http_history", {"count": limit, "offset": 0})
    except BridgeUnavailable as exc:
        return f"erro: {exc}"
    if "denied by Burp Suite" in text:
        return "erro: acesso ao HTTP history negado no Burp (dialog Allow/Deny)."

    lines: list[str] = []
    for chunk in text.split("\n\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            item = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        method, url = _parse_request_line(item.get("request") or "")
        status = _parse_status_code(item.get("response") or "")
        lines.append(f"  [{status}] {method} {url}")

    if not lines:
        return "Proxy history do Burp está vazio (nenhuma requisição capturada ainda)."
    return f"Últimas {len(lines)} requisição(ões) no Proxy do Burp:\n" + "\n".join(lines)


async def tool_burp_search_history(args: dict) -> str:
    """Busca no Proxy history do Burp por um termo (em vez de listar tudo
    e o usuário procurar manualmente). Pagina o history até achar
    'max_results' ocorrências ou esgotar 'max_pages'."""
    query = str(args.get("query") or "").strip().lower()
    if not query:
        return "Uso: informe 'query' (termo a buscar no method/url/status do history)."
    try:
        max_results = max(1, min(int(args.get("max_results", 20)), 100))
        max_pages = max(1, min(int(args.get("max_pages", 5)), 20))
    except (TypeError, ValueError):
        return "Uso: 'max_results' e 'max_pages' precisam ser números."

    page_size = 100
    matches: list[str] = []
    scanned = 0
    for page in range(max_pages):
        try:
            text = await _call_tool(
                "get_proxy_http_history", {"count": page_size, "offset": page * page_size}
            )
        except BridgeUnavailable as exc:
            return f"erro: {exc}"
        if "denied by Burp Suite" in text:
            return "erro: acesso ao HTTP history negado no Burp (dialog Allow/Deny)."

        chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
        if not chunks:
            break
        for chunk in chunks:
            try:
                item = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            scanned += 1
            method, url = _parse_request_line(item.get("request") or "")
            status = _parse_status_code(item.get("response") or "")
            line = f"[{status}] {method} {url}"
            if query in line.lower():
                matches.append(f"  {line}")
                if len(matches) >= max_results:
                    break
        if len(matches) >= max_results or len(chunks) < page_size:
            break

    if not matches:
        return f"Busca '{query}' no Burp: 0 resultados (varreu {scanned} requisição(ões))."
    return (
        f"Busca '{query}' no Burp: {len(matches)} resultado(s) "
        f"(varreu {scanned} requisição(ões)):\n" + "\n".join(matches)
    )


def _scan_item_for_vulns(request_raw: str, response_raw: str) -> list[str]:
    """Heurísticas passivas sobre um par request/response cru do Burp.
    Não é o Burp Scanner (Pro) — é um raio-x rápido pra não precisar
    ler cada requisição na mão procurando sinal de vulnerabilidade."""
    findings: list[str] = []
    resp = response_raw or ""

    if _SQLI_ERROR_RE.search(resp):
        findings.append("possível SQL injection — erro de banco refletido na resposta")
    if _STACK_TRACE_RE.search(resp):
        findings.append("stack trace / erro verboso exposto na resposta")

    for line in resp.splitlines():
        if line.lower().startswith("set-cookie"):
            low = line.lower()
            missing = [f for f in ("secure", "httponly") if f not in low]
            if missing:
                findings.append(f"cookie sem flag {'/'.join(missing)}: {line.strip()[:80]}")

    server = _SERVER_HEADER_RE.search(resp)
    if server and re.search(r"\d", server.group(1)):
        findings.append(f"banner de servidor com versão exposta: {server.group(1).strip()[:80]}")

    header_block = resp.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0].lower()
    if "content-type: text/html" in header_block:
        missing_sec = [h for h in _SECURITY_HEADERS if h not in header_block]
        if len(missing_sec) == len(_SECURITY_HEADERS):
            findings.append("nenhum header de segurança (CSP/HSTS/X-Frame-Options/X-Content-Type-Options)")

    first_line = (request_raw or "").replace("\r\n", "\n").split("\n", 1)[0]
    path = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""
    for key, values in parse_qs(urlsplit(path).query).items():
        for v in values:
            if len(v) >= 4 and v in resp:
                findings.append(f"parâmetro '{key}' refletido sem encode na resposta (possível XSS)")
                break

    return findings


async def tool_burp_find_vulnerabilities(args: dict) -> str:
    """Varre o Proxy history do Burp com heurísticas passivas (SQLi refletido,
    stack trace exposto, cookie sem Secure/HttpOnly, banner de versão, XSS
    refletido, ausência de headers de segurança) — em vez do usuário ler
    requisição por requisição procurando isso na mão."""
    try:
        max_pages = max(1, min(int(args.get("max_pages", 5)), 20))
    except (TypeError, ValueError):
        return "Uso: 'max_pages' precisa ser um número."

    page_size = 100
    flagged: list[str] = []
    scanned = 0
    for page in range(max_pages):
        try:
            text = await _call_tool(
                "get_proxy_http_history", {"count": page_size, "offset": page * page_size}
            )
        except BridgeUnavailable as exc:
            return f"erro: {exc}"
        if "denied by Burp Suite" in text:
            return "erro: acesso ao HTTP history negado no Burp (dialog Allow/Deny)."

        chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
        if not chunks:
            break
        for chunk in chunks:
            try:
                item = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            scanned += 1
            request_raw = item.get("request") or ""
            response_raw = item.get("response") or ""
            findings = _scan_item_for_vulns(request_raw, response_raw)
            if findings:
                method, url = _parse_request_line(request_raw)
                status = _parse_status_code(response_raw)
                flagged.append(
                    f"  [{status}] {method} {url}\n" + "\n".join(f"    - {f}" for f in findings)
                )
        if len(chunks) < page_size:
            break

    if not flagged:
        return f"Varredura passiva no Burp: nenhum achado em {scanned} requisição(ões)."
    return (
        f"Varredura passiva no Burp: {len(flagged)} requisição(ões) com achado(s) "
        f"de {scanned} varrida(s):\n" + "\n".join(flagged[:50])
    )


async def tool_burp_send_request(args: dict) -> str:
    """Envia uma requisição HTTP através do Burp (mesmo motor do Repeater)."""
    url = str(args.get("url") or "").strip()
    if not url:
        return "Uso: informe uma 'url' (http:// ou https://) para enviar a requisição."
    if not _URL_RE.match(url):
        return f"url inválida: {url!r} (precisa começar com http:// ou https://)."
    if not urlsplit(url).hostname:
        return f"url inválida: {url!r} (sem host)."
    method = str(args.get("method") or "GET").strip().upper()
    body = str(args.get("body") or "")

    parts = urlsplit(url)
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"

    raw_headers = args.get("headers")
    headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
    if not any(k.lower() == "host" for k in headers):
        headers = {"Host": parts.hostname, **headers}
    if body and not any(k.lower() == "content-length" for k in headers):
        headers["Content-Length"] = str(len(body.encode("utf-8")))

    header_block = "\n".join(f"{k}: {v}" for k, v in headers.items())
    content = f"{method} {path} HTTP/1.1\n{header_block}\n\n{body}"

    try:
        text = await _call_tool(
            "send_http1_request",
            {
                "content": content,
                "targetHostname": parts.hostname,
                "targetPort": port,
                "usesHttps": https,
            },
        )
    except BridgeUnavailable as exc:
        return f"erro: {exc}"
    if text.startswith("Send HTTP request denied"):
        return f"erro: requisição negada no Burp (dialog Allow/Deny) para {parts.hostname}:{port}."

    status = _parse_status_code(text)
    body = _clean_send_response(text)
    return f"Resposta HTTP {status} de {method} {url}:\n\n{body[:4000]}"


def register(registry) -> None:
    for name, desc, fn, required in (
        ("burp_proxy_history", "Lista as últimas requisições capturadas no Proxy history do Burp Suite ('limit' opcional).", tool_burp_proxy_history, ()),
        ("burp_search_history", "Busca um termo no Proxy history do Burp (informe 'query'; 'max_results' e 'max_pages' opcionais) — evita procurar na mão.", tool_burp_search_history, ("query",)),
        ("burp_find_vulnerabilities", "Varre o Proxy history do Burp procurando vulnerabilidades (SQLi refletido, XSS refletido, cookie inseguro, banner de versão, stack trace, headers de segurança ausentes). 'max_pages' opcional.", tool_burp_find_vulnerabilities, ()),
        ("burp_send_request", "Envia uma requisição HTTP através do Burp Suite, como no Repeater (informe 'url'; 'method', 'headers' e 'body' opcionais).", tool_burp_send_request, ("url",)),
    ):
        registry.register(name, desc, fn, risk="moderate", requires_confirmation=True, required_args=required)
