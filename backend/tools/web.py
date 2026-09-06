"""Recon web/rede passivo, sem binário externo: fingerprint de headers HTTP,
inspeção de certificado/TLS e resolução DNS. httpx e ssl/cryptography já são
dependências do projeto — então essas ferramentas rodam em qualquer máquina,
diferente das que dependem de nmap/sqlmap/etc instalados.

`http_headers` faz um único GET no alvo (barato, como abrir no navegador) e
audita banners, headers de segurança e flags de cookie. `tls_inspect` abre
um handshake TLS e lê o certificado. `dns_lookup` consulta um resolver
público via DNS-over-HTTPS (não fala direto com a infra do alvo).
"""

import re
import socket
import ssl

import httpx

from security.sanitize import sanitize_text
from tools.pentest import _normalize_url, _validate_url

MAX_OUTPUT_CHARS = 8000
_HOST_RE = re.compile(r"^[0-9a-zA-Z.-]{1,253}$")

# Headers de segurança auditados: header -> por que importa se faltar.
_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "sem HSTS: downgrade pra HTTP / SSL strip"),
    ("content-security-policy", "sem CSP: XSS mais fácil de explorar"),
    ("x-frame-options", "sem X-Frame-Options/CSP frame-ancestors: clickjacking"),
    ("x-content-type-options", "sem nosniff: MIME sniffing"),
    ("referrer-policy", "sem Referrer-Policy: vazamento de URL no Referer"),
    ("permissions-policy", "sem Permissions-Policy: sem restrição de APIs do browser"),
)
# Banners que entregam tecnologia/versão (bom pra correlacionar exploit).
_BANNER_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "x-drupal-cache", "x-runtime",
)


def analyze_http(status: int, headers: dict, cookies: list[str],
                 final_url: str, redirects: list[str]) -> str:
    """Monta o laudo de um response HTTP. Função pura — recebe dados já
    coletados, não faz rede, então testável isolada."""
    # normaliza chaves de header pra minúsculas
    hl = {k.lower(): v for k, v in headers.items()}
    lines = [f"HTTP {status} — {final_url}"]

    if redirects:
        lines.append("Cadeia de redirect: " + " -> ".join(redirects + [final_url]))

    banners = [(h, hl[h]) for h in _BANNER_HEADERS if h in hl]
    if banners:
        lines.append("")
        lines.append("Banners (tecnologia/versão):")
        lines.extend(f"  {h}: {v}" for h, v in banners)

    missing = [(h, why) for h, why in _SECURITY_HEADERS if h not in hl]
    present = [h for h, _ in _SECURITY_HEADERS if h in hl]
    lines.append("")
    lines.append("Headers de segurança:")
    if present:
        lines.append("  presentes: " + ", ".join(present))
    if missing:
        lines.append("  FALTANDO:")
        lines.extend(f"    - {h} ({why})" for h, why in missing)
    else:
        lines.append("  todos os auditados presentes.")

    if cookies:
        lines.append("")
        lines.append("Cookies:")
        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            flags = []
            if "secure" not in low:
                flags.append("sem Secure")
            if "httponly" not in low:
                flags.append("sem HttpOnly")
            if "samesite" not in low:
                flags.append("sem SameSite")
            note = f" [{', '.join(flags)}]" if flags else " [ok]"
            lines.append(f"  {name}{note}")

    return "\n".join(lines)[:MAX_OUTPUT_CHARS]


async def tool_http_headers(args: dict) -> str:
    """GET único no alvo e laudo de banners/headers de segurança/cookies."""
    url = _normalize_url(str(args.get("url") or ""))
    err = _validate_url(url)
    if err:
        return err
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberRecon/1.0)"}
    try:
        # verify=False é proposital: recon de pentest precisa fingerprintar
        # alvos com cert self-signed/expirado/hostname errado (comum em infra
        # interna) — recusar handshake aí seria pior. Não transmitimos segredo,
        # só lemos headers do alvo.
        async with httpx.AsyncClient(follow_redirects=True, timeout=15,
                                     verify=False, headers=headers) as client:  # noqa: S501  # nosec B501
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return f"erro: falha ao acessar {url}: {sanitize_text(str(exc))[:400]}"
    redirects = [str(r.url) for r in resp.history]
    # httpx junta Set-Cookie múltiplos; pega a lista crua dos headers.
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    return analyze_http(resp.status_code, dict(resp.headers), cookies,
                        str(resp.url), redirects)


def analyze_cert(cert, tls_version: str, cipher: str, host: str,
                 verify_error: str | None) -> str:
    """Monta o laudo de um certificado x509 (objeto cryptography) + params da
    conexão. Função pura, testável isolada."""
    from cryptography.x509 import DNSName
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID

    def _name(name, oid):
        try:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else "?"
        except Exception:
            return "?"

    lines = [f"TLS de {host}:"]
    lines.append(f"  protocolo: {tls_version}")
    lines.append(f"  cipher: {cipher}")
    if verify_error:
        lines.append(f"  VERIFICAÇÃO FALHOU: {verify_error}")

    subj_cn = _name(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _name(cert.issuer, NameOID.ORGANIZATION_NAME)
    lines.append(f"  subject CN: {subj_cn}")
    lines.append(f"  issuer: {issuer_cn} / {issuer_org}")

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days
    lines.append(f"  válido: {not_before:%Y-%m-%d} a {not_after:%Y-%m-%d} "
                 f"({days_left} dias restantes)")
    if days_left < 0:
        lines.append("  ALERTA: certificado EXPIRADO.")
    elif days_left < 15:
        lines.append("  ALERTA: expira em menos de 15 dias.")
    if issuer_cn == subj_cn:
        lines.append("  ALERTA: possível certificado self-signed (issuer == subject).")

    from cryptography.x509 import ExtensionNotFound
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(DNSName)
        if sans:
            lines.append("  SANs: " + ", ".join(sans[:20]))
    except ExtensionNotFound:
        pass  # cert sem SAN — só reporta o resto

    fp = cert.fingerprint(hashes.SHA256()).hex()
    lines.append(f"  SHA256 fingerprint: {fp}")

    return "\n".join(lines)[:MAX_OUTPUT_CHARS]


async def tool_tls_inspect(args: dict) -> str:
    """Abre handshake TLS no host:porta e reporta cert + protocolo/cipher."""
    import asyncio

    host = str(args.get("host") or "").strip()
    if "://" in host:
        from urllib.parse import urlsplit
        host = urlsplit(host).hostname or host
    if not host or host.startswith("-") or not _HOST_RE.fullmatch(host):
        return "Uso: informe um 'host' (ex: exemplo.com); 'port' opcional (padrão 443)."
    try:
        port = int(args.get("port") or 443)
    except (TypeError, ValueError):
        return "port inválido: informe um número."
    if not (0 < port < 65536):
        return f"port inválido: {port}."

    def _fetch():
        from cryptography import x509
        # contexto que NÃO verifica — pra conseguir ler cert mesmo se
        # self-signed/expirado; a verificação é reportada separado.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version() or "?"
                cipher = (ssock.cipher() or ("?",))[0]
        cert = x509.load_der_x509_certificate(der)
        # segunda passada só pra saber se verificaria de verdade
        verify_error = None
        vctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=10) as s2:
                with vctx.wrap_socket(s2, server_hostname=host):
                    pass
        except ssl.SSLCertVerificationError as exc:
            verify_error = str(getattr(exc, "verify_message", exc) or exc)
        except (ssl.SSLError, OSError):
            pass
        return cert, tls_version, cipher, verify_error

    try:
        cert, tls_version, cipher, verify_error = await asyncio.wait_for(
            asyncio.to_thread(_fetch), timeout=25)
    except asyncio.TimeoutError:
        return f"erro: TLS de {host}:{port} excedeu o tempo limite."
    except (OSError, ssl.SSLError) as exc:
        return f"erro: falha no handshake TLS com {host}:{port}: {sanitize_text(str(exc))[:300]}"
    return analyze_cert(cert, tls_version, cipher, host, verify_error)


_DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


async def tool_dns_lookup(args: dict) -> str:
    """Resolve registros DNS via DNS-over-HTTPS (Cloudflare) — não fala direto
    com a infra do alvo. Consulta A/AAAA/MX/TXT/NS/CNAME/SOA, ou o 'type' dado."""
    domain = str(args.get("domain") or "").strip().rstrip(".")
    if not domain or domain.startswith("-") or not _HOST_RE.fullmatch(domain):
        return "Uso: informe um 'domain' (ex: exemplo.com); 'type' opcional."
    want = str(args.get("type") or "").strip().upper()
    types = (want,) if want in _DNS_TYPES else _DNS_TYPES

    lines = [f"DNS de {domain} (via DoH Cloudflare):"]
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            for rtype in types:
                try:
                    resp = await client.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": domain, "type": rtype},
                        headers={"accept": "application/dns-json"})
                    data = resp.json()
                except (httpx.HTTPError, ValueError):
                    lines.append(f"  {rtype}: erro na consulta")
                    continue
                answers = data.get("Answer") or []
                records = [a.get("data", "") for a in answers if a.get("data")]
                if records:
                    lines.append(f"  {rtype}: " + ", ".join(records[:20]))
                elif want:
                    lines.append(f"  {rtype}: nenhum registro")
    except httpx.HTTPError as exc:
        return f"erro: falha consultando DoH: {sanitize_text(str(exc))[:300]}"
    if len(lines) == 1:
        return f"dns_lookup {domain}: nenhum registro encontrado."
    return "\n".join(lines)[:MAX_OUTPUT_CHARS]


def register(registry) -> None:
    registry.register(
        "http_headers",
        "Faz um GET no alvo e audita banners de tecnologia, headers de segurança (HSTS/CSP/X-Frame/etc) e flags de cookie (informe 'url').",
        tool_http_headers, risk="info", requires_confirmation=False,
        required_args=("url",), target_arg="url", category="web")
    registry.register(
        "tls_inspect",
        "Abre TLS no host e reporta certificado (issuer/validade/SANs/fingerprint) e protocolo/cipher; flag pra expirado/self-signed (informe 'host'; 'port' opcional).",
        tool_tls_inspect, risk="info", requires_confirmation=False,
        required_args=("host",), target_arg="host", category="web")
    registry.register(
        "dns_lookup",
        "Resolve registros DNS (A/AAAA/MX/TXT/NS/CNAME/SOA) via DNS-over-HTTPS, sem tocar o alvo (informe 'domain'; 'type' opcional).",
        tool_dns_lookup, risk="info", requires_confirmation=False,
        required_args=("domain",), target_arg=None, category="web")
