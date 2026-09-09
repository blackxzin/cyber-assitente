"""Recon passivo via APIs de terceiros (Shodan).

Nunca toca o alvo — consulta o banco do Shodan sobre um IP já indexado.
risk=info, sem confirmação (mesmo nível de `domain_whois`/`searchsploit`).
Precisa de `SHODAN_API_KEY` no .env; sem chave devolve aviso claro.
"""

import ipaddress

import httpx

from config.settings import settings
from security.sanitize import sanitize_text

MAX_OUTPUT_CHARS = 8000
_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


def _validate_ip(value: str) -> str | None:
    value = value.strip()
    if not value:
        return "Uso: informe um 'ip' (o Shodan indexa por IP, não por domínio)."
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return f"ip inválido: {value!r} (o Shodan consulta por IP; resolva o domínio antes)."
    return None


def _format_shodan(data: dict) -> str:
    lines: list[str] = []
    ip = data.get("ip_str", "?")
    org = data.get("org") or data.get("isp") or "?"
    os_name = data.get("os") or "?"
    country = data.get("country_name") or "?"
    ports = data.get("ports") or []
    lines.append(f"Shodan {ip} — org: {org} | OS: {os_name} | país: {country}")
    if ports:
        lines.append(f"Portas abertas ({len(ports)}): " + ", ".join(str(p) for p in sorted(ports)))
    vulns = data.get("vulns") or []
    if vulns:
        lines.append("CVEs conhecidos: " + ", ".join(sorted(vulns)[:30]))
    for item in (data.get("data") or [])[:15]:
        port = item.get("port", "?")
        product = item.get("product") or ""
        version = item.get("version") or ""
        transport = item.get("transport", "")
        banner = f"{product} {version}".strip()
        lines.append(f"  {port}/{transport}  {banner}".rstrip())
    return "\n".join(lines)


async def tool_shodan_host(args: dict) -> str:
    """Consulta o Shodan sobre um IP: portas, serviços, CVEs indexados."""
    ip = str(args.get("ip") or "").strip()
    err = _validate_ip(ip)
    if err:
        return err
    if not settings.shodan_api_key:
        return ("erro: SHODAN_API_KEY não configurada. Pegue a chave em "
                "https://account.shodan.io e ponha no .env (SHODAN_API_KEY=...).")
    url = _SHODAN_HOST_URL.format(ip=ip)
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, params={"key": settings.shodan_api_key})
    except httpx.HTTPError as exc:
        return f"erro consultando Shodan: {sanitize_text(str(exc))[:300]}"
    if resp.status_code == 401:
        return "erro: chave Shodan inválida (401)."
    if resp.status_code == 404:
        return f"Shodan: nenhuma informação indexada pra {ip}."
    if resp.status_code != 200:
        return f"erro Shodan: HTTP {resp.status_code}."
    try:
        data = resp.json()
    except ValueError:
        return "erro: resposta do Shodan não é JSON."
    return sanitize_text(_format_shodan(data))[:MAX_OUTPUT_CHARS]


def register(registry) -> None:
    registry.register(
        "shodan_host",
        "Consulta o Shodan sobre um IP (portas, serviços, CVEs indexados) — "
        "recon passivo, não toca o alvo (informe 'ip'; precisa de SHODAN_API_KEY).",
        tool_shodan_host,
        risk="info", requires_confirmation=False,
        required_args=("ip",), target_arg=None, category="osint",
    )
