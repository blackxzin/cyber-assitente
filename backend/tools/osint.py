"""Ferramentas de OSINT sobre identidades e domínios (email, username,
domínio) — recon passivo/semi-ativo, sem alvo de rede direto.

`email_osint`/`username_osint` batem em dezenas/centenas de sites de
terceiros (holehe/sherlock) pra checar cadastro/presença — mesmo nível de
risco do `cpf_osint` existente (moderate, confirmação humana). `domain_whois`
e `subdomain_enum` são consultas passivas a serviços públicos (registro
WHOIS, certificate transparency do crt.sh) que nunca tocam o alvo — mesmo
padrão do `searchsploit_lookup` (info, sem confirmação).
"""

import asyncio
import json
import re
import sys

from pathlib import Path

import httpx

from security.sanitize import sanitize_text
from tools.pentest import _run

MAX_OUTPUT_CHARS = 8000
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")
_DOMAIN_RE = re.compile(r"^[0-9a-zA-Z.-]{1,253}$")
_WHOIS_FIELDS = (
    "domain_name", "registrar", "creation_date",
    "expiration_date", "name_servers", "emails", "org", "country",
)


def _venv_script(name: str) -> str:
    """Resolve console-script instalado no mesmo venv do backend.

    holehe/sherlock ficam em `.venv/bin/`, que não está necessariamente no
    PATH do processo do servidor (rodado direto via `.venv/bin/python`, sem
    ativar o venv) — resolve pelo diretório do próprio interpretador em vez
    de confiar em PATH.
    """
    candidate = Path(sys.executable).parent / name
    return str(candidate) if candidate.is_file() else name


def _validate_email(email: str) -> str | None:
    email = email.strip()
    if not email or email.startswith("-"):
        return "Uso: informe um 'email' válido (ex: nome@dominio.com)."
    if not _EMAIL_RE.fullmatch(email):
        return f"email inválido: {email!r}"
    return None


def _validate_username(username: str) -> str | None:
    username = username.strip()
    if not username or username.startswith("-"):
        return "Uso: informe um 'username' pra buscar em redes sociais."
    if not _USERNAME_RE.fullmatch(username):
        return f"username inválido: {username!r}"
    return None


def _validate_domain(domain: str) -> str | None:
    domain = domain.strip()
    if not domain or domain.startswith("-"):
        return "Uso: informe um 'domain' (ex: exemplo.com)."
    if not _DOMAIN_RE.fullmatch(domain):
        return f"domain inválido: {domain!r}"
    return None


async def tool_email_osint(args: dict) -> str:
    """Descobre em quais sites um email está cadastrado, via holehe."""
    email = str(args.get("email") or "").strip()
    err = _validate_email(email)
    if err:
        return err
    argv = [_venv_script("holehe"), email, "--no-color", "--no-clear", "-T", "20"]
    out = await _run(argv, timeout=120)
    return out or f"holehe em {email}: sem saída."


async def tool_username_osint(args: dict) -> str:
    """Busca um username em centenas de redes sociais/plataformas, via sherlock."""
    username = str(args.get("username") or "").strip()
    err = _validate_username(username)
    if err:
        return err
    argv = [_venv_script("sherlock"), username, "--print-found", "--no-color", "--timeout", "15"]
    out = await _run(argv, timeout=150)
    return out or f"sherlock em {username}: sem saída."


async def tool_domain_whois(args: dict) -> str:
    """Consulta WHOIS de um domínio (registrante, datas, nameservers)."""
    domain = str(args.get("domain") or "").strip()
    err = _validate_domain(domain)
    if err:
        return err
    try:
        import whois as pywhois
    except ImportError:
        return "erro: biblioteca python-whois não instalada."
    try:
        data = await asyncio.wait_for(asyncio.to_thread(pywhois.whois, domain), timeout=20)
    except asyncio.TimeoutError:
        return f"erro: whois de {domain} excedeu 20s."
    except Exception as exc:
        return f"erro: whois falhou pra {domain}: {sanitize_text(str(exc))[:400]}"
    lines = [f"WHOIS {domain}:"]
    for field in _WHOIS_FIELDS:
        value = data.get(field) if isinstance(data, dict) else getattr(data, field, None)
        if value:
            lines.append(f"  {field}: {value}")
    if len(lines) == 1:
        return f"whois de {domain}: sem dados encontrados."
    return "\n".join(lines)[:MAX_OUTPUT_CHARS]


async def tool_subdomain_enum(args: dict) -> str:
    """Enumera subdomínios via certificate transparency (crt.sh) — passivo,
    não envia tráfego ao alvo."""
    domain = str(args.get("domain") or "").strip()
    err = _validate_domain(domain)
    if err:
        return err
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    except httpx.HTTPError as exc:
        return f"erro: falha consultando crt.sh: {sanitize_text(str(exc))[:400]}"
    if resp.status_code != 200:
        return f"erro: crt.sh retornou HTTP {resp.status_code}."
    try:
        entries = resp.json()
    except json.JSONDecodeError:
        return "erro: crt.sh não retornou JSON válido."
    subdomains: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lstrip("*.")
            if name and name.endswith(domain):
                subdomains.add(name)
    if not subdomains:
        return f"subdomain_enum {domain}: nenhum subdomínio encontrado (crt.sh)."
    body = "\n".join(f"  {s}" for s in sorted(subdomains))
    return f"Subdomínios de {domain} ({len(subdomains)}, via crt.sh):\n{body}"[:MAX_OUTPUT_CHARS]


def register(registry) -> None:
    for name, desc, fn, risk, required, confirm in (
        ("email_osint", "Descobre em quais sites um email está cadastrado, via holehe (informe 'email').", tool_email_osint, "moderate", ("email",), True),
        ("username_osint", "Busca um username em centenas de redes sociais, via sherlock (informe 'username').", tool_username_osint, "moderate", ("username",), True),
        ("domain_whois", "Consulta WHOIS de um domínio: registrante, datas, nameservers (informe 'domain').", tool_domain_whois, "info", ("domain",), False),
        ("subdomain_enum", "Enumera subdomínios via certificate transparency, sem tocar o alvo (informe 'domain').", tool_subdomain_enum, "info", ("domain",), False),
    ):
        registry.register(name, desc, fn, risk=risk, requires_confirmation=confirm,
                          required_args=required, target_arg=None, category="osint")
