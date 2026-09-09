"""Enumeração de host/serviço: SMB (smbclient), subdomínios ativos
(subfinder) e enum4linux.

`smb_enum`/`enum4linux_scan` tocam o alvo (autenticação/consulta de shares)
→ risk=moderate, confirmação humana, target_arg=host, mesmo padrão das
ofensivas de `tools/pentest.py`. `subfinder_scan` só consulta APIs públicas
de subdomínio (passivo por padrão) → risk=info, sem confirmação, como o
`subdomain_enum` (crt.sh) que já existe.
"""

import re

from tools.pentest import _run, _validate_target

MAX_OUTPUT_CHARS = 8000
_DOMAIN_RE = re.compile(r"^[0-9a-zA-Z.-]{1,253}$")


def _validate_domain(domain: str) -> str | None:
    domain = domain.strip()
    if not domain or domain.startswith("-"):
        return "Uso: informe um 'domain' (ex: exemplo.com)."
    if not _DOMAIN_RE.fullmatch(domain):
        return f"domain inválido: {domain!r}"
    return None


async def tool_smb_enum(args: dict) -> str:
    """Lista shares SMB de um host via smbclient (sessão nula por padrão).

    'username'/'password' opcionais pra sessão autenticada; sem eles usa -N
    (null session), que muitos servidores mal-configurados aceitam.
    """
    host = str(args.get("host") or "").strip()
    err = _validate_target(host)
    if err:
        return err
    argv = ["smbclient", "-L", f"//{host}/", "-g"]
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    if username:
        argv += ["-U", f"{username}%{password}"]
    else:
        argv += ["-N"]
    out = await _run(argv, timeout=60)
    if out.startswith("erro"):
        return out
    return out or f"smb_enum em {host}: sem shares listados (ou acesso negado)."


async def tool_subfinder(args: dict) -> str:
    """Enumera subdomínios de um domínio via subfinder (fontes passivas)."""
    domain = str(args.get("domain") or "").strip()
    err = _validate_domain(domain)
    if err:
        return err
    out = await _run(["subfinder", "-d", domain, "-silent", "-all"], timeout=120)
    if out.startswith("erro"):
        return out
    subs = [line.strip() for line in out.splitlines() if line.strip()]
    if not subs:
        return f"subfinder em {domain}: nenhum subdomínio encontrado."
    body = "\n".join(f"  {s}" for s in subs[:200])
    extra = len(subs) - 200
    if extra > 0:
        body += f"\n  ...(+{extra} subdomínios)"
    return f"subfinder em {domain} — {len(subs)} subdomínio(s):\n" + body


async def tool_enum4linux(args: dict) -> str:
    """Enumeração SMB/Samba completa (usuários, shares, políticas) com enum4linux."""
    host = str(args.get("host") or "").strip()
    err = _validate_target(host)
    if err:
        return err
    out = await _run(["enum4linux", "-a", host], timeout=180)
    if out.startswith("erro"):
        return out
    return out or f"enum4linux em {host}: sem saída."


def register(registry) -> None:
    registry.register(
        "smb_enum",
        "Lista shares SMB de um host com smbclient (informe 'host'; "
        "'username'/'password' opcionais, senão usa sessão nula).",
        tool_smb_enum,
        risk="moderate", requires_confirmation=True,
        required_args=("host",), target_arg="host", category="ofensivo",
    )
    registry.register(
        "enum4linux_scan",
        "Enumeração SMB/Samba completa (usuários, shares, políticas) com "
        "enum4linux (informe 'host').",
        tool_enum4linux,
        risk="moderate", requires_confirmation=True,
        required_args=("host",), target_arg="host", category="ofensivo",
    )
    registry.register(
        "subfinder_scan",
        "Enumera subdomínios de um domínio via subfinder, fontes passivas "
        "(informe 'domain'). Não toca o alvo — consulta APIs públicas.",
        tool_subfinder,
        risk="info", requires_confirmation=False,
        required_args=("domain",), target_arg=None, category="osint",
    )
