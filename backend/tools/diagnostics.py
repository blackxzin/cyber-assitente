"""Ferramentas de diagnóstico read-only.

Dados vêm de `ss`/`systemctl` via executor (allowlist) e do próprio SQLite
(sem shell). Nenhuma escrita, nenhuma alteração de sistema.
"""

import socket
import time

from database import db as database
from tools.terminal.executor import run_safe_command


async def tool_local_ports(args: dict) -> str:
    """Portas TCP/UDP em escuta via ss (read-only, allowlist)."""
    out, err = await run_safe_command(["ss", "-tulnp"])
    if err and not out:
        return f"erro: {err}"
    return "Portas locais em escuta (TCP/UDP):\n" + "\n".join(
        f"  {line}" for line in out.splitlines() if line.strip()
    )


async def tool_systemd_services(args: dict) -> str:
    """Serviços systemd ativos via systemctl list-units (leitura pura)."""
    out, err = await run_safe_command(
        ["systemctl", "--no-pager", "--plain", "list-units",
         "--type=service", "--state=running"]
    )
    if err and not out:
        return f"erro: {err}"
    return "Serviços systemd em execução:\n" + "\n".join(
        f"  {line}" for line in out.splitlines() if line.strip()
    )


async def tool_connectivity(args: dict) -> str:
    """Conectividade TCP via socket (sem shell; host vem do usuário/LLM)."""
    host = str(args.get("host") or "").strip()
    if not host:
        return "Uso: informe um host (IP ou nome) para o teste de conectividade."
    port = int(args.get("port", 80))
    lines = [f"Testando conectividade com {host}:{port} (timeout 3s):"]
    # Resolução de nome sem tocar o shell.
    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return f"{lines[0]}\n  Falha de resolução de DNS: {exc}"
    for family, stype, proto, _, addr in addrinfo[:2]:
        try:
            sock = socket.socket(family, stype, proto)
            sock.settimeout(3)
            t0 = time.monotonic()
            result = sock.connect_ex(addr)
            latency = round((time.monotonic() - t0) * 1000, 1)
            sock.close()
            if result == 0:
                lines.append(f"  {addr[0]}:{port} — conectou em {latency} ms")
            else:
                lines.append(f"  {addr[0]}:{port} — sem resposta (código {result})")
        except OSError as exc:
            lines.append(f"  {addr[0]}:{port} — erro: {exc}")
    return "\n".join(lines)


async def tool_recent_logs(args: dict) -> str:
    """Últimos eventos de segurança do próprio banco (zero shell)."""
    limit = max(1, min(int(args.get("limit", 10)), 50))
    with database.db() as conn:
        rows = conn.execute(
            "SELECT level, category, description, created_at "
            "FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    if not rows:
        return "Nenhum evento de segurança registrado ainda."
    lines = ["Últimos eventos de segurança:"]
    for r in rows:
        lines.append(f"  {r['created_at']} [{r['level']}] {r['category']}: {r['description']}")
    return "\n".join(lines)


def register(registry) -> None:
    for name, desc, fn in (
        ("local_ports", "Lista as portas TCP/UDP locais em escuta no sistema.", tool_local_ports),
        ("systemd_services", "Lista os serviços systemd atualmente em execução.", tool_systemd_services),
        ("connectivity", "Testa conectividade TCP com um host (informe 'host'; porta opcional).", tool_connectivity),
        ("recent_logs", "Mostra os últimos eventos de segurança registrados no banco.", tool_recent_logs),
    ):
        required = ("host",) if name == "connectivity" else ()
        registry.register(name, desc, fn, risk="info", requires_confirmation=False,
                          required_args=required, category="diagnóstico")
