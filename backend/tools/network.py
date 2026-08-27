"""Read-only network tools.

`ip addr` / `ip route` run through the Safety Layer executor so they are
logged and constrained; everything else reads /proc or /sys directly.
"""

from tools.registry import ToolRegistry
from tools.terminal.executor import run_safe_command


async def tool_network_interfaces(args: dict) -> str:
    out, err = await run_safe_command(["ip", "-brief", "addr"])
    if err and not out:
        return f"erro: {err}"
    lines = ["Interfaces de rede:"]
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            iface, status = parts[0], parts[1]
            ip = parts[2] if len(parts) > 2 else "sem IP"
            lines.append(f"  {iface}: {status} — {ip}")
    return "\n".join(lines)


async def tool_network_routes(args: dict) -> str:
    out, err = await run_safe_command(["ip", "route"])
    if err and not out:
        return f"erro: {err}"
    return "Rotas:\n" + "\n".join(f"  {line}" for line in out.splitlines() if line.strip())


async def tool_dns_servers(args: dict) -> str:
    nameservers: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    nameservers.append(line.split()[-1])
    except OSError as exc:
        return f"erro: {exc}"
    return "Servidores DNS:\n" + "\n".join(f"  {ns}" for ns in nameservers) or "  (nenhum encontrado)"


def register(registry: ToolRegistry) -> None:
    registry.register(
        "network_interfaces",
        "Lista as interfaces de rede e seus IPs.",
        tool_network_interfaces,
        risk="info",
        requires_confirmation=False,
    )
    registry.register(
        "network_routes",
        "Mostra as rotas da tabela de roteamento.",
        tool_network_routes,
        risk="info",
        requires_confirmation=False,
    )
    registry.register(
        "dns_servers",
        "Lista os servidores DNS configurados.",
        tool_dns_servers,
        risk="info",
        requires_confirmation=False,
    )
