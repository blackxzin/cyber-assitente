"""Read-only system information tools (stdlib only).

Every tool returns plain text ready to be explained by the LLM.
Data comes from /proc so nothing external is executed.
"""

import os
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path

from config.settings import ROOT


def _format_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def _meminfo(key: str) -> int:
    """Read a MemTotal-style value from /proc/meminfo (in kB)."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith(key):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def tool_system_info(args: dict) -> str:
    os_name = "unknown"
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
                break
    except OSError:
        pass

    uname = os.uname()
    loadavg = os.getloadavg()
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    booted = datetime.now() - timedelta(seconds=uptime)
    return "\n".join([
        f"Sistema operacional: {os_name}",
        f"Kernel: {uname.release}",
        f"Arquitetura: {uname.machine}",
        f"Hostname: {uname.nodename}",
        f"Usuário: {os.environ.get('USER', '?')}",
        f"Load average: {', '.join(f'{x:.2f}' for x in loadavg)}",
        f"Ligado desde: {booted.strftime('%Y-%m-%d %H:%M:%S')}",
    ])


def cpu_percent() -> float:
    """Aproxima uso de CPU via load average de 1min / núcleos."""
    ncpu = os.cpu_count() or 1
    load1 = os.getloadavg()[0]
    return round(min(load1 / ncpu, 1.0) * 100, 1)


def mem_percent() -> float:
    mem_total = _meminfo("MemTotal")
    mem_available = _meminfo("MemAvailable")
    if not mem_total:
        return 0.0
    return round((1 - mem_available / mem_total) * 100, 1)


def disk_percent() -> float:
    total, used, _free = shutil.disk_usage(ROOT)
    return round(used / total * 100, 1) if total else 0.0


def tool_memory_info(args: dict) -> str:
    mem_total = _meminfo("MemTotal") * 1024
    mem_available = _meminfo("MemAvailable") * 1024
    swap_total = _meminfo("SwapTotal") * 1024
    swap_free = _meminfo("SwapFree") * 1024
    used_pct = round((1 - mem_available / mem_total) * 100, 1) if mem_total else 0
    return "\n".join([
        f"Memória total: {_format_size(mem_total)}",
        f"Memória disponível: {_format_size(mem_available)} ({used_pct}% em uso)",
        f"Swap total: {_format_size(swap_total)}",
        f"Swap livre: {_format_size(swap_free)}",
    ])


def tool_disk_info(args: dict) -> str:
    total, used, free = shutil.disk_usage(ROOT)
    percent = round(used / total * 100, 1) if total else 0
    return "\n".join([
        f"Disco (raiz do projeto {ROOT}):",
        f"  Total: {_format_size(total)}",
        f"  Usado: {_format_size(used)} ({percent}%)",
        f"  Livre: {_format_size(free)}",
    ])


def tool_process_list(args: dict) -> str:
    limit = int(args.get("limit", 15))
    processes: list[tuple[str, int, str]] = []  # (comm, rss_bytes, pid)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(errors="ignore")
            comm = stat[stat.index("(") + 1: stat.index(")")]
            rest = stat.rsplit(")", 1)[1].split()
            rss_pages = int(rest[22])  # field 24 = RSS (pages), after comm
            processes.append((comm, rss_pages * os.sysconf("SC_PAGE_SIZE"), entry.name))
        except (OSError, ValueError, IndexError):
            continue
    processes.sort(key=lambda p: p[1], reverse=True)
    lines = [f"{'PID':>8}  {'COMANDO':<25}  {'RAM':>10}"]
    for comm, rss, pid in processes[:limit]:
        lines.append(f"{pid:>8}  {comm[:25]:<25}  {_format_size(rss):>10}")
    return "\n".join(lines)


def register(registry) -> None:
    registry.register(
        "system_info",
        "Informações do sistema (SO, kernel, hostname, uptime, load).",
        tool_system_info,
        risk="info",
        requires_confirmation=False,
    )
    registry.register(
        "memory_info",
        "Uso de memória RAM e swap.",
        tool_memory_info,
        risk="info",
        requires_confirmation=False,
    )
    registry.register(
        "disk_info",
        "Uso de disco.",
        tool_disk_info,
        risk="info",
        requires_confirmation=False,
    )
    registry.register(
        "process_list",
        "Lista os processos com maior uso de memória.",
        tool_process_list,
        risk="info",
        requires_confirmation=False,
    )
