"""Background security watcher.

Runs on a timer while the app is up: diffs local listening sockets since
the last tick (new port = alert), watches disk usage against a threshold,
and purges old cpf_osint results (data-retention). Every finding also
fires a desktop notification — see services/notify.py.

Started from api/main.py on FastAPI startup; cancelled on shutdown.
"""

import asyncio
import re

from config.settings import settings
from database import db as database
from security.logging import log_event
from services.diffing import new_lines
from services.notify import notify_desktop
from tools.system import disk_percent
from tools.terminal import executor

_LISTEN_RE = re.compile(r"^\S+\s+LISTEN\s+\S+\s+\S+\s+\S+:\S+\s+\S+.*$", re.MULTILINE)


async def _check_local_ports() -> None:
    out, _err = await executor.run_safe_command(["ss", "-tulnp"])
    previous = database.get_snapshot("local_ports", "ss")
    if previous is not None:
        opened = new_lines(previous, out, _LISTEN_RE)
        if opened:
            joined = "\n".join(opened)
            database.insert_alert(
                "medium",
                "Nova(s) porta(s) local(is) escutando",
                joined,
            )
            await notify_desktop("Cyber — nova porta local", joined.splitlines()[0])
    database.save_snapshot("local_ports", "ss", out)


async def _check_disk() -> None:
    pct = disk_percent()
    was_over = database.get_snapshot("flag", "disk_alert") == "active"
    is_over = pct >= settings.disk_alert_percent
    if is_over and not was_over:
        msg = f"Disco em {pct}% (limite {settings.disk_alert_percent}%)."
        database.insert_alert("high", "Disco quase cheio", msg)
        await notify_desktop("Cyber — disco quase cheio", msg)
    database.save_snapshot("flag", "disk_alert", "active" if is_over else "clear")


async def _purge_osint() -> None:
    removed = database.purge_old_tool_calls("cpf_osint", settings.osint_retention_days)
    if removed:
        log_event("info", "watcher", f"cpf_osint: {removed} registro(s) além de "
                  f"{settings.osint_retention_days} dias removido(s).")


async def tick() -> None:
    """Run one watch cycle; each check is isolated so one failure doesn't
    block the others."""
    for check in (_check_local_ports, _check_disk, _purge_osint):
        try:
            await check()
        except Exception as exc:
            log_event("warning", "watcher", f"{check.__name__} falhou: {exc}")


async def run_forever() -> None:
    while True:
        await tick()
        await asyncio.sleep(settings.watcher_interval_seconds)
