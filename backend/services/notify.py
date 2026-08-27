"""Desktop notification (notify-send) — best-effort, never raises.

Used by the watcher to surface high-severity alerts without the user
having to have the chat open.
"""

import asyncio


async def notify_desktop(title: str, message: str) -> None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "notify-send", "-a", "Cyber", title, message,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except OSError:
        pass  # notify-send indisponível/sem permissão (ex: sem sessão gráfica) — não é fatal
