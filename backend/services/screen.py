"""Screen capture for the vision pipeline (grim on Hyprland/Wayland).

Returns a base64-encoded PNG. Falls back to a clean error if grim is missing.
"""

import asyncio
import base64

GRIM = "/usr/bin/grim"


async def capture_screen() -> str:
    """Captura o desktop e devolve PNG em base64."""
    proc = await asyncio.create_subprocess_exec(
        GRIM, "-", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
    if proc.returncode != 0 or not out:
        raise RuntimeError(f"grim falhou (rc={proc.returncode}): {err.decode(errors='ignore')[:200]}")
    return base64.b64encode(out).decode()
