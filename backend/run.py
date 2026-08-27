"""Entry point: initialize DB and launch the server.

    python backend/run.py
"""

import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

import uvicorn  # noqa: E402

from config.settings import settings  # noqa: E402
from database import db as database  # noqa: E402

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

if __name__ == "__main__":
    if settings.host not in _LOOPBACK_HOSTS and os.environ.get("I_UNDERSTAND_THE_RISK") != "1":
        # This app has no authentication layer — every tool (terminal,
        # nmap, packet capture, CPF OSINT) is reachable to whoever can
        # reach this port. HOST=127.0.0.1 + Origin/Sec-Fetch-Site checks
        # (api/main.py) are what keeps that safe. Binding elsewhere
        # (0.0.0.0, a LAN IP) removes that protection entirely.
        sys.exit(
            f"recusando iniciar: HOST={settings.host!r} não é loopback e a API não tem "
            "autenticação — qualquer um na rede poderia rodar terminal/nmap/OSINT. "
            "Use HOST=127.0.0.1 ou, se tiver certeza do risco, defina "
            "I_UNDERSTAND_THE_RISK=1."
        )
    database.init_db()
    print(f"→ DB pronto em {database.DB_PATH}")
    print(f"→ IA: {settings.ai_provider} / {settings.ai_model}")
    print(f"→ Modo de segurança: {settings.safe_mode}")
    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )
