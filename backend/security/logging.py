"""Auditoria em arquivo via stdlib logging.

Camada ADICIONAL ao database.insert_security_event (SQLite): o arquivo
logs/security.log retém eventos independente do banco. Tudo é sanitizado
antes de gravar (security/sanitize.py).
"""

import json
import logging
import logging.handlers
from functools import lru_cache

from config.settings import LOG_DIR
from security.sanitize import sanitize_text

_MAX_BYTES = 1024 * 1024
_BACKUP_COUNT = 5
_RESULT_TRUNCATE = 500


@lru_cache(maxsize=1)
def _get_logger() -> logging.Logger:
    """Logger raiz 'cyber' com RotatingFileHandler em LOG_DIR/security.log."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "security.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(module)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    logger = logging.getLogger("cyber")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_event(level: str, category: str, message: str) -> None:
    """Registra um evento sanitizado (level: info|warning|danger)."""
    _get_logger().log(
        getattr(logging, level.upper(), logging.INFO),
        "%s %s",
        category,
        sanitize_text(message),
    )


def log_tool(category: str, **fields) -> None:
    """Registra evento estruturado de ferramenta; campos sanitizados."""
    safe = {
        k: (sanitize_text(v) if isinstance(v, str) else v)
        for k, v in fields.items()
    }
    if isinstance(safe.get("result"), str) and len(safe["result"]) > _RESULT_TRUNCATE:
        safe["result"] = safe["result"][:_RESULT_TRUNCATE] + "...[truncado]"
    _get_logger().info(
        "%s %s",
        category,
        json.dumps(safe, ensure_ascii=False, default=str),
    )
