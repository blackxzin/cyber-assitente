"""SQLite persistence layer.

Schema is modeled to migrate cleanly to PostgreSQL later: one table per
domain area, timestamps in UTC ISO-8601 text, integer primary keys.
Uses only the standard library so there are zero runtime dependencies.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from config.settings import DB_PATH, DATA_DIR, LOG_DIR

_LOCK = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT 'Nova conversa',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id),
    role TEXT NOT NULL CHECK (role IN ('user','assistant','system','tool')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER REFERENCES messages(id),
    tool TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    result TEXT NOT NULL DEFAULT '',
    risk TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'ok',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL CHECK (level IN ('info','warning','danger')),
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'fact',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);

CREATE TABLE IF NOT EXISTS learning_progress (
    concept TEXT PRIMARY KEY,
    times_asked INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def db():
    """Yield a connection with an open transaction; rollback on error."""
    conn = _connect()
    try:
        with _LOCK:
            yield conn
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)


_TABLES = frozenset({
    "conversations", "messages", "tool_calls", "security_events",
    "alerts", "settings", "memory", "snapshots", "learning_progress",
})


def insert(table: str, **values: Any) -> int:
    # table/column names are interpolated into SQL text (values are not —
    # those go through '?' placeholders). Only call this with literal
    # table/kwarg names from code, never with names derived from user input.
    # The allowlist below is defense-in-depth in case that contract is
    # ever violated by a future caller.
    if table not in _TABLES:
        raise ValueError(f"insert(): unknown table {table!r}")
    cols = ", ".join(values)
    marks = ", ".join("?" * len(values))
    with db() as conn:
        cur = conn.execute(
            f"INSERT INTO {table} ({cols}) VALUES ({marks})",  # nosec B608
            list(values.values()),
        )
        return int(cur.lastrowid)


def insert_security_event(level: str, category: str, description: str, **details: Any) -> int:
    return insert(
        "security_events",
        level=level,
        category=category,
        description=description,
        details=json.dumps(details, default=str),
        created_at=_now(),
    )


def insert_alert(severity: str, title: str, description: str) -> int:
    return insert(
        "alerts",
        severity=severity,
        title=title,
        description=description,
        acknowledged=0,
        created_at=_now(),
    )


def get_alert_counts() -> dict[str, int]:
    with db() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE acknowledged=0 GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["n"] for r in rows}


def save_messages(messages: list[dict[str, str]]) -> int:
    """Persist a user+assistant pair; return the assistant message id."""
    with db() as conn:
        conv = conn.execute(
            "INSERT INTO conversations (title, created_at, updated_at) VALUES (?,?,?)",
            ("Nova conversa", _now(), _now()),
        ).lastrowid
        for m in messages:
            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?,?,?,?)",
                (conv, m["role"], m["content"], _now()),
            )
    return conv


def history(limit: int = 12) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT m.id, m.role, m.content, m.created_at, c.title
            FROM messages m JOIN conversations c ON c.id = m.conversation_id
            ORDER BY m.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


def recent_conversation_id() -> int | None:
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM conversations ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row["id"] if row else None


def log_tool_call(tool: str, args: dict, result: str, risk: str = "info", status: str = "ok") -> int:
    return insert(
        "tool_calls",
        tool=tool,
        args=json.dumps(args, default=str),
        result=result[:2000],
        risk=risk,
        status=status,
        created_at=_now(),
    )


def get_snapshot(kind: str, key: str) -> str | None:
    """Read the last stored snapshot for (kind, key) — e.g. ('nmap', host)."""
    with db() as conn:
        row = conn.execute(
            "SELECT content FROM snapshots WHERE kind=? AND key=?", (kind, key)
        ).fetchone()
    return row["content"] if row else None


def save_snapshot(kind: str, key: str, content: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO snapshots (kind, key, content, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(kind, key) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at",
            (kind, key, content, _now()),
        )


def insert_memory(content: str, kind: str = "fact") -> int:
    return insert("memory", kind=kind, content=content, created_at=_now())


def list_memory(kind: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    with db() as conn:
        if kind:
            rows = conn.execute(
                "SELECT id, kind, content, created_at FROM memory WHERE kind=? ORDER BY id DESC LIMIT ?",
                (kind, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, kind, content, created_at FROM memory ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def delete_memory(memory_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM memory WHERE id=?", (memory_id,))
    return cur.rowcount > 0


def touch_learning_progress(concept: str) -> None:
    """Insert or bump the times_asked counter for a concept the user asked about."""
    with db() as conn:
        conn.execute(
            "INSERT INTO learning_progress (concept, times_asked, last_seen) VALUES (?, 1, ?) "
            "ON CONFLICT(concept) DO UPDATE SET "
            "times_asked = times_asked + 1, last_seen = excluded.last_seen",
            (concept, _now()),
        )


def learning_progress(limit: int = 50) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT concept, times_asked, last_seen FROM learning_progress "
            "ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def purge_old_tool_calls(tool: str, days: int) -> int:
    """Delete tool_calls rows for 'tool' older than 'days'. Returns rows removed.

    Used to enforce a data-retention window for sensitive results (e.g.
    cpf_osint) — see README 'Segurança'.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM tool_calls WHERE tool=? AND created_at < ?", (tool, cutoff)
        )
        return cur.rowcount
