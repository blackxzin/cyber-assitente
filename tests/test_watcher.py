"""Testes do watcher em segundo plano (backend/services/watcher.py):
diff de portas locais, alerta de disco com deduplicação, e purga de OSINT.
Todo I/O externo (ss, notify-send) é mockado — só a lógica é testada.
"""

from datetime import datetime, timedelta, timezone

import pytest

from database import db
from services import watcher


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


@pytest.fixture(autouse=True)
def _no_desktop_notifications(monkeypatch):
    sent = []

    async def _fake_notify(title, message):
        sent.append((title, message))

    monkeypatch.setattr(watcher, "notify_desktop", _fake_notify)
    return sent


SS_BEFORE = "tcp   LISTEN 0 128 127.0.0.1:8000 0.0.0.0:*\n"
SS_AFTER = SS_BEFORE + "tcp   LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*\n"


async def test_check_local_ports_alerts_on_new_listener(monkeypatch, _no_desktop_notifications):
    calls = iter([SS_BEFORE, SS_AFTER])

    async def _fake_run_safe_command(argv):
        return next(calls), ""

    monkeypatch.setattr(watcher.executor, "run_safe_command", _fake_run_safe_command)

    await watcher._check_local_ports()  # baseline only, no previous snapshot
    assert db.get_alert_counts() == {}

    await watcher._check_local_ports()  # now a new listener appears
    assert db.get_alert_counts() == {"medium": 1}
    assert _no_desktop_notifications  # notified once


async def test_check_disk_alerts_once_then_stays_quiet_while_over_threshold(monkeypatch):
    monkeypatch.setattr(watcher, "disk_percent", lambda: 90)
    monkeypatch.setattr("config.settings.settings.disk_alert_percent", 85)

    await watcher._check_disk()
    assert db.get_alert_counts() == {"high": 1}

    await watcher._check_disk()  # still over threshold — must not re-alert
    assert db.get_alert_counts() == {"high": 1}


async def test_check_disk_clears_flag_once_usage_drops(monkeypatch):
    monkeypatch.setattr("config.settings.settings.disk_alert_percent", 85)

    monkeypatch.setattr(watcher, "disk_percent", lambda: 90)
    await watcher._check_disk()
    assert db.get_alert_counts() == {"high": 1}

    monkeypatch.setattr(watcher, "disk_percent", lambda: 10)
    await watcher._check_disk()

    monkeypatch.setattr(watcher, "disk_percent", lambda: 90)
    await watcher._check_disk()
    assert db.get_alert_counts() == {"high": 2}  # re-alerta depois de normalizar


async def test_purge_osint_removes_expired_rows():
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    db.insert("tool_calls", tool="cpf_osint", args="{}", result="r", risk="moderate",
              status="ok", created_at=old)
    await watcher._purge_osint()
    with db.db() as conn:
        rows = conn.execute("SELECT * FROM tool_calls WHERE tool='cpf_osint'").fetchall()
    assert rows == []
