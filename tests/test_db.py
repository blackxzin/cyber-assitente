"""Testes da camada SQLite (backend/database/db.py): snapshots (usados pelo
diff de scan/watcher) e retenção de dados sensíveis (cpf_osint)."""

from datetime import datetime, timedelta, timezone

import pytest

from database import db


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Each test gets its own throwaway SQLite file."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_snapshot_roundtrip_and_update():
    assert db.get_snapshot("nmap", "10.0.0.5") is None
    db.save_snapshot("nmap", "10.0.0.5", "first output")
    assert db.get_snapshot("nmap", "10.0.0.5") == "first output"
    db.save_snapshot("nmap", "10.0.0.5", "second output")
    assert db.get_snapshot("nmap", "10.0.0.5") == "second output"


def test_snapshots_are_isolated_by_kind_and_key():
    db.save_snapshot("nmap", "host-a", "a")
    db.save_snapshot("nmap", "host-b", "b")
    db.save_snapshot("local_ports", "ss", "c")
    assert db.get_snapshot("nmap", "host-a") == "a"
    assert db.get_snapshot("nmap", "host-b") == "b"
    assert db.get_snapshot("local_ports", "ss") == "c"


def test_purge_old_tool_calls_removes_only_expired_matching_tool():
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    recent = datetime.now(timezone.utc).isoformat()
    db.insert("tool_calls", tool="cpf_osint", args="{}", result="r", risk="moderate",
              status="ok", created_at=old)
    db.insert("tool_calls", tool="cpf_osint", args="{}", result="r", risk="moderate",
              status="ok", created_at=recent)
    db.insert("tool_calls", tool="nmap_scan", args="{}", result="r", risk="moderate",
              status="ok", created_at=old)

    removed = db.purge_old_tool_calls("cpf_osint", days=30)

    assert removed == 1
    with db.db() as conn:
        rows = conn.execute("SELECT tool, created_at FROM tool_calls").fetchall()
    remaining = {(r["tool"], r["created_at"]) for r in rows}
    assert ("cpf_osint", old) not in remaining
    assert ("cpf_osint", recent) in remaining
    assert ("nmap_scan", old) in remaining  # outra ferramenta não é afetada


def test_alert_counts_group_by_severity():
    db.insert_alert("high", "t1", "d1")
    db.insert_alert("high", "t2", "d2")
    db.insert_alert("medium", "t3", "d3")
    counts = db.get_alert_counts()
    assert counts == {"high": 2, "medium": 1}
