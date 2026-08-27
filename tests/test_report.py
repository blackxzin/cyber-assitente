"""Testes do gerador de relatório de pentest (backend/services/report.py)."""

import pytest

from database import db
from services.report import generate_pentest_report


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_empty_report_says_nothing_registered():
    report = generate_pentest_report()
    assert "Nenhuma ação de pentest registrada ainda." in report
    assert "0 ação(ões)" in report


def test_report_includes_pentest_tool_calls_grouped_by_tool():
    db.log_tool_call("nmap_scan", {}, "22/tcp open ssh\n80/tcp open http", status="ok")
    db.log_tool_call("nmap_scan", {}, "443/tcp open https", status="ok")
    db.log_tool_call("sqlmap_scan", {}, "parameter 'id' is vulnerable", status="ok")

    report = generate_pentest_report()
    assert "### nmap_scan (2 execução(ões))" in report
    assert "### sqlmap_scan (1 execução(ões))" in report
    assert "22/tcp open ssh" in report
    assert "parameter 'id' is vulnerable" in report
    assert "3 ação(ões) de auditoria registrada(s)" in report


def test_report_excludes_non_pentest_tools():
    db.log_tool_call("memory_info", {}, "8GB total", status="ok")
    report = generate_pentest_report()
    assert "memory_info" not in report
    assert "Nenhuma ação de pentest registrada ainda." in report


def test_report_marks_errored_calls_differently():
    db.log_tool_call("nikto_scan", {}, "erro: timeout", status="error")
    report = generate_pentest_report()
    assert "⚠️" in report
    assert "✅" not in report


def test_report_includes_alerts_section():
    db.insert_alert("high", "Porta nova aberta", "3389/tcp em 10.0.0.5")
    report = generate_pentest_report()
    assert "## Alertas" in report
    assert "**[HIGH]** Porta nova aberta" in report
    assert "1 alerta(s) no histórico" in report


def test_report_truncates_long_output_snippets():
    huge = "\n".join(f"linha {i}" for i in range(50))
    db.log_tool_call("gobuster_scan", {}, huge, status="ok")
    report = generate_pentest_report()
    assert "linha 0" in report
    assert "...[truncado]" in report
    assert "linha 49" not in report


def test_report_respects_limit():
    for i in range(5):
        db.log_tool_call("nmap_scan", {}, f"scan {i}", status="ok")
    report = generate_pentest_report(limit=2)
    assert "scan 3" in report
    assert "scan 4" in report
    assert "scan 0" not in report
