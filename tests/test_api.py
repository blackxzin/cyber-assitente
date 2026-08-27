"""Testes dos endpoints principais da API (backend/api/main.py) via
FastAPI TestClient. Banco isolado; watcher desligado (sem subprocess de
fundo nem risco de tocar dado real durante o teste)."""

import pytest
from fastapi.testclient import TestClient

from config.settings import settings
from database import db


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(settings, "watcher_enabled", False)
    db.init_db()

    import api.main as main_module
    # _rate_buckets is module-level, shared process-global state — reset it
    # so one test's request volume can never push another test over the
    # rate limit (all TestClient requests share the synthetic "testclient" host).
    main_module._rate_buckets.clear()
    with TestClient(main_module.app) as c:
        yield c


def test_health_reports_tools_and_mode(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "nmap_scan" in body["tools"]


def test_list_tools_includes_confirmable_ones(client):
    r = client.get("/api/tools")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["tools"]}
    assert {
        "nmap_scan", "packet_capture", "cpf_osint",
        "sqlmap_scan", "hydra_bruteforce", "gobuster_scan", "nikto_scan",
        "burp_proxy_history", "burp_search_history", "burp_find_vulnerabilities",
        "burp_send_request",
    } <= names


def test_system_summary_has_percent_fields(client):
    r = client.get("/api/system")
    assert r.status_code == 200
    body = r.json()
    for key in ("cpu_percent", "mem_percent", "disk_percent", "alerts"):
        assert key in body


def test_chat_rejects_empty_message(client):
    r = client.post("/api/chat", json={"message": "  "})
    assert r.status_code == 400


def test_terminal_denies_denylisted_command(client):
    r = client.post("/api/terminal", json={"command": "rm -rf /"})
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


def test_terminal_runs_allowlisted_command(client):
    r = client.post("/api/terminal", json={"command": "hostname"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["output"].strip()


def test_terminal_requires_confirmation_for_unknown_command(client):
    r = client.post("/api/terminal", json={"command": "echo hi"})
    assert r.status_code == 200
    assert r.json()["status"] == "confirm"


def test_terminal_rejects_empty_command(client):
    r = client.post("/api/terminal", json={"command": ""})
    assert r.status_code == 400


def test_approve_unknown_action_is_404(client):
    r = client.post("/api/actions/999/approve")
    assert r.status_code == 404


def test_deny_unknown_action_is_404(client):
    r = client.post("/api/actions/999/deny")
    assert r.status_code == 404


def test_safety_classify_returns_decision(client):
    r = client.post("/api/safety/classify", json={"action": "nmap 10.0.0.5", "risk": "moderate"})
    assert r.status_code == 200
    assert r.json()["decision"] == "confirm"


def test_safety_classify_rejects_empty_action(client):
    r = client.post("/api/safety/classify", json={"action": ""})
    assert r.status_code == 400


def test_safety_classify_rejects_invalid_risk(client):
    r = client.post("/api/safety/classify", json={"action": "ls", "risk": "not-a-risk"})
    assert r.status_code == 400


def test_alerts_list_starts_empty_and_ack_requires_id(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json()["alerts"] == []

    r = client.post("/api/alerts/ack", json={})
    assert r.status_code == 400


def test_security_events_list(client):
    r = client.get("/api/security/events")
    assert r.status_code == 200
    assert r.json()["events"] == []


def test_history_empty_by_default(client):
    r = client.get("/api/history")
    assert r.status_code == 200


def test_cross_origin_post_is_refused(client):
    r = client.post(
        "/api/alerts/ack",
        json={},
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
    )
    assert r.status_code == 403


def test_same_origin_post_with_matching_origin_is_allowed(client):
    r = client.post(
        "/api/alerts/ack",
        json={},
        headers={"Origin": f"http://127.0.0.1:{settings.port}"},
    )
    assert r.status_code == 400  # passes CSRF gate, fails on missing 'id' as expected


def test_cross_site_post_without_origin_header_is_refused(client):
    r = client.post(
        "/api/alerts/ack",
        json={},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert r.status_code == 403


def test_get_requests_are_never_blocked_by_csrf_gate(client):
    r = client.get("/api/alerts", headers={"Origin": "http://evil.example"})
    assert r.status_code == 200
    assert r.json()["alerts"] == []


# --- API token (settings.api_token) ---
def test_api_token_off_by_default_no_header_needed(client):
    r = client.get("/api/tools")
    assert r.status_code == 200


def test_api_token_required_once_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret")
    r = client.get("/api/tools")
    assert r.status_code == 401


def test_api_token_accepted_via_header(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret")
    r = client.get("/api/tools", headers={"X-API-Token": "s3cret"})
    assert r.status_code == 200


def test_api_token_does_not_gate_health_check(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret")
    r = client.get("/api/health")
    assert r.status_code == 200


# --- Rate limiting ---
def test_rate_limit_blocks_after_threshold(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 2)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health").status_code == 200
    r = client.get("/api/health")
    assert r.status_code == 429


# --- Memória longa ---
def test_memory_list_starts_empty(client):
    r = client.get("/api/memory")
    assert r.status_code == 200
    assert r.json()["facts"] == []


def test_forget_unknown_memory_is_404(client):
    r = client.delete("/api/memory/999")
    assert r.status_code == 404


def test_add_memory_via_api_then_list_and_forget(client):
    r = client.post("/api/memory", json={"content": "host de staging é 10.0.0.7"})
    assert r.status_code == 200
    assert "10.0.0.7" in r.json()["message"]

    r = client.get("/api/memory")
    facts = r.json()["facts"]
    assert len(facts) == 1
    assert facts[0]["content"] == "host de staging é 10.0.0.7"

    r = client.delete(f"/api/memory/{facts[0]['id']}")
    assert r.status_code == 200
    assert client.get("/api/memory").json()["facts"] == []


def test_add_memory_rejects_empty_content(client):
    r = client.post("/api/memory", json={"content": "   "})
    assert r.status_code == 400


def test_add_memory_redacts_secrets(client):
    r = client.post("/api/memory", json={"content": "a chave é sk-ant-api03-abcdefghijklmnopqrstuvwxyz"})
    assert r.status_code == 200
    facts = client.get("/api/memory").json()["facts"]
    assert "sk-ant-api03" not in facts[0]["content"]


# --- Progresso do modo Learning ---
def test_learning_progress_starts_empty(client):
    r = client.get("/api/learning/progress")
    assert r.status_code == 200
    assert r.json()["progress"] == []
