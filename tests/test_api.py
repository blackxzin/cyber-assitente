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


def test_tools_expose_category_for_ui_grouping(client):
    r = client.get("/api/tools")
    by_name = {t["name"]: t["category"] for t in r.json()["tools"]}
    assert by_name["nmap_scan"] == "ofensivo"
    assert by_name["cpf_osint"] == "osint"
    assert by_name["searchsploit_lookup"] == "exploração"
    assert by_name["re_file_info"] == "engenharia-reversa"
    assert by_name["burp_proxy_history"] == "burp"
    assert by_name["system_info"] == "sistema"
    assert by_name["network_interfaces"] == "rede"
    assert by_name["local_ports"] == "diagnóstico"
    assert by_name["remember"] == "memória"


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


# --- Escopo autorizado ---
def test_scope_starts_empty(client):
    r = client.get("/api/scope")
    assert r.status_code == 200
    assert r.json()["scope"] == []


def test_set_scope_then_reflected_in_health_and_scope_endpoint(client):
    r = client.post("/api/scope", json={"scope": ["10.0.0.0/24", "example.com"]})
    assert r.status_code == 200
    assert r.json()["scope"] == ["10.0.0.0/24", "example.com"]

    assert client.get("/api/scope").json()["scope"] == ["10.0.0.0/24", "example.com"]
    assert client.get("/api/health").json()["authorized_scope"] == ["10.0.0.0/24", "example.com"]


def test_set_scope_rejects_non_list_body(client):
    r = client.post("/api/scope", json={"scope": "10.0.0.0/24"})
    assert r.status_code == 400


def test_set_scope_empty_list_clears_scope(client):
    client.post("/api/scope", json={"scope": ["10.0.0.0/24"]})
    r = client.post("/api/scope", json={"scope": []})
    assert r.json()["scope"] == []


# --- Config do research provider (2° modelo) ---
def test_research_provider_config_starts_from_env(client):
    r = client.get("/api/provider/research")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] in ("env", "none")
    assert "openrouter" in body["available_providers"]


def test_set_research_provider_config_applies_immediately(client):
    r = client.post("/api/provider/research", json={
        "provider": "openrouter",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "anthropic/claude-sonnet-4.5",
        "api_key": "sk-or-dummy-test-key",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "ui"
    assert body["provider"] == "openrouter"
    assert body["model"] == "anthropic/claude-sonnet-4.5"
    assert body["api_key_set"] is True

    # não devolve a chave em texto puro de volta
    assert "api_key" not in body

    # aplicado de verdade no orchestrator ativo, sem reiniciar processo
    import api.main as main_module
    assert main_module._chat.orchestrator.research_provider.config.model == "anthropic/claude-sonnet-4.5"


def test_set_research_provider_config_rejects_unknown_provider(client):
    r = client.post("/api/provider/research", json={"provider": "nao-existe"})
    assert r.status_code == 400


def test_set_research_provider_config_empty_clears_override(client):
    client.post("/api/provider/research", json={"provider": "openrouter", "api_key": "sk-or-x"})
    r = client.post("/api/provider/research", json={"provider": ""})
    assert r.status_code == 200
    assert r.json()["source"] in ("env", "none")


def test_set_research_provider_config_omitted_key_keeps_existing(client):
    client.post("/api/provider/research", json={
        "provider": "openrouter", "model": "model-a", "api_key": "sk-or-original",
    })
    r = client.post("/api/provider/research", json={"provider": "openrouter", "model": "model-b"})
    body = r.json()
    assert body["model"] == "model-b"
    assert body["api_key_set"] is True  # chave original preservada


def test_health_reflects_research_provider_override(client):
    assert client.get("/api/health").json()["research_provider"] is None
    client.post("/api/provider/research", json={
        "provider": "openrouter", "model": "anthropic/claude-sonnet-4.5",
    })
    body = client.get("/api/health").json()
    assert body["research_provider"] == "openrouter"
    assert body["research_model"] == "anthropic/claude-sonnet-4.5"


# --- Relatório de pentest ---
def test_report_downloads_markdown(client):
    r = client.get("/api/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"]
    assert "# Relatório de Pentest" in r.text


# --- Progresso do modo Learning ---
def test_learning_progress_starts_empty(client):
    r = client.get("/api/learning/progress")
    assert r.status_code == 200
    assert r.json()["progress"] == []
