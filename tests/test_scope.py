"""Testes do gate de escopo autorizado (backend/security/scope.py)."""

import pytest

from database import db
from security import scope


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_empty_scope_authorizes_everything():
    assert scope.get_scope() == []
    assert scope.is_authorized("10.0.0.5") is True
    assert scope.is_authorized("qualquer-coisa.exemplo.com") is True


def test_set_scope_persists_and_round_trips():
    saved = scope.set_scope(["10.0.0.0/24", " example.com ", ""])
    assert saved == ["10.0.0.0/24", "example.com"]
    assert scope.get_scope() == ["10.0.0.0/24", "example.com"]


def test_ip_authorized_inside_cidr_only():
    scope.set_scope(["10.0.0.0/24"])
    assert scope.is_authorized("10.0.0.5") is True
    assert scope.is_authorized("10.0.1.5") is False


def test_bare_ip_pattern_matches_only_itself():
    scope.set_scope(["10.0.0.5"])
    assert scope.is_authorized("10.0.0.5") is True
    assert scope.is_authorized("10.0.0.6") is False


def test_domain_pattern_matches_exact_and_subdomains():
    scope.set_scope(["example.com"])
    assert scope.is_authorized("example.com") is True
    assert scope.is_authorized("api.example.com") is True
    assert scope.is_authorized("notexample.com") is False
    assert scope.is_authorized("evil.com") is False


def test_wildcard_domain_pattern_matches_subdomains():
    scope.set_scope(["*.example.com"])
    assert scope.is_authorized("api.example.com") is True
    assert scope.is_authorized("example.com") is True  # bare apex also allowed


def test_extract_host_from_url_and_bare_host():
    assert scope.extract_host("http://10.0.0.5:8080/path") == "10.0.0.5"
    assert scope.extract_host("https://example.com/") == "example.com"
    assert scope.extract_host("10.0.0.5") == "10.0.0.5"
    assert scope.extract_host("10.0.0.5:22") == "10.0.0.5"


def test_scope_pattern_as_full_url_matches_by_host():
    # Regressão: colar a URL inteira no painel de escopo (em vez de só o
    # domínio) fazia o alvo "cair" no branch de CIDR por causa da '/' da URL
    # e do path, e ipaddress.ip_network() rejeitava — todo alvo desse
    # domínio (mesmo o próprio path exato colado) virava "fora de escopo".
    scope.set_scope(["https://exemplo.com.br/"])
    assert scope.is_authorized("exemplo.com.br") is True
    assert scope.is_authorized("https://exemplo.com.br/cpanel") is True
    assert scope.is_authorized("https://outro.com/") is False


def test_is_authorized_extracts_host_from_url_target():
    scope.set_scope(["example.com"])
    assert scope.is_authorized("http://example.com/admin?x=1") is True
    assert scope.is_authorized("http://evil.com/") is False


def test_check_target_returns_none_when_no_target_arg():
    scope.set_scope(["example.com"])
    assert scope.check_target(None, {"host": "evil.com"}) is None


def test_check_target_returns_none_when_arg_missing():
    scope.set_scope(["example.com"])
    assert scope.check_target("host", {}) is None


def test_check_target_returns_none_when_authorized():
    scope.set_scope(["10.0.0.0/24"])
    assert scope.check_target("host", {"host": "10.0.0.5"}) is None


def test_check_target_returns_error_message_when_out_of_scope():
    scope.set_scope(["10.0.0.0/24"])
    msg = scope.check_target("host", {"host": "8.8.8.8"})
    assert msg is not None
    assert "8.8.8.8" in msg
    assert "fora do escopo" in msg
