"""Testa que o VulnLab é vulnerável DE PROPÓSITO — cada teste prova uma vuln.

Se um deles falhar, o alvo de treino deixou de servir pro que existe (dar às
ferramentas ofensivas algo real pra explorar). Não usa rede: exercita as
funções puras direto, e um teste end-to-end sobe o servidor em porta efêmera.
"""

import base64
import sys
import threading
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

LAB = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB))

import vulnerable_app as lab  # noqa: E402


def test_sqli_bypass_logs_in():
    conn = lab.build_users_db()
    rows = lab.try_login(conn, "' OR '1'='1", "' OR '1'='1")
    assert rows, "SQL injection deveria derrubar o WHERE e casar usuários"
    users = {u for u, _ in rows}
    assert "admin" in users


def test_normal_bad_login_fails():
    conn = lab.build_users_db()
    assert lab.try_login(conn, "admin", "senha-errada") == []


def test_normal_good_login_works():
    conn = lab.build_users_db()
    rows = lab.try_login(conn, "admin", "admin123")
    assert rows == [("admin", "admin")]


def test_vulnerable_query_uses_concatenation():
    # A prova do SQLi: o input entra cru na string da query (sem placeholder).
    q = lab.vulnerable_login_query("x' OR 1=1 --", "y")
    assert "x' OR 1=1 --" in q


def test_search_reflects_xss_unescaped():
    payload = "<script>alert(1)</script>"
    html = lab.render_search(payload)
    assert payload in html, "XSS refletido: o termo deve voltar sem escape"


def test_weak_basic_auth_accepts_known_creds():
    token = base64.b64encode(b"admin:admin123").decode()
    assert lab.check_basic_auth(f"Basic {token}") is True


def test_basic_auth_rejects_wrong_creds():
    token = base64.b64encode(b"admin:wrong").decode()
    assert lab.check_basic_auth(f"Basic {token}") is False
    assert lab.check_basic_auth(None) is False
    assert lab.check_basic_auth("Bearer xyz") is False


def test_end_to_end_server_serves_vulns():
    srv = lab.make_server("127.0.0.1", 0)  # porta efêmera
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        # banner de versão
        with urlopen(base + "/", timeout=5) as r:
            assert (r.headers.get("Server") or "").strip() == lab.SERVER_BANNER
        # SQLi via HTTP
        inj = "%27%20OR%20%271%27%3D%271"
        with urlopen(f"{base}/login?user={inj}&pass={inj}", timeout=5) as r:
            assert b"Bem-vindo" in r.read()
        # rota enumerável
        with urlopen(base + "/config.php", timeout=5) as r:
            assert r.status == 200
        # admin sem auth = 401
        try:
            urlopen(base + "/admin", timeout=5)
            assert False, "deveria exigir auth"
        except HTTPError as e:
            assert e.code == 401
        # admin com creds fracas
        token = base64.b64encode(b"admin:admin123").decode()
        req = Request(base + "/admin", headers={"Authorization": f"Basic {token}"})
        with urlopen(req, timeout=5) as r:
            assert b"LAB{" in r.read()
    finally:
        srv.shutdown()


# --- vulns adicionais (2ª rodada) ---

def test_command_injection_builds_shell_string():
    cmd = lab.build_ping_command("127.0.0.1; id")
    assert cmd == "ping -c 1 127.0.0.1; id"  # payload entra cru no shell


def test_path_traversal_escapes_base_dir():
    p = lab.resolve_download_path("/srv/public", "../../../../etc/passwd")
    # sem normalização: o join mantém o ../ que escapa do base
    assert p.endswith("etc/passwd") and ".." in p


def test_idor_returns_any_profile_without_auth():
    admin = lab.get_profile("1")
    assert admin and admin["role"] == "admin" and "ssn" in admin
    assert lab.get_profile("2")["user"] == "joao"  # dado de OUTRO usuário
    assert lab.get_profile("999") is None


def test_ssrf_accepts_arbitrary_internal_url():
    assert lab.is_ssrf_allowed("http://127.0.0.1:8667/status") is True
    assert lab.is_ssrf_allowed("http://169.254.169.254/") is True  # metadata interno
    assert lab.is_ssrf_allowed("ftp://x") is False


def test_end_to_end_new_vulns():
    import os as _os
    from urllib.request import urlopen as _urlopen

    main = lab.make_server("127.0.0.1", 0)
    second = lab.make_second_server("127.0.0.1", 0)
    p1, p2 = main.server_address[1], second.server_address[1]
    for s in (main, second):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{p1}"
        # command injection: echo roda no servidor
        with _urlopen(f"{base}/ping?host=127.0.0.1%3B%20echo%20PWNED", timeout=10) as r:
            assert b"PWNED" in r.read()
        # path traversal: lê o próprio fonte do lab (sobe de DOWNLOAD_DIR)
        fname = _os.path.basename(__file__)
        with _urlopen(f"{base}/download?file=../tests/{fname}", timeout=5) as r:
            assert b"test_end_to_end_new_vulns" in r.read()
        # IDOR via HTTP
        with _urlopen(f"{base}/profile?id=1", timeout=5) as r:
            assert b'"role": "admin"' in r.read()
        # SSRF: faz o alvo principal buscar o 2º alvo interno
        ssrf = f"{base}/fetch?url=http://127.0.0.1:{p2}/status"
        with _urlopen(ssrf, timeout=8) as r:
            assert b"admin-panel" in r.read()
        # 2º alvo tem banner próprio (nmap veria 2 serviços distintos)
        with _urlopen(f"http://127.0.0.1:{p2}/", timeout=5) as r:
            assert (r.headers.get("Server") or "").strip() == lab.SECOND_BANNER
    finally:
        main.shutdown()
        second.shutdown()
