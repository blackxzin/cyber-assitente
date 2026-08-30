#!/usr/bin/env python3
"""VulnLab — alvo de treino DELIBERADAMENTE VULNERÁVEL para o Cyber.

⚠️  USO LOCAL / AUTORIZADO. Sobe SÓ em 127.0.0.1. Nunca exponha à rede.
Serve pra dar ao assistente (e às ferramentas nmap/sqlmap/gobuster/nikto/
hydra) um alvo real e legal para fechar o ciclo achar→explorar→reportar sem
tocar em sistemas de terceiros.

Vulnerabilidades plantadas (todas de propósito):
  - SQL injection      em  GET /login?user=&pass=  (query montada por concat)
  - XSS refletido      em  GET /search?q=          (eco sem escape)
  - Command injection  em  GET /ping?host=         (shell montado por concat)
  - Path traversal     em  GET /download?file=     (join sem normalizar)
  - IDOR               em  GET /profile?id=        (qualquer id, sem auth/dono)
  - SSRF               em  GET /fetch?url=          (busca URL arbitrária, incl. interna)
  - Auth fraca         em  GET /admin              (Basic admin:admin123 — bruteforce)
  - Superfície p/ enum: /robots.txt /backup.zip /.git/HEAD /config.php /admin
  - Banner de versão "VulnLab/1.0" no header Server (searchsploit/nikto)
  - 2º alvo "AdminPanel/2.3" noutra porta (nmap acha múltiplos serviços)

Só usa a biblioteca padrão do Python — roda em qualquer lugar, sem instalar nada.
A lógica vulnerável mora em funções puras (testáveis em tests/test_lab.py); o
servidor HTTP é só a casca em volta delas.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sqlite3
import json as _json
from html import escape  # usado só nas partes NÃO-vulneráveis, de propósito
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

# Diretório "público" do download — o path traversal escapa DELE.
DOWNLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

SERVER_BANNER = "VulnLab/1.0"
# Credencial fraca de propósito — é o par que o hydra deve achar.
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin123"

# Caminhos "escondidos" que respondem 200 — comida para gobuster/nikto.
DISCOVERABLE = {
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n"),
    "/backup.zip": ("application/zip", "PK\x03\x04 fake-backup-nao-e-um-zip-de-verdade"),
    "/.git/HEAD": ("text/plain", "ref: refs/heads/master\n"),
    "/config.php": ("text/plain", "<?php $db_pass = 'S3nh4Fr4c4!'; // exposto de proposito ?>"),
}


def build_users_db() -> sqlite3.Connection:
    """Banco em memória com um usuário admin — alvo do SQLi."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT, role TEXT)")
    conn.execute(
        "INSERT INTO users (user, pass, role) VALUES (?,?,?)",
        (ADMIN_USER, ADMIN_PASSWORD, "admin"),
    )
    conn.execute(
        "INSERT INTO users (user, pass, role) VALUES (?,?,?)",
        ("joao", "joao2024", "user"),
    )
    conn.commit()
    return conn


def vulnerable_login_query(user: str, password: str) -> str:
    """Monta a query por CONCATENAÇÃO — é AQUI que mora o SQL injection.

    `user=' OR '1'='1` e `pass=' OR '1'='1` derrubam o WHERE inteiro.
    (Função pura de propósito, pra deixar o SQLi óbvio e testável.)
    """
    return (
        "SELECT user, role FROM users "
        f"WHERE user = '{user}' AND pass = '{password}'"
    )


def try_login(conn: sqlite3.Connection, user: str, password: str) -> list[tuple]:
    """Roda a query vulnerável e devolve as linhas casadas."""
    query = vulnerable_login_query(user, password)
    try:
        return list(conn.execute(query))
    except sqlite3.Error as exc:
        # Erro de SQL vaza pro atacante (também de propósito — feedback de SQLi).
        raise RuntimeError(f"SQL error: {exc}") from exc


def render_search(query: str) -> str:
    """Devolve o termo de busca SEM escapar — XSS refletido de propósito."""
    return (
        "<!doctype html><html><body>"
        f"<h1>Resultados para: {query}</h1>"  # <- sem escape: XSS
        "<p>Nenhum resultado encontrado.</p>"
        "</body></html>"
    )


def check_basic_auth(auth_header: str | None) -> bool:
    """Valida Basic admin:admin123 — o alvo do bruteforce do hydra."""
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(auth_header[6:]).decode("utf-8", "replace")
    except Exception:
        return False
    user, _, password = raw.partition(":")
    return user == ADMIN_USER and password == ADMIN_PASSWORD


def build_ping_command(host: str) -> str:
    """Monta o comando de shell por CONCATENAÇÃO — command injection de propósito.

    `host=127.0.0.1; id` vira `ping -c 1 127.0.0.1; id` e o `id` roda no servidor.
    (Função pura pra deixar a injeção óbvia e testável sem executar nada.)
    """
    return f"ping -c 1 {host}"


def resolve_download_path(base_dir: str, filename: str) -> str:
    """Junta base + nome SEM normalizar/validar — path traversal de propósito.

    `filename=../../../../etc/passwd` escapa do base_dir e lê arquivo arbitrário.
    """
    return os.path.join(base_dir, filename)


# "Banco" de perfis exposto por IDOR — qualquer id, sem auth nem dono.
PROFILES = {
    "1": {"id": "1", "user": "admin", "email": "admin@vulnlab.local", "role": "admin", "ssn": "000-11-2222"},
    "2": {"id": "2", "user": "joao", "email": "joao@vulnlab.local", "role": "user", "ssn": "333-44-5555"},
    "3": {"id": "3", "user": "maria", "email": "maria@vulnlab.local", "role": "user", "ssn": "666-77-8888"},
}


def get_profile(profile_id: str) -> dict | None:
    """Devolve o perfil de QUALQUER id, sem checar dono/sessão — IDOR de propósito."""
    return PROFILES.get(profile_id)


def is_ssrf_allowed(url: str) -> bool:
    """SEM allowlist: aceita qualquer URL, inclusive interna/loopback — SSRF de propósito.

    Um servidor seguro bloquearia esquemas file:// e destinos internos; este não.
    """
    return url.startswith(("http://", "https://"))


class VulnHandler(BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = ""  # esconde a versão do Python, deixa só o banner do lab
    db: sqlite3.Connection  # injetado no factory abaixo

    def log_message(self, *args) -> None:  # silencia ruído no terminal
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html",
              headers: dict | None = None) -> None:
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path, params = parts.path, parse_qs(parts.query)

        if path == "/":
            self._send(200, f"<h1>{SERVER_BANNER}</h1>"
                            "<p>Rotas: /login /search /ping /download /profile /fetch /admin</p>")
            return

        if path in DISCOVERABLE:
            ctype, body = DISCOVERABLE[path]
            self._send(200, body, ctype)
            return

        if path == "/login":
            user = (params.get("user") or [""])[0]
            password = (params.get("pass") or [""])[0]
            try:
                rows = try_login(self.db, user, password)
            except RuntimeError as exc:
                self._send(500, f"<pre>{escape(str(exc))}</pre>")
                return
            if rows:
                who = ", ".join(f"{u} ({r})" for u, r in rows)
                self._send(200, f"<h1>Bem-vindo: {who}</h1>")
            else:
                self._send(401, "<h1>Login inválido</h1>")
            return

        if path == "/search":
            q = (params.get("q") or [""])[0]
            self._send(200, render_search(q))
            return

        if path == "/ping":  # command injection
            host = (params.get("host") or ["127.0.0.1"])[0]
            cmd = build_ping_command(host)
            out = subprocess.run(cmd, shell=True, capture_output=True,
                                 text=True, timeout=10).stdout
            self._send(200, f"<pre>{out}</pre>")
            return

        if path == "/download":  # path traversal
            filename = (params.get("file") or [""])[0]
            full = resolve_download_path(DOWNLOAD_DIR, filename)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    self._send(200, fh.read(), "text/plain")
            except OSError as exc:
                self._send(404, f"erro: {escape(str(exc))}", "text/plain")
            return

        if path == "/profile":  # IDOR — qualquer id, sem auth
            profile = get_profile((params.get("id") or [""])[0])
            if profile is None:
                self._send(404, '{"error":"perfil nao encontrado"}', "application/json")
            else:
                self._send(200, _json.dumps(profile), "application/json")
            return

        if path == "/fetch":  # SSRF — busca URL controlada pelo atacante
            url = (params.get("url") or [""])[0]
            if not is_ssrf_allowed(url):
                self._send(400, "erro: url invalida", "text/plain")
                return
            try:
                with urlopen(url, timeout=8) as r:  # noqa: S310 (SSRF de propósito)
                    body = r.read(65536).decode("utf-8", "replace")
                self._send(200, body, "text/plain")
            except Exception as exc:
                self._send(502, f"erro ao buscar: {escape(str(exc))}", "text/plain")
            return

        if path == "/admin":
            if check_basic_auth(self.headers.get("Authorization")):
                self._send(200, "<h1>Painel admin</h1><p>Flag: LAB{admin_acessado}</p>")
            else:
                self._send(401, "<h1>401 — auth necessária</h1>",
                           headers={"WWW-Authenticate": 'Basic realm="VulnLab"'})
            return

        self._send(404, "<h1>404 Not Found</h1>")


def make_server(host: str = "127.0.0.1", port: int = 8666) -> ThreadingHTTPServer:
    """Cria o servidor com um banco vulnerável dedicado."""
    conn = build_users_db()
    handler = type("BoundVulnHandler", (VulnHandler,), {"db": conn})
    return ThreadingHTTPServer((host, port), handler)


# --- 2º alvo: serviço distinto noutra porta, pro nmap achar MÚLTIPLOS ---
SECOND_BANNER = "AdminPanel/2.3"


class SecondTargetHandler(BaseHTTPRequestHandler):
    """Alvo secundário — banner e superfície diferentes do principal, pra dar
    ao nmap um segundo serviço com fingerprint próprio."""

    server_version = SECOND_BANNER
    sys_version = ""

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        body = (f"<h1>{SECOND_BANNER}</h1><p>Painel interno. Rota: /status</p>"
                if self.path == "/" else
                '{"service":"admin-panel","version":"2.3","status":"ok"}'
                if self.path == "/status" else "<h1>404</h1>")
        data = body.encode()
        self.send_response(200 if self.path in ("/", "/status") else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_second_server(host: str = "127.0.0.1", port: int = 8667) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), SecondTargetHandler)


def main() -> None:
    import argparse
    import threading

    ap = argparse.ArgumentParser(description="VulnLab — alvo de treino local")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8666)
    ap.add_argument("--port2", type=int, default=8667,
                    help="2º alvo (banner AdminPanel/2.3); 0 desliga")
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Recusado: VulnLab só sobe em loopback (127.0.0.1).")
    srv = make_server(args.host, args.port)
    print(f"VulnLab em http://{args.host}:{args.port}  (Ctrl+C para parar)")
    print("Vulns: SQLi /login · XSS /search · cmd-inj /ping · path-traversal /download")
    print("       IDOR /profile · SSRF /fetch · auth fraca /admin (admin:admin123)")
    srv2 = None
    if args.port2:
        srv2 = make_second_server(args.host, args.port2)
        threading.Thread(target=srv2.serve_forever, daemon=True).start()
        print(f"2º alvo ({SECOND_BANNER}) em http://{args.host}:{args.port2}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nencerrando VulnLab…")
        srv.shutdown()
        if srv2:
            srv2.shutdown()


if __name__ == "__main__":
    main()
