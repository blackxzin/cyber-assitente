"""Utilitários offline de pentest: JWT, identificação de hash e
encode/decode. Tudo puro (base64/hashlib/json da stdlib) — nunca toca rede
nem binário externo, então roda em qualquer máquina e são risk=info sem
confirmação, mesmo padrão do `searchsploit_lookup`.

O foco é o dia a dia de um pentester ao lidar com token capturado, hash
achado num dump e payload pra codificar/decodificar rápido, sem sair da IA.
"""

import base64
import binascii
import json
import re
import time
import urllib.parse

MAX_OUTPUT_CHARS = 8000


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def _b64url_decode(segment: str) -> bytes:
    """Decodifica um segmento base64url de JWT, corrigindo o padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> str:
    """Decodifica header+payload de um JWT (sem verificar assinatura) e
    aponta problemas de segurança comuns. Função pura, testável isolada."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return "jwt inválido: esperado 2 ou 3 segmentos separados por '.'."
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError) as exc:
        return f"jwt inválido: falha ao decodificar base64/JSON ({exc})."
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return "jwt inválido: header/payload não são objetos JSON."

    lines = ["JWT decodificado (assinatura NÃO verificada):", "", "== header =="]
    lines.append(json.dumps(header, indent=2, ensure_ascii=False))
    lines.append("")
    lines.append("== payload ==")
    lines.append(json.dumps(payload, indent=2, ensure_ascii=False))

    findings: list[str] = []
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        findings.append(
            "CRÍTICO: alg='none' — servidor que aceitar isso valida token sem "
            "assinatura (troque payload à vontade)."
        )
    elif alg.startswith("hs"):
        findings.append(
            "HS* (HMAC simétrico): se o servidor também aceitar RS*, tem risco "
            "de key-confusion (assinar HS256 usando a chave pública RSA como segredo). "
            "Segredo fraco = brute-force offline (hashcat -m 16500)."
        )
    now = int(time.time())
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < now:
            findings.append(f"exp expirado há {now - int(exp)}s (token vencido).")
        else:
            findings.append(f"exp válido por mais {int(exp) - now}s.")
    if not parts[2:] or not parts[2]:
        findings.append("Sem segmento de assinatura (token unsecured).")

    if findings:
        lines.append("")
        lines.append("== análise ==")
        lines.extend(f"  - {f}" for f in findings)
    return "\n".join(lines)[:MAX_OUTPUT_CHARS]


# ---------------------------------------------------------------------------
# Identificação de hash
# ---------------------------------------------------------------------------
# (regex, descrição, modo hashcat) — ordem importa: prefixos ($2a$...) antes
# dos genéricos de comprimento.
_HASH_SIGNATURES: tuple[tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt", "3200"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"), "md5crypt", "500"),
    (re.compile(r"^\$5\$"), "sha256crypt", "7400"),
    (re.compile(r"^\$6\$"), "sha512crypt", "1800"),
    (re.compile(r"^\$apr1\$"), "Apache apr1-md5", "1600"),
    (re.compile(r"^\$y\$|^\$7\$"), "yescrypt/scrypt", "-"),
    (re.compile(r"^\{SSHA\}"), "LDAP SSHA", "111"),
    (re.compile(r"^\{SHA\}"), "LDAP SHA1", "101"),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"), "MD5 com salt (hash:salt)", "10"),
    (re.compile(r"^[0-9a-fA-F]{16}$"), "MySQL <4.1 / DES", "200"),
    (re.compile(r"^\*[0-9A-Fa-f]{40}$"), "MySQL 4.1+ (SHA1 duplo)", "300"),
)
# Hashes hex "nus" — comprimento é ambíguo (MD5 vs NTLM vs MD4 têm 32 chars),
# então lista candidatos com o modo hashcat de cada um.
_HEX_LENGTHS: dict[int, list[tuple[str, str]]] = {
    32: [("MD5", "0"), ("NTLM", "1000"), ("MD4", "900"), ("LM (metade)", "3000")],
    40: [("SHA1", "100"), ("MySQL 4.1+ (sem *)", "300"), ("RIPEMD-160", "6000")],
    56: [("SHA-224", "1300"), ("SHA3-224", "17300")],
    64: [("SHA-256", "1400"), ("SHA3-256", "17400"), ("BLAKE2s", "-")],
    96: [("SHA-384", "10800"), ("SHA3-384", "17500")],
    128: [("SHA-512", "1700"), ("SHA3-512", "17600"), ("Whirlpool", "6100")],
}


def identify_hash(value: str) -> str:
    """Adivinha o tipo de um hash por prefixo/formato/comprimento e sugere o
    modo do hashcat. Função pura, testável isolada."""
    value = value.strip()
    if not value:
        return "Uso: informe um 'hash' pra identificar."
    if " " in value or "\n" in value:
        return "hash inválido: não deve conter espaços/quebras de linha."

    for pattern, label, mode in _HASH_SIGNATURES:
        if pattern.match(value):
            suffix = f" (hashcat -m {mode})" if mode != "-" else ""
            return f"Hash identificado: {label}{suffix}."

    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in _HEX_LENGTHS:
        cands = _HEX_LENGTHS[len(value)]
        lines = [f"Hash hex de {len(value)} chars — candidatos:"]
        for label, mode in cands:
            suffix = f"  (hashcat -m {mode})" if mode != "-" else ""
            lines.append(f"  - {label}{suffix}")
        return "\n".join(lines)

    return f"Hash não reconhecido (comprimento {len(value)}). Pode ser codificado ou salgado."


# ---------------------------------------------------------------------------
# Encode / decode
# ---------------------------------------------------------------------------

def _rot13(text: str) -> str:
    import codecs
    return codecs.encode(text, "rot_13")


def transform(op: str, text: str) -> str:
    """Aplica uma transformação de encode/decode. Função pura."""
    op = op.strip().lower().replace("-", "_")
    try:
        if op == "base64_encode":
            return base64.b64encode(text.encode()).decode()
        if op == "base64_decode":
            return base64.b64decode(text.encode()).decode("utf-8", "replace")
        if op == "hex_encode":
            return text.encode().hex()
        if op == "hex_decode":
            return bytes.fromhex(text).decode("utf-8", "replace")
        if op == "url_encode":
            return urllib.parse.quote(text, safe="")
        if op == "url_decode":
            return urllib.parse.unquote(text)
        if op == "rot13":
            return _rot13(text)
    except (binascii.Error, ValueError) as exc:
        return f"erro: falha em {op}: {exc}"
    return (
        f"op inválida: {op!r}. Use base64_encode/base64_decode/hex_encode/"
        "hex_decode/url_encode/url_decode/rot13."
    )


# ---------------------------------------------------------------------------
# Wrappers de ferramenta
# ---------------------------------------------------------------------------

async def tool_jwt_decode(args: dict) -> str:
    token = str(args.get("token") or "").strip()
    if not token:
        return "Uso: informe um 'token' JWT."
    return decode_jwt(token)


async def tool_hash_identify(args: dict) -> str:
    value = str(args.get("hash") or "").strip()
    return identify_hash(value)


async def tool_encode_decode(args: dict) -> str:
    op = str(args.get("op") or "").strip()
    text = str(args.get("text") or "")
    if not op:
        return ("Uso: informe 'op' e 'text'. Ops: base64_encode/base64_decode/"
                "hex_encode/hex_decode/url_encode/url_decode/rot13.")
    if not text:
        return "Uso: informe o 'text' a transformar."
    return transform(op, text)[:MAX_OUTPUT_CHARS]


def register(registry) -> None:
    for name, desc, fn, required in (
        ("jwt_decode", "Decodifica header/payload de um JWT (sem verificar assinatura) e aponta falhas (alg=none, HS/RS confusion, exp) — informe 'token'.", tool_jwt_decode, ("token",)),
        ("hash_identify", "Identifica o tipo de um hash e sugere o modo do hashcat (informe 'hash').", tool_hash_identify, ("hash",)),
        ("encode_decode", "Codifica/decodifica texto: base64/hex/url/rot13 (informe 'op' e 'text').", tool_encode_decode, ("op", "text")),
    ):
        registry.register(name, desc, fn, risk="info", requires_confirmation=False,
                          required_args=required, target_arg=None, category="cripto")
