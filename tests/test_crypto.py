"""Testes das ferramentas offline de cripto (JWT, hash, encode/decode).
Tudo puro — nenhum teste toca rede ou binário.
"""

import base64
import json
import time

import pytest

from tools.crypto import (
    decode_jwt,
    identify_hash,
    tool_encode_decode,
    tool_hash_identify,
    tool_jwt_decode,
    transform,
)


def _make_jwt(header: dict, payload: dict) -> str:
    def seg(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{seg(header)}.{seg(payload)}.fakesig"


# --- JWT ---

def test_decode_jwt_shows_header_and_payload():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin", "role": "user"})
    out = decode_jwt(token)
    assert "HS256" in out
    assert "admin" in out
    assert "assinatura NÃO verificada" in out


def test_decode_jwt_flags_alg_none():
    token = _make_jwt({"alg": "none"}, {"sub": "x"})
    out = decode_jwt(token)
    assert "CRÍTICO" in out and "none" in out


def test_decode_jwt_flags_expired():
    token = _make_jwt({"alg": "HS256"}, {"exp": int(time.time()) - 3600})
    out = decode_jwt(token)
    assert "expirado" in out


def test_decode_jwt_flags_valid_exp():
    token = _make_jwt({"alg": "HS256"}, {"exp": int(time.time()) + 3600})
    out = decode_jwt(token)
    assert "válido por mais" in out


def test_decode_jwt_strips_bearer_prefix():
    token = "Bearer " + _make_jwt({"alg": "HS256"}, {"a": 1})
    out = decode_jwt(token)
    assert "HS256" in out


@pytest.mark.parametrize("bad", ["", "notajwt", "only.one", "a.b.c.d.e"])
def test_decode_jwt_rejects_malformed(bad):
    out = decode_jwt(bad)
    assert "inválido" in out


# --- hash identify ---

@pytest.mark.parametrize("value,expected", [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),
    ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "SHA1"),
    ("a" * 64, "SHA-256"),
    ("a" * 128, "SHA-512"),
])
def test_identify_hash_hex_lengths(value, expected):
    assert expected in identify_hash(value)


def test_identify_hash_bcrypt():
    out = identify_hash("$2b$12$" + "a" * 53)
    assert "bcrypt" in out and "3200" in out


def test_identify_hash_sha512crypt():
    assert "sha512crypt" in identify_hash("$6$salt$hashhashhash")


def test_identify_hash_suggests_hashcat_mode():
    assert "-m 1000" in identify_hash("a" * 32)  # NTLM candidate


def test_identify_hash_rejects_empty_and_spaces():
    assert "Uso:" in identify_hash("")
    assert "inválido" in identify_hash("has com espaco")


def test_identify_hash_unknown():
    assert "não reconhecido" in identify_hash("xyz123")


# --- encode/decode ---

def test_transform_base64_roundtrip():
    enc = transform("base64_encode", "hello")
    assert transform("base64_decode", enc) == "hello"


def test_transform_hex_roundtrip():
    enc = transform("hex_encode", "AB")
    assert enc == "4142"
    assert transform("hex_decode", enc) == "AB"


def test_transform_url():
    assert transform("url_encode", "a b&c") == "a%20b%26c"
    assert transform("url_decode", "a%20b%26c") == "a b&c"


def test_transform_rot13_is_involutive():
    assert transform("rot13", transform("rot13", "Secret")) == "Secret"


def test_transform_accepts_hyphen_op():
    assert transform("base64-encode", "x") == base64.b64encode(b"x").decode()


def test_transform_invalid_op():
    assert "op inválida" in transform("frobnicate", "x")


def test_transform_bad_hex_reports_error():
    assert "erro" in transform("hex_decode", "zz")


# --- tool wrappers ---

@pytest.mark.asyncio
async def test_tool_jwt_decode_requires_token():
    assert "Uso:" in await tool_jwt_decode({})


@pytest.mark.asyncio
async def test_tool_hash_identify_delegates():
    out = await tool_hash_identify({"hash": "5f4dcc3b5aa765d61d8327deb882cf99"})
    assert "MD5" in out


@pytest.mark.asyncio
async def test_tool_encode_decode_requires_args():
    assert "Uso:" in await tool_encode_decode({"op": "base64_encode"})
    assert "Uso:" in await tool_encode_decode({"text": "x"})


@pytest.mark.asyncio
async def test_tool_encode_decode_works():
    assert await tool_encode_decode({"op": "base64_encode", "text": "hi"}) == base64.b64encode(b"hi").decode()
