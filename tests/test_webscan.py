"""Testes das ferramentas de scan web modernas (nuclei, ffuf, wafw00f).

Sem tocar nos binários reais: `_run` (importado de tools.pentest e usado
por webscan) é mockado via monkeypatch — só validação/argv/parsing são
exercitados aqui.
"""

import json

import pytest

from tools import webscan
from tools.webscan import (
    _clean_severity,
    _format_nuclei_hits,
    _parse_ffuf_json,
    _parse_nuclei_jsonl,
    tool_ffuf,
    tool_nuclei,
    tool_wafw00f,
)


# ---- helpers puros ----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("high,critical", "high,critical"),
    ("HIGH, Critical", "high,critical"),
    ("", "medium,high,critical"),
    ("bogus", "medium,high,critical"),
    ("info,bogus,low", "info,low"),
])
def test_clean_severity(raw, expected):
    assert _clean_severity(raw) == expected


def test_parse_nuclei_jsonl_ignores_non_json_lines():
    out = (
        "[INF] banner line\n"
        '{"template-id":"x","info":{"name":"XSS","severity":"high"},"matched-at":"http://a/x"}\n'
        "garbage\n"
        '{"template-id":"y","info":{"name":"Info","severity":"info"},"host":"http://a"}\n'
    )
    hits = _parse_nuclei_jsonl(out)
    assert len(hits) == 2


def test_format_nuclei_hits_sorts_by_severity_desc():
    hits = [
        {"info": {"name": "low-one", "severity": "low"}, "matched-at": "u1"},
        {"info": {"name": "crit-one", "severity": "critical"}, "matched-at": "u2"},
    ]
    formatted = _format_nuclei_hits(hits)
    assert formatted.index("crit-one") < formatted.index("low-one")


def test_parse_ffuf_json_reads_results():
    raw = json.dumps({"results": [{"status": 200, "url": "http://a/admin", "length": 42}]})
    assert len(_parse_ffuf_json(raw)) == 1
    assert _parse_ffuf_json("not json") == []


# ---- nuclei -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_nuclei_rejects_bad_url():
    out = await tool_nuclei({"url": "-bad flag"})
    assert "inválida" in out.lower() or "uso" in out.lower()


@pytest.mark.asyncio
async def test_nuclei_builds_expected_argv(monkeypatch):
    captured = {}

    async def fake_run(argv, timeout=90):
        captured["argv"] = argv
        return '{"template-id":"t","info":{"name":"N","severity":"high"},"matched-at":"http://x/"}'

    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_nuclei({"url": "x.com", "severity": "high,critical", "tags": "cve,exposure"})
    argv = captured["argv"]
    assert argv[0] == "nuclei"
    assert "-jsonl" in argv
    assert "high,critical" in argv
    assert "-tags" in argv and "cve,exposure" in argv
    assert "http://x.com" in argv
    assert "achado" in out.lower()


@pytest.mark.asyncio
async def test_nuclei_drops_bogus_tags(monkeypatch):
    captured = {}

    async def fake_run(argv, timeout=90):
        captured["argv"] = argv
        return ""

    monkeypatch.setattr(webscan, "_run", fake_run)
    await tool_nuclei({"url": "x.com", "tags": "cve;rm -rf"})
    assert "-tags" not in captured["argv"]  # tag com ';' e espaço descartada


@pytest.mark.asyncio
async def test_nuclei_no_findings_message(monkeypatch):
    async def fake_run(argv, timeout=90):
        return ""

    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_nuclei({"url": "x.com"})
    assert "nenhum achado" in out.lower()


# ---- ffuf -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ffuf_appends_fuzz_marker(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    captured = {}

    async def fake_run(argv, timeout=90):
        captured["argv"] = argv
        # simula o ffuf gravando o arquivo -o
        idx = argv.index("-o")
        from pathlib import Path
        Path(argv[idx + 1]).write_text(json.dumps(
            {"results": [{"status": 200, "url": "http://x.com/admin", "length": 10}]}))
        return ""

    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_ffuf({"url": "x.com", "wordlist": str(wl)})
    assert "FUZZ" in " ".join(captured["argv"])
    assert "admin" in out


@pytest.mark.asyncio
async def test_ffuf_missing_wordlist(monkeypatch):
    async def fake_run(argv, timeout=90):
        return ""

    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_ffuf({"url": "x.com", "wordlist": "/nope/nao_existe.txt"})
    assert "não encontrada" in out.lower()


# ---- wafw00f ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_wafw00f_passes_url(monkeypatch):
    captured = {}

    async def fake_run(argv, timeout=90):
        captured["argv"] = argv
        return "http://x.com is behind Cloudflare"

    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_wafw00f({"url": "x.com"})
    assert "http://x.com" in captured["argv"]
    assert "Cloudflare" in out


# ---- web_recon_chain --------------------------------------------------------

@pytest.mark.asyncio
async def test_web_recon_chain_combines_steps(monkeypatch):
    from tools.webscan import tool_web_recon_chain

    async def fake_headers(args):
        return "Server: nginx; sem HSTS"

    async def fake_run(argv, timeout=90):
        return '{"template-id":"t","info":{"name":"CVE-X","severity":"high"},"matched-at":"http://x/"}'

    monkeypatch.setattr(webscan, "tool_http_headers", fake_headers)
    monkeypatch.setattr(webscan, "_run", fake_run)
    out = await tool_web_recon_chain({"url": "x.com"})
    assert "Headers/fingerprint" in out
    assert "nginx" in out
    assert "Vulnerabilidades" in out
    assert "CVE-X" in out
