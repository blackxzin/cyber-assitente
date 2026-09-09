"""Testes de tools/pipeline.py (recon_pipeline). nmap/http_headers/nuclei
mockados via monkeypatch — nunca dispara scan real."""

import pytest

from tools import pipeline
from tools.pipeline import _web_targets, tool_recon_pipeline

_NMAP_SAMPLE = """\
22/tcp   open  ssh     OpenSSH 8.9
80/tcp   open  http    nginx 1.18
443/tcp  open  https   nginx 1.18
8080/tcp open  http-proxy
3306/tcp open  mysql   MySQL 8.0
"""


def test_web_targets_picks_only_web_ports():
    urls = _web_targets(_NMAP_SAMPLE)
    assert "http://__HOST__" in urls          # 80 = default http, sem porta
    assert "https://__HOST__" in urls         # 443 = default https, sem porta
    assert "http://__HOST__:8080" in urls     # proxy web em porta não-padrão
    assert all("22" not in u and "3306" not in u for u in urls)  # ssh/mysql fora


def test_web_targets_empty_when_no_web():
    assert _web_targets("22/tcp open ssh\n3306/tcp open mysql\n") == []


def test_web_targets_caps_at_max():
    many = "\n".join(f"{p}/tcp open http" for p in range(8000, 8010))
    assert len(_web_targets(many)) <= 4


@pytest.mark.asyncio
async def test_pipeline_rejects_bad_host():
    out = await tool_recon_pipeline({"host": "-flag"})
    assert "inválido" in out.lower()


@pytest.mark.asyncio
async def test_pipeline_stops_when_no_web(monkeypatch):
    async def fake_nmap(args):
        return "22/tcp open ssh\n3306/tcp open mysql"
    monkeypatch.setattr(pipeline, "tool_nmap_scan", fake_nmap)
    out = await tool_recon_pipeline({"host": "10.0.0.5"})
    assert "Nenhum serviço web" in out


@pytest.mark.asyncio
async def test_pipeline_runs_full_chain(monkeypatch):
    calls = {"headers": [], "nuclei": []}

    async def fake_nmap(args):
        return "80/tcp open http nginx"

    async def fake_headers(args):
        calls["headers"].append(args["url"])
        return "Server: nginx"

    async def fake_nuclei(args):
        calls["nuclei"].append(args["url"])
        return "nuclei: nenhum achado"

    monkeypatch.setattr(pipeline, "tool_nmap_scan", fake_nmap)
    monkeypatch.setattr(pipeline, "tool_http_headers", fake_headers)
    monkeypatch.setattr(pipeline, "tool_nuclei", fake_nuclei)
    out = await tool_recon_pipeline({"host": "10.0.0.5", "severity": "high"})
    assert "http://10.0.0.5" in calls["headers"]
    assert "http://10.0.0.5" in calls["nuclei"]
    assert "Pipeline de recon" in out
    assert "nginx" in out
