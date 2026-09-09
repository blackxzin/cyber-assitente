"""Scanners web modernos estilo ProjectDiscovery/fuzzing (nuclei, ffuf,
wafw00f).

Mesmo padrão argv-exec das ferramentas de `tools/pentest.py`: sem shell,
timeout, saída sanitizada, `requires_confirmation=True` (risk=moderate) —
disparam tráfego real contra o alvo, então o operador revisa alvo/args
antes. Reusa os helpers de validação/execução de `tools.pentest` pra não
duplicar a lógica de normalização de URL e subprocess.
"""

import json

from pathlib import Path

from security.tempfiles import secure_tmp_path
from tools.pentest import _run, _normalize_url, _validate_url
from tools.web import tool_http_headers

# nuclei/ffuf podem rodar mais que os 90s padrão do _run — dão passos por
# muitos templates/palavras. Timeouts próprios, ainda limitados.
_NUCLEI_TIMEOUT = 240
_FFUF_TIMEOUT = 180
_WAFW00F_TIMEOUT = 60
_MAX_HITS = 40

_NUCLEI_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_ORDER = {s: i for i, s in enumerate(_NUCLEI_SEVERITIES)}
_SEV_ICON = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

_FFUF_WORDLIST_DEFAULTS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
)


def _clean_severity(raw: str) -> str:
    """Normaliza o filtro de severidade (aceita 'high,critical' ou vazio).

    Devolve string pronta pro -severity do nuclei. Descarta valores
    desconhecidos — evita injeção de flag e argv inválido.
    """
    parts = [p.strip().lower() for p in str(raw or "").split(",") if p.strip()]
    valid = [p for p in parts if p in _SEV_ORDER]
    return ",".join(valid) if valid else "medium,high,critical"


def _parse_nuclei_jsonl(output: str) -> list[dict]:
    """Cada linha do -jsonl é um objeto JSON de um achado. Linhas que não
    são JSON (banner/log) são ignoradas — parsing best-effort."""
    hits: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return hits


def _format_nuclei_hits(hits: list[dict]) -> str:
    """Ordena por severidade (mais grave primeiro) e formata pra leitura."""
    def sev_of(h: dict) -> str:
        return str(h.get("info", {}).get("severity", "info")).lower()

    hits = sorted(hits, key=lambda h: -_SEV_ORDER.get(sev_of(h), 0))
    lines: list[str] = []
    for h in hits[:_MAX_HITS]:
        info = h.get("info", {})
        sev = sev_of(h)
        icon = _SEV_ICON.get(sev, "⚪")
        name = info.get("name") or h.get("template-id", "?")
        where = h.get("matched-at") or h.get("host", "")
        lines.append(f"  {icon} [{sev}] {name} — {where}")
    extra = len(hits) - _MAX_HITS
    if extra > 0:
        lines.append(f"  ...(+{extra} achados)")
    return "\n".join(lines)


async def tool_nuclei(args: dict) -> str:
    """Scanner de vulnerabilidades por template (nuclei) numa URL/host.

    Roda com rate-limit e filtro de severidade (padrão medium+). 'severity'
    e 'tags' opcionais (ex: tags='cve,exposure', severity='high,critical').
    """
    url = _normalize_url(str(args.get("url") or ""))
    err = _validate_url(url)
    if err:
        return err
    severity = _clean_severity(args.get("severity"))
    argv = [
        "nuclei", "-u", url, "-jsonl", "-silent",
        "-severity", severity,
        "-rate-limit", "50", "-timeout", "10", "-retries", "1",
        "-no-color", "-disable-update-check",
    ]
    tags = str(args.get("tags") or "").strip()
    if tags and all(c.isalnum() or c in ",-_" for c in tags):
        argv += ["-tags", tags]
    out = await _run(argv, timeout=_NUCLEI_TIMEOUT)
    if out.startswith("erro"):
        return out
    hits = _parse_nuclei_jsonl(out)
    if not hits:
        return f"nuclei em {url}: nenhum achado ({severity}). Alvo pode estar limpo pros templates rodados."
    return (f"nuclei em {url} — {len(hits)} achado(s) [{severity}]:\n"
            + _format_nuclei_hits(hits))


def _parse_ffuf_json(raw: str) -> list[dict]:
    """Lê o JSON de saída do ffuf (-of json). 'results' é a lista de hits."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    return data.get("results", []) if isinstance(data, dict) else []


async def tool_ffuf(args: dict) -> str:
    """Fuzzing rápido de diretórios/arquivos com ffuf (alternativa ao
    gobuster). A URL precisa do marcador FUZZ (ex: http://site/FUZZ);
    se não tiver, é anexado no fim do caminho. 'wordlist' opcional."""
    url = _normalize_url(str(args.get("url") or ""))
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    err = _validate_url(url.replace("FUZZ", "x"))
    if err:
        return err
    wordlist = str(args.get("wordlist") or "").strip()
    if not wordlist:
        wordlist = next((w for w in _FFUF_WORDLIST_DEFAULTS if Path(w).is_file()), "")
    if not wordlist:
        return "Uso: informe 'wordlist' (nenhuma wordlist padrão encontrada no sistema)."
    if not Path(wordlist).is_file():
        return f"wordlist não encontrada: {wordlist!r}"
    out_file = str(secure_tmp_path(".json", prefix="cyber_ffuf_"))
    argv = [
        "ffuf", "-u", url, "-w", wordlist,
        "-of", "json", "-o", out_file,
        "-t", "40", "-rate", "200", "-s",
    ]
    mc = str(args.get("match_codes") or "").strip()
    if mc and all(c.isdigit() or c in ",-" for c in mc):
        argv += ["-mc", mc]
    try:
        run_err = await _run(argv, timeout=_FFUF_TIMEOUT)
        if run_err.startswith("erro"):
            return run_err
        if not Path(out_file).exists():
            return f"ffuf em {url}: sem saída."
        results = _parse_ffuf_json(Path(out_file).read_text(errors="replace"))
    finally:
        Path(out_file).unlink(missing_ok=True)
    if not results:
        return f"ffuf em {url}: nada encontrado com essa wordlist."
    lines = [
        f"  {r.get('status', '?')}  {r.get('url', r.get('input', {}).get('FUZZ', '?'))}"
        f"  ({r.get('length', '?')} bytes)"
        for r in results[:_MAX_HITS]
    ]
    extra = len(results) - _MAX_HITS
    if extra > 0:
        lines.append(f"  ...(+{extra} resultados)")
    return f"ffuf em {url} — {len(results)} resultado(s):\n" + "\n".join(lines)


async def tool_wafw00f(args: dict) -> str:
    """Detecta WAF/firewall de aplicação na frente de uma URL (wafw00f)."""
    url = _normalize_url(str(args.get("url") or ""))
    err = _validate_url(url)
    if err:
        return err
    out = await _run(["wafw00f", "-a", "-o", "-", url], timeout=_WAFW00F_TIMEOUT)
    if out.startswith("erro"):
        return out
    return out or f"wafw00f em {url}: sem saída."


async def tool_web_recon_chain(args: dict) -> str:
    """Recon web encadeado numa URL: fingerprint de headers HTTP seguido de
    scan de vulnerabilidades por template (nuclei). Um passo so pro operador,
    juntando o que normalmente seriam duas ferramentas na ordem certa."""
    url = _normalize_url(str(args.get("url") or ""))
    err = _validate_url(url)
    if err:
        return err
    headers = await tool_http_headers({"url": url})
    nuclei = await tool_nuclei({
        "url": url,
        "severity": args.get("severity"),
        "tags": args.get("tags"),
    })
    return "\n".join([
        f"🔗 Recon web encadeado — {url}",
        "",
        "── 1) Headers/fingerprint ──",
        headers,
        "",
        "── 2) Vulnerabilidades (nuclei) ──",
        nuclei,
    ])


def register(registry) -> None:
    for name, desc, fn, required in (
        ("nuclei_scan",
         "Scanner de vulnerabilidades por template com nuclei numa URL "
         "(informe 'url'; 'severity' e 'tags' opcionais).",
         tool_nuclei, ("url",)),
        ("ffuf_scan",
         "Fuzzing rápido de diretórios/arquivos com ffuf (informe 'url'; "
         "'wordlist' e 'match_codes' opcionais).",
         tool_ffuf, ("url",)),
        ("wafw00f_scan",
         "Detecta WAF/firewall de aplicação na frente de uma URL (informe 'url').",
         tool_wafw00f, ("url",)),
        ("web_recon_chain",
         "Recon web encadeado numa URL: headers/fingerprint + nuclei numa "
         "tacada só (informe 'url'; 'severity' e 'tags' opcionais).",
         tool_web_recon_chain, ("url",)),
    ):
        registry.register(
            name, desc, fn,
            risk="moderate", requires_confirmation=True,
            required_args=required, target_arg="url", category="ofensivo",
        )
