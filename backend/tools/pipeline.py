"""Pipeline de recon encadeado: nmap → (detecção de serviço web) → nuclei.

Junta o fluxo clássico ProjectDiscovery (descobrir portas → provar quais
falam HTTP → escanear vuln) numa ferramenta só. Dispara tráfego real e
múltiplos scans contra o alvo → risk=moderate, confirmação humana,
target_arg=host. Reusa as ferramentas já existentes (nmap_scan, http_headers,
nuclei_scan) em vez de reimplementar cada passo.
"""

import re

from tools.pentest import tool_nmap_scan, _validate_target
from tools.webscan import tool_http_headers, tool_nuclei

# Porta aberta com serviço identificado pelo nmap: "80/tcp open http ...".
_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)
# Serviços que falam HTTP(S) — os que valem passar pro nuclei.
_WEB_SERVICES = ("http", "https", "http-proxy", "https-alt", "http-alt", "www", "ssl")
_MAX_WEB_TARGETS = 4


def _web_targets(nmap_output: str) -> list[str]:
    """Extrai URLs http(s) das portas web abertas no nmap. https pra portas
    443/8443 ou serviço com 'https'/'ssl'; http pro resto."""
    targets: list[str] = []
    seen: set[str] = set()
    for port, service in _PORT_RE.findall(nmap_output):
        svc = service.lower()
        if not any(w in svc for w in _WEB_SERVICES):
            continue
        secure = port in ("443", "8443") or "https" in svc or "ssl" in svc
        scheme = "https" if secure else "http"
        default = (scheme == "http" and port == "80") or (scheme == "https" and port == "443")
        url = f"{scheme}://__HOST__" if default else f"{scheme}://__HOST__:{port}"
        if url not in seen:
            seen.add(url)
            targets.append(url)
    return targets[:_MAX_WEB_TARGETS]


async def tool_recon_pipeline(args: dict) -> str:
    """nmap → detecta serviços web → nuclei em cada um. 'severity'/'tags'
    opcionais são repassados pro nuclei."""
    host = str(args.get("host") or "").strip()
    err = _validate_target(host)
    if err:
        return err

    nmap_out = await tool_nmap_scan({"host": host})
    blocks = [f"🧭 Pipeline de recon — {host}", "", "── 1) nmap ──", nmap_out]

    urls = [u.replace("__HOST__", host) for u in _web_targets(nmap_out)]
    if not urls:
        blocks += ["", "Nenhum serviço web detectado no nmap — pipeline para aqui "
                   "(sem alvo pra nuclei)."]
        return "\n".join(blocks)

    blocks += ["", f"── 2) serviços web detectados ({len(urls)}) ──", *(f"  {u}" for u in urls)]
    for url in urls:
        headers = await tool_http_headers({"url": url})
        nuclei = await tool_nuclei({
            "url": url,
            "severity": args.get("severity"),
            "tags": args.get("tags"),
        })
        blocks += ["", f"── 3) {url} ──", "· headers:", headers, "· nuclei:", nuclei]
    return "\n".join(blocks)


def register(registry) -> None:
    registry.register(
        "recon_pipeline",
        "Pipeline encadeado num host: nmap → detecta serviços web → headers "
        "+ nuclei em cada um (informe 'host'; 'severity' e 'tags' opcionais).",
        tool_recon_pipeline,
        risk="moderate", requires_confirmation=True,
        required_args=("host",), target_arg="host", category="ofensivo",
    )
