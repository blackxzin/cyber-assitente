"""Pentest report generator: compiles recent audit actions (tool_calls) and
alerts into a single Markdown report — a hand-off/archive artifact per
engagement, built from the same audit trail already persisted by
ChatService.stream() (see backend/services/chat.py)."""

from datetime import datetime, timezone

from database import db as database

# Ferramentas relevantes pra um relatório de pentest — exclui leituras de
# sistema (memory_info, disk_info...) que não são "achados" de engagement.
PENTEST_TOOLS = (
    "nmap_scan", "sqlmap_scan", "hydra_bruteforce", "gobuster_scan",
    "nikto_scan", "packet_capture", "cpf_osint",
    "burp_search_history", "burp_find_vulnerabilities", "burp_proxy_history",
)

_SNIPPET_LINES = 20


def generate_pentest_report(limit: int = 200) -> str:
    """Builds the report as a Markdown string, most recent action last
    within each tool's section (chronological reading order)."""
    placeholders = ",".join("?" * len(PENTEST_TOOLS))
    with database.db() as conn:
        rows = conn.execute(
            f"SELECT tool, result, status, created_at FROM tool_calls "  # nosec B608
            f"WHERE tool IN ({placeholders}) ORDER BY id DESC LIMIT ?",
            (*PENTEST_TOOLS, limit),
        ).fetchall()
        alerts = conn.execute(
            "SELECT severity, title, description, created_at FROM alerts ORDER BY id DESC LIMIT 50"
        ).fetchall()
    calls = list(reversed(rows))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = ["# Relatório de Pentest", "", f"Gerado em {now}.", "", "## Sumário"]
    lines.append(f"- {len(calls)} ação(ões) de auditoria registrada(s)")
    lines.append(f"- {len(alerts)} alerta(s) no histórico")
    lines.append("")

    if not calls:
        lines.append("Nenhuma ação de pentest registrada ainda.")
    else:
        by_tool: dict[str, list] = {}
        for row in calls:
            by_tool.setdefault(row["tool"], []).append(row)
        lines.append("## Achados por ferramenta")
        for tool in sorted(by_tool):
            tool_rows = by_tool[tool]
            lines.append(f"### {tool} ({len(tool_rows)} execução(ões))")
            for row in tool_rows:
                mark = "✅" if row["status"] == "ok" else "⚠️"
                lines.append(f"- {mark} {row['created_at']}")
                snippet = (row["result"] or "").strip()
                if snippet:
                    body_lines = snippet.splitlines()[:_SNIPPET_LINES]
                    lines.append("  ```")
                    lines.extend(f"  {line}" for line in body_lines)
                    if len(snippet.splitlines()) > _SNIPPET_LINES:
                        lines.append("  ...[truncado]")
                    lines.append("  ```")
            lines.append("")

    if alerts:
        lines.append("## Alertas")
        for a in alerts:
            lines.append(
                f"- **[{a['severity'].upper()}]** {a['title']} — {a['description']} ({a['created_at']})"
            )
        lines.append("")

    return "\n".join(lines)
