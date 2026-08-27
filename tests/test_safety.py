"""Self-check para o Safety Layer — roda com stdlib, sem framework.

    .venv/bin/python tests/test_safety.py
"""

import asyncio
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from security.safety import Risk, classify_action  # noqa: E402
from security.sanitize import sanitize_text  # noqa: E402
from tools.terminal import executor  # noqa: E402


async def main() -> int:
    failures = 0

    def check(label: str, got, want) -> None:
        nonlocal failures
        ok = got == want
        print(f"  {'PASS' if ok else 'FAIL'}  {label}  -> {got!r} (esperado {want!r})")
        if not ok:
            failures += 1

    print("== Safety Layer ==")
    # DANGEROUS always blocks, even in advanced mode
    check("rm -rf bloqueado", classify_action("rm -rf /", Risk.MODERATE).value, "block")
    check("shutdown bloqueado", classify_action("systemctl stop sshd", Risk.MODERATE).value, "block")
    check("kill -9 bloqueado", classify_action("kill -9 123", Risk.MODERATE).value, "block")
    # nmap agora é ferramenta registrada (confirmável), não mais off-policy
    check("nmap moderate → confirm", classify_action("nmap 192.168.1.1", Risk.MODERATE).value, "confirm")
    check("nmap info → allow (assisted)", classify_action("nmap 192.168.1.1", Risk.INFO).value, "allow")
    check("masscan não é mais off-policy", classify_action("masscan 192.168.1.1", Risk.INFO).value, "allow")
    check("wireshark não é mais off-policy", classify_action("wireshark -i eth0", Risk.MODERATE).value, "confirm")
    # INFO reads are allowed in assisted mode (default)
    check("info → allow (assisted)", classify_action("df -h", Risk.INFO).value, "allow")

    print("== Executor ==")
    check("ip addr = allow", executor.classify_command(["ip", "addr"]), "allow")
    check("rm -rf / = deny", executor.classify_command(["rm", "-rf", "/"]), "deny")
    check("echo foo = deny (não-lista)", executor.classify_command(["echo", "foo"]), "unknown")
    check("subshell = deny", executor.classify_command(["echo", "$(whoami)"]), "deny")
    check("ss -tulnp = allow", executor.classify_command(["ss", "-tulnp"]), "allow")
    check("systemctl list-units = allow", executor.classify_command(
        ["systemctl", "--no-pager", "--plain", "list-units", "--type=service", "--state=running"]), "allow")
    check("systemctl stop = deny", executor.classify_command(["systemctl", "stop", "sshd"]), "deny")
    check("ping host = unknown (fora allowlist)", executor.classify_command(
        ["ping", "-c", "1", "-W", "1", "8.8.8.8"]), "unknown")

    # run_safe_command actually executes an allowlisted command
    out, err = await executor.run_safe_command(["hostname"])
    print(f"  {'PASS' if out.strip() else 'FAIL'}  hostname executou ({out.strip()!r})")
    if not out.strip():
        failures += 1

    # nova allowlist executa de verdade
    out, _ = await executor.run_safe_command(["ss", "-tulnp"])
    print(f"  {'PASS' if out.strip() else 'FAIL'}  ss -tulnp executou")
    if not out.strip():
        failures += 1

    # blocked command raises, never executes
    try:
        await executor.run_safe_command(["rm", "-rf", "/tmp/x"])
        print("  FAIL  rm -rf não foi bloqueado")
        failures += 1
    except ValueError:
        print("  PASS  rm -rf bloqueado na execução")

    print("== Ferramentas confirmáveis ==")
    from tools import build_registry  # noqa: E402
    reg = build_registry()
    for name in ("nmap_scan", "packet_capture", "cpf_osint",
                 "sqlmap_scan", "hydra_bruteforce", "gobuster_scan", "nikto_scan"):
        spec = reg.get(name)
        check(f"{name} registrada", spec is not None, True)
        if spec:
            check(f"{name} exige confirmação", spec.requires_confirmation, True)
            check(f"{name} risk moderate", spec.risk, "moderate")

    # cpf_osint valida CPF antes de executar qualquer coisa
    check("cpf_osint rejeita cpf curto", await reg.run("cpf_osint", {"cpf": "123"}), "Uso: informe um 'cpf' com 11 dígitos (ex: 12345678901).")

    print("== Sanitização ==")
    dirty = "use a api_key=abc12345xyz e token xoxb-1234567890-abcdefghij"
    clean = sanitize_text(dirty)
    check("api_key redigido", "abc12345xyz" in clean, False)
    check("xoxb redigido", "xoxb-1234567890" in clean, False)

    print(f"\n{'TODOS OS TESTES PASSARAM' if failures == 0 else f'{failures} FALHA(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
