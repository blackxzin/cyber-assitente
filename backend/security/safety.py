"""Safety Layer: the single gate that classifies every requested action.

Decision flow:
    allow   → execute (read-only, allowlisted)
    confirm → needs human confirmation (warn with explanation)
    block   → refused outright (dangerous / destructive / off-policy)

The safe_mode setting never loosens a block: it only decides whether
an 'unknown' becomes 'allow' or 'confirm'.
"""

import re
from enum import Enum

from config.settings import settings

from .logging import log_event
from .sanitize import sanitize_text


class Risk(Enum):
    INFO = "info"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"


class Decision(Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


# Destructive/system-mutating patterns that are always blocked.
_BLOCK_PATTERNS: tuple[str, ...] = (
    "rm ",
    "rm -",
    "rm /",
    "dd ",
    "mkfs",
    "fdisk",
    "parted",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init ",
    "> /dev/sd",
    ">/dev/sd",
    ":(){",
    "chown ",
    "chmod 777",
    "kill -9",
    "kill -s",
    "systemctl stop",
    "systemctl disable",
    "iptables -F",
    "nft flush",
)

# Ferramentas ofensivas (nmap, sqlmap, hydra, gobuster, nikto, masscan,
# metasploit, hashcat, john, aircrack, ettercap, bettercap...) não são
# bloqueadas por nome: são ferramentas registradas (backend/tools/pentest.py)
# gated por CONFIRMAÇÃO humana (risk=moderate), igual qualquer outra ação
# que mexe fora da máquina local. O que fica sempre bloqueado abaixo é
# dano à própria máquina local (_BLOCK_PATTERNS), não o uso ofensivo em si.
_POLICY_BLOCKS: tuple[str, ...] = ()


def _matches(pattern: str, lowered: str) -> bool:
    """Word-boundary-aware match on both sides: 'rm ' must not fire inside
    'confirm ', and 'john' must not fire inside 'johnson'."""
    boundary = r"(?![a-z0-9])" if pattern[-1].isalnum() else ""
    return re.search(r"(?<![a-z0-9])" + re.escape(pattern) + boundary, lowered) is not None


def classify_action(action: str, risk: Risk) -> Decision:
    """Classify a free-text or command-line action into a Decision."""
    action = sanitize_text(action.strip())

    lowered = action.lower()

    # Off-policy tooling is always blocked — no override exists.
    for pat in _POLICY_BLOCKS:
        if _matches(pat, lowered):
            log_event("danger", "safety", f"bloqueado: {action}")
            return Decision.BLOCK

    if risk == Risk.DANGEROUS:
        log_event("danger", "safety", f"bloqueado: {action}")
        return Decision.BLOCK

    if risk == Risk.MODERATE:
        for pat in _BLOCK_PATTERNS:
            if _matches(pat, lowered):
                return Decision.BLOCK
        return Decision.CONFIRM

    # INFO-level actions: reads and harmless queries.
    if settings.safe_mode == "safe":
        return Decision.CONFIRM  # everything needs a nod in read-only mode
    if settings.safe_mode == "assisted":
        return Decision.ALLOW
    return Decision.ALLOW  # advanced: still respects the blocks above
