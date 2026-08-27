"""Secret sanitization for logs and stored messages.

Redacts credentials, tokens and private keys so they never hit disk
or the LLM context. This runs on every message and tool result
before anything is stored or forwarded.
"""

import re

# Ordered: longer/more specific patterns first so they win the match.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai key", re.compile(r"sk-[A-Za-z0-9_-]{16,}")),
    ("anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("google key", re.compile(r"AIza[0-9A-Za-z_-]{16,}")),
    ("slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github token", re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}")),
    ("aws access", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("api key", re.compile(r"(?i)\b(?:api[_-]?key|apikey|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{8,}")),
]

_REDACTED = "[REDACTED:{}]"


def sanitize_text(text: str) -> str:
    """Replace every detected secret with a redaction marker."""
    for label, pattern in _PATTERNS:
        text = pattern.sub(_REDACTED.format(label), text)
    return text


def sanitize_dict(data: dict) -> dict:
    """Redact string values in a shallow dict (tool results / args)."""
    return {k: (sanitize_text(v) if isinstance(v, str) else v) for k, v in data.items()}
