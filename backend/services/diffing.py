"""Tiny line-set diff helper shared by anything that watches text output
for change over time (nmap scans, `ss` listening sockets, ...).
"""

import re


def new_lines(previous: str | None, current: str, pattern: re.Pattern) -> list[str]:
    """Lines matched by 'pattern' in 'current' that were absent from 'previous'."""
    prev = {m.group(0) for m in pattern.finditer(previous)} if previous else set()
    cur = {m.group(0) for m in pattern.finditer(current)}
    return sorted(cur - prev)
