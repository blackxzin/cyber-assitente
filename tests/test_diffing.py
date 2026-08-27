"""Testes do helper genérico de diff de linhas (services/diffing.py) e do
uso concreto em pentest.py (novas portas abertas entre dois scans)."""

from tools.pentest import _OPEN_PORT_RE
from services.diffing import new_lines

NMAP_BEFORE = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7
80/tcp   open  http    nginx 1.26
"""

NMAP_AFTER = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7
80/tcp   open  http    nginx 1.26
6379/tcp open  redis   Redis 7.2
"""


def test_new_lines_detects_newly_opened_port():
    added = new_lines(NMAP_BEFORE, NMAP_AFTER, _OPEN_PORT_RE)
    assert len(added) == 1
    assert added[0].startswith("6379/tcp")


def test_new_lines_empty_when_nothing_changed():
    assert new_lines(NMAP_BEFORE, NMAP_BEFORE, _OPEN_PORT_RE) == []


def test_new_lines_with_no_previous_returns_every_match():
    # Caller (pentest.py/watcher.py) is responsible for skipping the diff
    # entirely on a first-ever scan; the helper itself has no baseline to
    # compare against, so everything currently matched counts as "new".
    added = new_lines(None, NMAP_AFTER, _OPEN_PORT_RE)
    assert len(added) == 3
