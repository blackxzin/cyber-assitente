"""Pytest bootstrap: put backend/ on sys.path so tests import it as top-level."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
