#!/usr/bin/env bash
# Sobe o VulnLab (alvo de treino local). Uso: ./run_lab.sh [porta]
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-8666}"
PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
exec "$PY" lab/vulnerable_app.py --port "$PORT"
