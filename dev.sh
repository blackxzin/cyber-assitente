#!/usr/bin/env bash
# Cybersecurity AI — modo desenvolvimento (auto-reload)
set -euo pipefail
cd "$(dirname "$0")"

[ -d .venv ] || { echo "Rode ./install.sh primeiro."; exit 1; }

if ! curl -s -m 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
  nohup ollama serve >/dev/null 2>&1 &
  sleep 2
fi

./.venv/bin/python -c "import sys; sys.path.insert(0,'backend'); from database import db as d; d.init_db()"
exec ./.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload --app-dir backend
