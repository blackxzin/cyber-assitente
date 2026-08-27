#!/usr/bin/env bash
# Cybersecurity AI — inicia o servidor
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "Ambiente não criado. Rode ./install.sh primeiro."
  exit 1
fi

# Garante que o Ollama está de pé
if ! curl -s -m 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "Ollama offline — iniciando..."
  nohup ollama serve >/dev/null 2>&1 &
  sleep 2
fi

echo "▶ Cybersecurity AI em http://127.0.0.1:8000  (Ctrl+C para parar)"
exec ./.venv/bin/python backend/run.py
