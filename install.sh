#!/usr/bin/env bash
# Cybersecurity AI — instalação local (Arch/Debian + Ollama)
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 1/3 Criando ambiente Python"
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

if [ ! -d "$HOME/cpfFinder" ]; then
  echo "==> 1b/3 cpfFinder não encontrado em ~/cpfFinder (usado pela ferramenta cpf_osint)."
  echo "    Clone com:  git clone https://github.com/p1ngul1n0/cpfFinder ~/cpfFinder"
fi

echo "==> 2/3 Verificando Ollama"
if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama não encontrado. Instale em https://ollama.com e rode: ollama pull dolphin-llama3"
  exit 1
fi
if ! ollama list 2>/dev/null | grep -q dolphin-llama3; then
  echo "Baixando modelo dolphin-llama3 (sem filtro, para cyber defensivo)..."
  ollama pull dolphin-llama3
fi

echo "==> 3/3 Banco de dados"
./.venv/bin/python -c "import sys; sys.path.insert(0,'backend'); from database import db as d; d.init_db(); print('DB OK em', d.DB_PATH)"

echo
echo "Instalado! Rode:  ./start.sh"
echo "Depois abra http://127.0.0.1:8000"
echo
echo "Dica — overlay desktop (personagem):"
echo "    cd overlay && npm install && cd .. && ./run.sh"
