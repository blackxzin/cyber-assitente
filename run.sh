#!/usr/bin/env bash
# Cybersecurity AI — sobe tudo: servidor (chat) + personagem no desktop (overlay voz PTT).
# Uso: ./run.sh   (Ctrl+C encerra os dois)
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "Ambiente não criado. Rode ./install.sh primeiro."
  exit 1
fi

# mata instâncias antigas (evita crash de GPU no Hyprland)
pkill -9 -f "backend/run.py" 2>/dev/null || true
pkill -9 -f "node_modules/electron/dist/electron" 2>/dev/null || true
sleep 1

# --- 1. Ollama ---
if ! curl -s -m 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "Ollama offline — iniciando..."
  nohup ollama serve >/dev/null 2>&1 &
  sleep 2
fi

# --- 2. servidor (chat + API) ---
echo "▶ Subindo servidor..."
.venv/bin/python backend/run.py >/tmp/cyber-srv.log 2>&1 &
SRV=$!

# espera a porta responder (timeout 20s)
for i in $(seq 1 20); do
  if curl -s -m 1 http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -s -m 1 http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
  echo "✗ Servidor não subiu. Log:"
  tail -15 /tmp/cyber-srv.log
  kill $SRV 2>/dev/null || true
  exit 1
fi
echo "✓ Chat em http://127.0.0.1:8000  (abra no navegador)"

# --- 3. overlay (personagem no desktop) ---
echo "▶ Personagem no desktop!"
echo "  Ctrl+Shift+M = voz (segure p/ falar)"
echo "  Ctrl+Shift+C = liga/desliga caminhada"
echo "  Ctrl+Shift+X = fechar personagem"
echo "  Ctrl+C aqui  = encerra tudo"

cd overlay
./hyprland-helper.sh 2>/dev/null || true

# encerra tudo ao sair (Ctrl+C)
trap 'echo; echo "encerrando..."; kill $SRV 2>/dev/null || true; pkill -9 -f "node_modules/electron/dist/electron" 2>/dev/null || true' EXIT INT TERM

exec node_modules/electron/dist/electron . --disable-gpu
