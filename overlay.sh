#!/usr/bin/env bash
# Cybersecurity AI — inicia a personagem no desktop (overlay) + backend (para a voz PTT)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# --- Backend (/api/chat e /api/audio/*) em background ---
PYBIN="$ROOT/.venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "❌ venv não encontrado em $ROOT/.venv. Rode install.sh primeiro."
  exit 1
fi

# health check: conecta no soquete 8000 (GET dá 405, então testamos a porta)
backend_up() {
  "$PYBIN" -c "import socket,sys; s=socket.create_connection(('127.0.0.1',8000),1); s.close(); sys.exit(0)" 2>/dev/null
}

BACK_PID=""
if backend_up; then
  echo "→ Backend já estava rodando em :8000."
else
  echo "▶ Subindo backend (FastAPI + STT/TTS)…"
  "$PYBIN" backend/run.py > /tmp/cyber-backend.log 2>&1 &
  BACK_PID=$!
  # espera até o servidor responder (máx 30s)
  for i in $(seq 1 30); do
    if backend_up; then break; fi
    sleep 1
  done
  if backend_up; then
    echo "→ Backend no ar (pid $BACK_PID)  log: /tmp/cyber-backend.log"
  else
    echo "⚠️  Backend demorou — voz pode não funcionar. Cheque /tmp/cyber-backend.log"
  fi
fi

cleanup() {
  pkill -9 -f "node_modules/electron/dist/electron" >/dev/null 2>&1 || true
  if [ -n "$BACK_PID" ]; then
    kill "$BACK_PID" >/dev/null 2>&1 || true
    echo "→ backend (pid $BACK_PID) finalizado."
  fi
}
trap cleanup EXIT INT TERM

# --- Overlay (Electron) ---
cd "$ROOT/overlay"
if [ ! -x node_modules/electron/dist/electron ]; then
  echo "Electron não instalado. Rode: cd overlay && npm install"
  exit 1
fi

./hyprland-helper.sh >/dev/null 2>&1 || true

echo ""
echo "▶ Personagem no desktop!"
echo "  Ctrl+Shift+M = voz PTT (aperte pra gravar, solte → responde falado)"
echo "  Ctrl+Shift+V = ela olha a sua tela e comenta (visão NVIDIA)"
echo "  Ctrl+Shift+S = voltar ao chão"
echo "  Ctrl+Shift+X = fechar"
echo "  Clique nela = menu (chat, voz, olhar tela, status…)"
echo ""
exec node_modules/electron/dist/electron . --disable-gpu
