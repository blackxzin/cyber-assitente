#!/usr/bin/env bash
# Instala as ferramentas ofensivas que o Cyber usa. Detecta o que já existe e
# só instala o que falta. Suporta Arch (pacman) + pipx pras ferramentas Python.
# Uso: ./install-tools.sh   (pede sudo só se precisar instalar algo via pacman)
set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf "  %-14s %s\n" "$1" "$2"; }

echo "▶ Ferramentas ofensivas — estado atual:"
# binário -> pacote pacman (repo oficial)
declare -A PAC=(
  [nmap]=nmap [sqlmap]=sqlmap [gobuster]=gobuster [nikto]=nikto
  [hydra]=hydra [dumpcap]=wireshark-cli [tshark]=wireshark-cli
  [r2]=radare2 [yara]=yara [searchsploit]=exploitdb
)
# binário -> pacote pipx (PyPI)
declare -A PIPX=( [holehe]=holehe [sherlock]=sherlock-project )

missing_pac=()
for bin in "${!PAC[@]}"; do
  if have "$bin"; then say "$bin" "OK"; else say "$bin" "faltando (pacman: ${PAC[$bin]})"; missing_pac+=("${PAC[$bin]}"); fi
done
missing_pipx=()
for bin in "${!PIPX[@]}"; do
  if have "$bin"; then say "$bin" "OK"; else say "$bin" "faltando (pipx: ${PIPX[$bin]})"; missing_pipx+=("${PIPX[$bin]}"); fi
done

# dedup pacman
if ((${#missing_pac[@]})); then
  uniq_pac=$(printf "%s\n" "${missing_pac[@]}" | sort -u | tr '\n' ' ')
  if have pacman; then
    echo; echo "▶ Instalando via pacman: $uniq_pac"
    sudo pacman -S --needed $uniq_pac || echo "⚠ pacman falhou em algum pacote — instale manualmente."
  else
    echo; echo "⚠ pacman não encontrado. Instale manualmente: $uniq_pac"
  fi
fi

if ((${#missing_pipx[@]})); then
  echo; echo "▶ Ferramentas Python (pipx): ${missing_pipx[*]}"
  if have pipx; then
    for p in "${missing_pipx[@]}"; do pipx install "$p" || echo "⚠ pipx install $p falhou"; done
  else
    echo "⚠ pipx não encontrado. Instale com: sudo pacman -S python-pipx"
  fi
fi

echo; echo "✓ Pronto. Rode de novo pra reconferir."
