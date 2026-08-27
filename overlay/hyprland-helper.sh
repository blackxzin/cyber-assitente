#!/usr/bin/env bash
# Configura o Hyprland para a janela da personagem.
# Regras: sem foco, sem borda, e click-through (input pass).
set -euo pipefail

hyprctl clients -j >/dev/null 2>&1 || { echo "hyprctl indisponível"; exit 0; }

# Click-through (aceitar input pass): via windowrule nopass - NÃO,
# click-through real no Hyprland é feito com 'decoration:dim_inactive'
# desligado + a janela não ter foco + acceptsInput=false.
# A forma mais simples e confiável: usar hyprctl dispatch de windowrule
# para remover a janela do foco, e aplicar opacity 1.

# Opacity total para o transparent funcionar
hyprctl keyword decoration:active_opacity 1 >/dev/null 2>&1 || true
hyprctl keyword decoration:inactive_opacity 1 >/dev/null 2>&1 || true

# windowrules (valem quando a janela abrir; usar --batch para persistir)
hyprctl --batch 'keyword windowrule "nofocus,title:Cyber" ; keyword windowrule "noborder,title:Cyber" ; keyword windowrule "noanim,title:Cyber"' >/dev/null 2>&1 || true

# Click-through: desativa a captura de input da janela pelo compositor
# (a janela continua visível, mas cliques passam para o que está atrás).
# No Hyprland a janela XWayland precisa de acceptsInput=false; o Electron
# já faz isso com setIgnoreMouseEvents. Aqui apenas garantimos nofocus.
exit 0
