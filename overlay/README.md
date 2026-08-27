# Cyber — Desktop Overlay

A personagem do Cybersecurity AI como **mascote na área de trabalho**.

Janela transparente, sem borda, sempre-em-cima e **click-through** (não bloqueia
cliques no desktop). Ela caminha de um lado ao outro da tela com os sprites
fornecidos.

## Como usar

```bash
cd overlay
npm start        # ou: node_modules/electron/dist/electron . --disable-gpu
```

## Atalhos globais

| Atalho | Ação |
|---|---|
| `Ctrl+Shift+C` | Liga/desliga a caminhada |
| `Ctrl+Shift+S` | Volta a personagem para o chão (base da tela) |
| `Ctrl+Shift+X` | Fecha o overlay |

## Reposicionar

Segure o mouse sobre a personagem e **arraste** (o drag é ativado ao clicar
nela — o main temporariamente desativa o click-through).

## Funcionamento

- `main.js` — cria a janela transparente, controla o movimento (`step()`), atalhos globais.
- `index.html` — renderer: mostra os sprites, alterna entre `idle` e `walk`, aplica flip ao inverter direção.
- `preload.js` — ponte segura (contextIsolation) entre renderer e main.
- `hyprland-helper.sh` — configura opacity 1 e regras de janela no Hyprland.

## Sprites

Vêm de `frontend/static/character/` (idle, walk, thinking, speaking, alert,
working, listening, sleep). O caminho é codificado com `pathToFileURL` para
lidar com espaços no diretório.

## Solução de problemas

- **Fundo cinza / não transparente no Hyprland**: rode `./hyprland-helper.sh`
  ou configure `decoration:active_opacity 1` e `decoration:inactive_opacity 1`
  no Hyprland.
- **Crash de GPU**: use `--disable-gpu` (já está no script `npm start`).
- **Não caminha**: confirme que `moving = true` no main.js, ou pressione `Ctrl+Shift+C`.
