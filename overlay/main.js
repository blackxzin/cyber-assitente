// Cybersecurity AI — Personagem overlay na área de trabalho.
//
// Cria uma janela transparente, sem borda, sempre-em-cima e click-through
// (ignora cliques do mouse) que mostra a personagem animada andando.
// A interação acontece por atalhos globais e por arrastar com a tecla
// modificadora pressionada (para quem quiser reposicionar).

const { app, BrowserWindow, globalShortcut, screen, shell, ipcMain } = require("electron");
const path = require("path");
const { execFile } = require("child_process");

// --- Configurações (podem vir de um arquivo depois) ---
const CONFIG = {
  height: 150,          // altura da janela/personagem em px (sprites ~2:1, então largura ≈ 75)
  speed: 55,            // velocidade de caminhada em px/s (genuíno, não por-tick)
  walkFps: 8,           // frames por segundo da animação de caminhada
  idleFps: 6,           // fps do idle
  gravity: true,        // ficar "no chão" do workspace (menor y)
  debug: false,
};

const ROOT = path.join(__dirname, "..");
const SPRITE_DIR = path.join(ROOT, "frontend", "static", "character");

// Estados de animação (espelham frontend/static/character/manifest.json canvas_size).
// canvas_size = [largura, altura]. A janela usa a MAIOR altura e a MAIOR largura relativa
// para caber todos os estados sem cortar; object-fit:contain centraliza cada frame.
const CANVAS = {
  idle:      [78, 198], walk: [93, 193], thinking: [86, 103],
  listening: [83, 103], speaking: [86, 123], alert: [78, 133],
};
const MAX_H = Math.max(...Object.values(CANVAS).map((c) => c[1]));          // 198
const MAX_W_BY_MAX_H = Math.max(...Object.values(CANVAS)                     // largura do sprite mais largo... p/ janela com altura=MAX_H
  .map((c) => c[0] * (MAX_H / c[1])));
const WIN_W = Math.round(CONFIG.height * (MAX_W_BY_MAX_H / MAX_H));        // largura da janela p/ altura=height
const WIN_H = CONFIG.height;

const STATES = {
  idle:      { dir: "idle",      frames: 6, fps: CONFIG.idleFps },
  walk:      { dir: "walk",      frames: 7, fps: CONFIG.walkFps },
  thinking:  { dir: "thinking",  frames: 3, fps: 4 },
  listening: { dir: "listening",frames: 3, fps: 5 },
  talking:   { dir: "speaking",  frames: 7, fps: 10 },
  alert:     { dir: "alert",     frames: 3, fps: 5 },
};

// --- Voz PTT ---
const BACKEND = "http://127.0.0.1:8000";
let recording = false;
let recPath = "/tmp/cyber_voice.wav";
let recProc = null;
let voiceState = null;  // quando ativo (listening/thinking/talking/alert), sobrepõe walk/idle

let win = null;
let x = 100;
let y = 0;
let width = WIN_W;
let height = WIN_H;
let moving = true; // caminha sempre; nunca para/dorme (estados de voz sobrepõem)
let direction = 1; // 1 = direita, -1 = esquerda
let dragging = false;
let dragOffsetX = 0;
let dragOffsetY = 0;

// --- helpers ---
const pad2 = (n) => String(n).padStart(2, "0");
function spriteUrl(state, frame) {
  const s = STATES[state];
  const { pathToFileURL } = require("url");
  return pathToFileURL(path.join(SPRITE_DIR, s.dir, `${s.dir}_${pad2(frame)}.png`)).href;
}

function getScreenSize() {
  // usa a tela do cursor (ativa) — evita "sumir" em outro monitor/workspace
  try {
    const pt = screen.getCursorScreenPoint();
    const d = screen.getDisplayNearestPoint(pt);
    if (d && d.bounds) return d.bounds;
  } catch {}
  const displays = screen.getAllDisplays();
  return displays.length ? displays[0].bounds : { width: 1440, height: 900 };
}

function createWindow() {
  const { width: sw, height: sh } = getScreenSize();
  width = WIN_W;
  height = WIN_H;
  x = 100;
  y = CONFIG.gravity ? sh - height - 40 : 40; // perto do chão
  console.log(`[overlay] window x=${x} y=${y} w=${width} h=${height} screen=${sw}x${sh}`);

  win = new BrowserWindow({
    title: "Cyber",
    width,
    height,
    x,
    y,
    transparent: true,
    backgroundColor: "#00000000",
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    hasShadow: false,
    focusable: false,
    skipTaskbar: true,
    fullscreenable: false,
    // type "toolbar" esconde em alguns compositores Wayland; sem type fica janela normal
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
    },
  });

  win.setAlwaysOnTop(true, "screen-saver");
  win.setIgnoreMouseEvents(true, { forward: true });
  win.loadFile(path.join(__dirname, "index.html"));

  win.webContents.on("did-finish-load", () => {
    sendConfig();
    step();
    startReactions();
    startAlertWatch();
  });

  // DEBUG: captura a janela real após 4s e salva (só com CONFIG.debug=true)
  if (CONFIG.debug) {
    setTimeout(() => {
      win.webContents.capturePage().then((img) => {
        const fs = require("fs");
        fs.writeFileSync("/tmp/cyber-overlay-live.png", img.toPNG());
        console.log("LIVE CAPTURE:", JSON.stringify(img.getSize()));
      });
    }, 4000);
  }

  // Roteia console do renderer pro stdout para debug
  win.webContents.on("console-message", (_e, level, message) => {
    console.log(`[renderer:${level}] ${message}`);
  });

  // Hotkeys globais (funcionam mesmo com a janela sem foco)
  // Ctrl+Shift+C: sem efeito — a personagem anda sempre (interage por voz/estados)
  globalShortcut.register("CommandOrControl+Shift+X", () => {
    globalShortcut.unregisterAll();
    app.quit();
  });
  globalShortcut.register("CommandOrControl+Shift+S", () => {
    y = getScreenSize().height - height - 60;
    win.setPosition(Math.round(x), Math.round(y));
  });

  // PTT: um toque inicia a gravação, outro para e processa voz→chat→TTS.
  globalShortcut.register("CommandOrControl+Shift+M", () => {
    if (recording) stopAndChat();
    else startRecording();
  });

  // Ver a tela: captura o desktop, pergunta à visão (NVIDIA) e fala a resposta.
  globalShortcut.register("CommandOrControl+Shift+V", () => {
    lookAtScreen();
  });

  // Recebe mensagens do renderer
  // Recebe mensagens do renderer via IPC (canal explícito)
  const { ipcMain } = require("electron");
  ipcMain.on("overlay-drag-start", (_e, mx, my) => {
    dragging = true;
    const pos = win.getPosition();
    dragOffsetX = mx - x;
    dragOffsetY = my - y;
    win.setIgnoreMouseEvents(false);
  });
  ipcMain.on("overlay-drag-end", () => {
    dragging = false;
    win.setIgnoreMouseEvents(true, { forward: true });
  });

  // --- Menu de ações (aberto pelo clique na personagem) ---
  // quando o menu abre/fecha, alterna click-through p/ capturar cliques nele
  ipcMain.on("overlay-menu-open", (_e, open) => {
    win.setIgnoreMouseEvents(!open, { forward: true });
  });
  ipcMain.on("overlay-menu-action", (_e, action) => {
    switch (action) {
      case "chat":
        shell.openExternal("http://127.0.0.1:8000/");
        break;
      case "look":
        lookAtScreen();
        break;
      case "voice":
        if (recording) stopAndChat();
        else startRecording();
        break;
      case "ground":
        y = getScreenSize().height - height - 60;
        win.setPosition(Math.round(x), Math.round(y));
        break;
      case "status": {
        const fs = require("fs");
        const backend = `${BACKEND}/api/health`;
        fetch(backend).then(async (r) => {
          const d = await r.json();
          const msg = `Modelo: ${d.model}\nModo seguro: ${d.safe_mode}\nFerramentas: ${d.tools.length}\nBackend: OK`;
          win.webContents.send("menu-toast", msg);
        }).catch(() => {
          win.webContents.send("menu-toast", "Backend offline — rode ./overlay.sh");
        });
        break;
      }
      case "close":
        globalShortcut.unregisterAll();
        app.quit();
        break;
    }
  });
}

function sendConfig() {
  const { pathToFileURL } = require("url");
  win.webContents.send("config", {
    spriteDir: pathToFileURL(SPRITE_DIR).href,
    width: WIN_W,
    height: WIN_H,
    states: STATES,
  });
}

// --- Loop de movimento: caminha até a borda, inverte, dá uma pausa ---
let stepTimer = null;
let lastStep = 0; // timestamp do último step (ms) — delta-time real
let idleUntil = 0; // timestamp até quando fica parada (idle ou thinking)
let walkUntil = 0; // timestamp até quando caminha
function step() {
  if (!win || win.isDestroyed()) return;

  const now = Date.now();
  const dt = lastStep ? Math.min((now - lastStep) / 1000, 0.1) : 0; // seconds, clamp 100ms
  lastStep = now;

  const { width: sw } = getScreenSize();
  // caminha só durante a janela de "walk"; fora dela (e sem voz) fica parada
  const isWalking = !voiceState && now >= idleUntil && now < walkUntil;
  if (!dragging && isWalking) {
    x += direction * CONFIG.speed * dt;     // px/s genuíno
    if (x > sw - width - 20) { x = sw - width - 20; direction = -1; }
    if (x < 20) { x = 20; direction = 1; }
    win.setPosition(Math.round(x), Math.round(y));
  }

  // estado de voz tem prioridade; senão: pensando → andando → parada (idle)
  if (voiceState) {
    // não sobrescreve
  } else if (now < idleUntil) {
    win.webContents.send("frame", { state: "thinking", moving: false, direction });
  } else if (isWalking) {
    win.webContents.send("frame", { state: "walk", moving: true, direction });
  } else {
    win.webContents.send("frame", { state: "idle", moving: false, direction });
  }
  stepTimer = setTimeout(step, 33);
}

// --- Comportamento autônomo: fica parada, de vez em quando anda ou reage ---
let reacTimer = null;
function scheduleActivity() {
  const now = Date.now();
  const r = Math.random();
  if (r < 0.30) {
    // 30%: anda por 3–7s
    idleUntil = 0;
    walkUntil = now + 3000 + Math.random() * 4000;
  } else if (r < 0.55) {
    // 25%: "pensa" (reage) por 2–4s, depois volta ao idle
    idleUntil = now + 2000 + Math.random() * 2000;
    walkUntil = 0;
  } else {
    // 45%: só fica parada mesmo
    idleUntil = 0;
    walkUntil = 0;
  }
}
function startReactions() {
  // agenda a próxima ação autônoma (a cada 6s de parada)
  reacTimer = setInterval(() => {
    if (!win || win.isDestroyed()) return;
    if (voiceState) return;                                   // voz tem prioridade
    if (Date.now() < idleUntil || Date.now() < walkUntil) return; // ação atual em andamento
    scheduleActivity();
  }, 6000);
}

// --- PTT: Ctrl+Shift+M inicia/para gravação, transcreve e fala a resposta ---
function setState(name) {
  voiceState = name && name !== "idle" ? name : null;
  if (win && !win.isDestroyed()) {
    win.webContents.send("frame", { state: name, moving: false, direction });
  }
}

function startRecording() {
  if (recording) return;
  // pw-record grava WAV 16kHz mono no mic padrão do PipeWire.
  recProc = execFile("pw-record", ["--rate", "16000", "--channels", "1", "--format", "s16", recPath]);
  recording = true;
  setState("listening");
  console.log("[voz] gravando…");
}

async function stopAndChat() {
  if (!recording) return;
  recording = false;
  if (recProc) { recProc.kill("SIGINT"); recProc = null; }
  setState("thinking");

  // pequena espera para o pw-record fechar o arquivo
  await new Promise((r) => setTimeout(r, 250));
  const fs = require("fs");
  if (!fs.existsSync(recPath) || fs.statSync(recPath).size < 1000) {
    console.log("[voz] gravação muito curta ou vazia");
    setState("idle");
    return;
  }

  try {
    // 1. transcreve
    const text = await transcribeFile(recPath);
    console.log("[voz] transcrito:", text);
    if (!text.trim()) { setState("idle"); return; }

    // 2. envia ao chat e acumula a resposta
    const reply = await sendChat(text);
    console.log("[voz] resposta:", reply.slice(0, 120));

    // 3. fala a resposta via TTS do backend (espeak-ng pt-br)
    setState("talking");
    await speakReply(reply);
  } catch (err) {
    console.error("[voz] erro:", err);
    setState("alert");
    setTimeout(() => setState("idle"), 3000);
  } finally {
    fs.rmSync(recPath, { force: true });
    setTimeout(() => { if (!recording) setState("idle"); }, 600);
  }
}

// --- Sincronização com o watcher: a personagem reage a alertas reais do
// backend (porta nova, disco cheio, diff de scan), não só a erros da própria
// voz/visão — "overlay sincronizado" (Fase 4) além da voz.
let seenAlertIds = null; // null = ainda não fez a primeira leitura (seed)
let alertPollTimer = null;

async function pollAlerts() {
  try {
    const r = await fetch(`${BACKEND}/api/alerts`);
    if (!r.ok) return;
    const { alerts } = await r.json();
    const ids = new Set((alerts || []).map((a) => a.id));
    if (seenAlertIds === null) {
      // primeira leitura: só marca o que já existe — não dispara animação
      // por alertas antigos de uma sessão anterior do watcher.
      seenAlertIds = ids;
      return;
    }
    const fresh = (alerts || []).filter((a) => !a.acknowledged && !seenAlertIds.has(a.id));
    seenAlertIds = ids;
    if (fresh.length && !recording && !voiceState) {
      const worst = fresh.find((a) => a.severity === "high") || fresh[0];
      console.log("[alerta]", worst.severity, worst.title, "-", worst.description);
      setState("alert");
      setTimeout(() => { if (!recording && voiceState === "alert") setState("idle"); }, 4000);
    }
  } catch {
    // backend fora do ar — silencioso, sem crash do overlay
  }
}

function startAlertWatch() {
  pollAlerts();
  alertPollTimer = setInterval(pollAlerts, 20000);
}

async function lookAtScreen() {
  if (recording || voiceState) return;
  setState("thinking");
  try {
    const r = await fetch(`${BACKEND}/api/vision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: "O que você está vendo na minha tela? Descreva de forma curta e natural, em português, como uma assistente olhando." }),
    });
    if (!r.ok) throw new Error("vision " + r.status);
    const data = await r.json();
    const reply = (data.text || "").trim();
    if (!reply) { setState("idle"); return; }
    console.log("[visão] viu:", reply.slice(0, 140));
    setState("talking");
    await speakReply(reply);
  } catch (err) {
    console.error("[visão] erro:", err);
    setState("alert");
    setTimeout(() => setState("idle"), 2500);
  } finally {
    setTimeout(() => { if (!recording) setState("idle"); }, 400);
  }
}

async function transcribeFile(path) {
  const fs = require("fs");
  const { FormData, Blob } = require("node:buffer");
  const fd = new FormData();
  fd.append("file", new Blob([fs.readFileSync(path)]), "voice.wav");
  const r = await fetch(`${BACKEND}/api/audio/transcribe`, { method: "POST", body: fd });
  if (!r.ok) throw new Error("transcribe " + r.status);
  return (await r.json()).text || "";
}

async function sendChat(message) {
  const r = await fetch(`${BACKEND}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  if (!r.ok) throw new Error("chat " + r.status);
  // SSE: acumula o último data:{content}
  let acc = "";
  const text = await r.text();
  for (const part of text.split("\n\n")) {
    const line = part.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const data = JSON.parse(line.slice(5).trim());
    if (typeof data.content === "string") acc = data.content;
  }
  return acc;
}

async function speakReply(text) {
  const r = await fetch(`${BACKEND}/api/audio/speak`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error("speak " + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  const fs = require("fs");
  // MP3 = ID3 tag OU frame sync (0xFF 0xEx)
  const isMp3 = (buf[0] === 0x49 && buf[1] === 0x44) ||
    (buf.length > 1 && buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0);
  const ttsPath = "/tmp/cyber_tts_play." + (isMp3 ? "mp3" : "wav");
  fs.writeFileSync(ttsPath, buf);
  try {
    const { spawn } = require("child_process");
    const p = spawn("pw-play", [ttsPath], { stdio: "ignore" });
    await new Promise((res) => p.on("exit", res));
  } catch {
    await new Promise((r) => setTimeout(r, 1500));
  }
  fs.rmSync(ttsPath, { force: true });
}

app.whenReady().then(() => {
  createWindow();
});

app.on("will-quit", () => {
  globalShortcut.unregisterAll();
  if (alertPollTimer) clearInterval(alertPollTimer);
});
