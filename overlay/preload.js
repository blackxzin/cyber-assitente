// Bridge segura entre o renderer e o main process (contextIsolation on).
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("overlay", {
  onConfig: (cb) => ipcRenderer.on("config", (_e, data) => cb(data)),
  onFrame: (cb) => ipcRenderer.on("frame", (_e, data) => cb(data)),
  setMoving: (cb) => ipcRenderer.on("set-moving", (_e, v) => cb(v)),
  dragStart: (mx, my) => ipcRenderer.send("overlay-drag-start", mx, my),
  dragEnd: () => ipcRenderer.send("overlay-drag-end"),
  // menu de ações
  menuAction: (action) => ipcRenderer.send("overlay-menu-action", action),
  menuSetOpen: (open) => ipcRenderer.send("overlay-menu-open", open),
  // main notifica para abrir/fechar o menu
  onMenuState: (cb) => ipcRenderer.on("menu-state", (_e, open) => cb(open)),
  // toast (mensagem rápida vinda do main, ex: status)
  onToast: (cb) => ipcRenderer.on("menu-toast", (_e, msg) => cb(msg)),
});
