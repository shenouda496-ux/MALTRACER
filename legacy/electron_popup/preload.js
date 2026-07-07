/**
 * preload.js
 * Exposes a minimal, safe IPC bridge via contextBridge.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('maltracerAPI', {
  // Renderer → Main
  contain:     (data) => ipcRenderer.send('contain', data),
  dismiss:     (data) => ipcRenderer.send('dismiss', data),
  closeWindow: ()     => ipcRenderer.send('close-window'),

  // Main → Renderer
  onAlertData: (cb) => ipcRenderer.on('alert-data', (_event, data) => cb(data)),
});
