/**
 * main.js  —  MalTracer Electron popup
 *
 * Fix: wrap process.stdout.write in try/catch to prevent EPIPE crash
 * when Python closes the pipe after simulation ends.
 */

const { app, BrowserWindow, ipcMain, screen } = require('electron');
const path = require('path');

let win = null;

// Safe stdout write — EPIPE when Python pipe closes must not crash the app
function safeWrite(data) {
  try {
    process.stdout.write(data + '\n');
  } catch (_) {
    // Pipe closed (EPIPE) — ignore silently
  }
}

// Also catch uncaught EPIPE at process level so Electron never shows the dialog
process.on('uncaughtException', (err) => {
  if (err.code === 'EPIPE') return;   // swallow broken-pipe silently
  console.error('[main] Uncaught exception:', err);
});

function createWindow() {
  const { width: sw, height: sh } = screen.getPrimaryDisplay().workAreaSize;

  const W = 420;
  const H = 640;
  const MARGIN = 20;

  win = new BrowserWindow({
    width:  W,
    height: H,
    x: sw - W - MARGIN,
    y: sh - H - MARGIN,

    frame:       false,
    transparent: false,
    alwaysOnTop: true,
    resizable:   false,
    skipTaskbar: false,
    movable:     true,

    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
  });

  win.loadFile(path.join(__dirname, 'popup.html'));
}

// ── IPC ───────────────────────────────────────────────────────────────────────

ipcMain.on('contain', (_event, data) => {
  safeWrite(JSON.stringify({ action: 'contain', ...data }));
});

ipcMain.on('dismiss', (_event, data) => {
  safeWrite(JSON.stringify({ action: 'dismiss', ...data }));
});

ipcMain.on('close-window', () => {
  app.quit();
});

// ── Lifecycle ─────────────────────────────────────────────────────────────────
app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
