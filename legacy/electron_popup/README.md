# MalTracer — Electron Popup

Frameless, transparent, always-on-top alert window.  
Replaces the old tkinter dialog completely.

## One-time setup (Windows, VS Code terminal)

```cmd
cd MalTracer_Release\electron_popup
npm install
```

This installs Electron (~150 MB) into `node_modules/`.

## How it's triggered

`alerts/popup_handler.py` launches Electron automatically when a MEDIUM or HIGH
threat is detected. You do not run it manually.

If you want to test it standalone:

```cmd
cd MalTracer_Release\electron_popup
npx electron . --alert-json "{\"incident_id\":\"INC-TEST\",\"tone\":\"warn\",\"title\":\"Test Alert\",\"process\":\"test.exe\"}"
```

## Window behaviour

| Feature | Value |
|---------|-------|
| Frame | `false` — no OS title bar |
| Transparent | `true` — glassmorphism background |
| Always on top | `true` — floats above all windows |
| Position | Bottom-right of primary display (16 px margin) |
| Auto-dismiss timer | 30 seconds |
| Timer resets | Every time a new alert arrives while the popup is open |
| Timer pauses | While user is hovering or clicking inside the window |
| Fade-out | 3-second smooth fade before close |

## Files

| File | Purpose |
|------|---------|
| `main.js` | Electron main process — creates frameless window, reads CLI arg, handles IPC |
| `preload.js` | Secure IPC bridge (contextBridge) |
| `popup.html` | Full popup UI — glassmorphic, all features, alert list newest-first |
| `package.json` | npm config |

## IPC protocol

Renderer → Main (user actions):

```json
{ "action": "contain", "incident_id": "INC-2047", "process": "svchost.exe" }
{ "action": "dismiss", "incident_id": "INC-2047" }
{ "action": "dismiss", "reason": "timeout" }
```

Python reads stdout of the Electron process and parses the last JSON line.
`contain` → `ask_medium()` returns `True`  
`dismiss` → `ask_medium()` returns `False`

## Live events

The popup also polls `http://127.0.0.1:7474/events` every 1.5 s so that
new live events injected by `simulate_from_logs.py` appear in the alert list
and reset the 30-second timer automatically.
