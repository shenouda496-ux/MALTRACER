# CHANGES — Finishing & packaging MalTracer for distribution

This document records every significant change made to turn MalTracer from a
developer tool (two separate CLI modes, an Electron popup, hand-placed Gmail
credentials, no build) into a single, always-on, double-clickable Windows app
with a native desktop GUI and encrypted credential storage.

Baseline before the work: **85 tests passing**. After: **102 tests passing**
(85 original + 17 new, covering credential storage, the auth flow, and resource
resolution). No original test was weakened.

---

## Phase 1 — One unified always-on application

- `maltracer.py` rewritten. **Default mode (no args, and `--dashboard`)** now calls
  `run_app()`, which starts — in a single process — the process/file/network
  monitors (`MalTracerEngine`) **and** the Gmail scanner (`EmailScannerService`),
  all feeding one native GUI. The window opens automatically on launch.
- Backward-compatible advanced flags kept: `--monitor` (headless engine),
  `--email-scan` (headless console scan), `--simulate` (replay logs into the GUI),
  `--status`. New hidden `--selftest` starts everything, pumps the event loop
  briefly, then exits 0 — used by the packaged build's smoke test.
- **Graceful partial failure:** each subsystem is started in its own try/except and
  reports status to the dashboard instead of aborting. A missing Gmail connection,
  a crashed monitor thread, or missing admin rights never takes down the app. The
  event bus already isolates handler exceptions; monitor threads are daemonized and
  independently supervised.
- Per-subsystem live status (Process / File / Network / Email / Privileges) is shown
  in the dashboard "System status" panel.

## Phase 2 — Email onboarding + encrypted credential storage

- **New `email_scanner/credential_store.py`** — stores the Gmail account + OAuth
  token via the `keyring` library. On Windows this is the **Windows Credential
  Manager** (`WinVaultKeyring`, DPAPI-encrypted per-user); on Linux the Secret
  Service. The token is **chunked** (1000-char pieces) to stay under the Windows
  credential blob size cap and reassembled on load. **No token or email is ever
  written to a plaintext file or hardcoded in source.**
- **`email_scanner/auth.py` refactored:** google imports are now lazy (module
  imports fine without google installed → tests stay import-safe). `login()`:
  - `interactive=False` → silently reuse a stored token, auto-refresh if expired,
    and raise `NotConnected` when nothing is stored (so the app can start without
    email).
  - `interactive=True` → run the standard browser consent flow and persist the new
    token to the store.
  - One-time migration: an existing plaintext `token.json` is imported into the
    secure store and then deleted.
- **New `email_scanner/service.py` (`EmailScannerService`)** — a start/stop-able,
  daemon-threaded refactor of the old `run_email_monitor` loop. It scans the inbox
  and pushes results to the **same UI sink** as the device monitors. HIGH emails are
  auto-contained (Gmail label + trash via `email_scanner.actions`); MEDIUM emails
  raise the same interactive Contain/Dismiss prompt as device threats.
- **GUI onboarding:** the dashboard shows "Email scanning: not connected — click to
  set up". "Connect Gmail account" runs the OAuth flow on a worker thread (the
  browser opens); on success the scanner starts and the button becomes
  "Disconnect Gmail account", which stops the scanner and clears the stored token.
  Later launches reuse the stored token with no re-auth.
- **Bundled OAuth client (developer action required):** the OAuth *client*
  ("desktop app") `email_scanner/credentials.json` is bundled with the app so end
  users never need a Google Cloud account. **A desktop-app client secret is not a
  true secret** (Google documents this — the security boundary is the per-user
  consent + token, not the client secret), so bundling it is acceptable. **The
  developer must supply a valid `credentials.json`** from their own Google Cloud
  project; the path is overridable via the `MALTRACER_OAUTH_CLIENT` env var.

## Phase 3 — Windows-first robustness

- **New `utils/resources.py`** — `resource_path()` resolves bundled files both from
  source and from a PyInstaller bundle (`sys._MEIPASS`). Wired into detection-rule
  loading (`detection_engine/engine.py`), the bundled OAuth client path, and the
  logs dataset. Confirmed at runtime: 50 rules load from the bundle.
- **New `utils/privileges.py`** — `is_admin()`, `reduced_features()` (human list of
  capabilities lost without admin), and `relaunch_as_admin()` (UAC via
  `ShellExecuteW "runas"`).
- **Admin behavior (design choice):** MalTracer does **not** force a UAC prompt on
  every launch. It starts with whatever privileges it has, runs every monitor, and
  shows a dashboard banner listing the reduced features (Windows Firewall blocking,
  watching protected paths, killing system-owned processes) plus a **"Restart as
  Administrator"** button. This matches the intent already present in
  `monitoring/file_monitor.py`, which had deliberately removed silent auto-UAC.
- **`logging_system/logger.py`:** the console `StreamHandler` is now guarded for
  `sys.stdout is None` (a windowed PyInstaller build has no console, which otherwise
  makes every log call raise). Also fixed the `\l` `SyntaxWarning` in the module
  docstring (now a raw string) that printed on every run.
- Verified the existing Windows paths are correct and unchanged: `netsh advfirewall`
  blocking (`containment/network_blocker.py`), quarantine under
  `%APPDATA%\MalTracer\...` (`utils/constants.py`), and the watchdog user/admin
  path lists (`monitoring/file_monitor.py`).

## Phase 4 — Native PySide6 GUI replacing Electron

**Decision: native PySide6 (Qt) desktop GUI; Electron removed entirely.** Node.js
was the biggest obstacle to a clean single-download build, and a web UI was
explicitly not wanted. PySide6 was verified to run on this Python **3.14** via its
stable-ABI (`cp310-abi3`) wheel, and Qt's `QSystemTrayIcon` gives both the tray
icon and native Windows toast notifications with no extra dependencies.
(CustomTkinter was the documented fallback had Qt not been viable.)

- **New `app/` package:** `main_window.py` (the `MainWindow` + `MediumDialog` +
  `DetailDialog` + runtime-drawn shield icon) and `style.py` (dark QSS theme
  approximating the old oklch palette). Faithful replica of the Electron three
  screens as a real windowed app.
- **In-process only.** The GUI subscribes directly to the alert pipeline through the
  `PopupHandler` sink and the `EmailScannerService`. **The localhost HTTP servers on
  ports 7474 / 7475 and the stdout IPC are gone** — they only existed to feed
  Electron. This is a major reliability and packaging win (nothing to bind, no
  cross-process handshake).
- **`alerts/popup_handler.py` rewritten internally, public API preserved.**
  `notify_high` / `notify_low` / `ask_medium` still exist with the same signatures,
  so `containment/containment_engine.py` and its tests were untouched. Internally
  they now forward to an in-process UI sink registered via `set_ui_sink()`.
  `ask_medium` still **blocks its containment thread on a `threading.Event`** until
  the user answers the modal — the identical synchronous contract Electron had, now
  without a subprocess. With no sink (headless `--monitor`, tests), it logs and
  returns False (dismiss). All HTTP/Electron/plyer code was deleted.
- **Native notifications:** `QSystemTrayIcon` tray icon + `showMessage` toasts fire
  even when the window is minimized; closing the window **minimizes to tray** and
  monitoring keeps running. "Quit" from the tray menu fully exits.
- **Real .eml scanning:** the Scan Email screen now parses the dropped/selected
  `.eml` with Python's `email` module and runs the **real** `email_scanner.analyzer`
  (SPF/DKIM/DMARC + keyword + URL heuristics), replacing the old faked filename
  regex.
- **Archived to `legacy/`:** `electron_popup/`, the static `dashboard/*.html`, the
  unused `email_scanner/server.py` (port-7475 server) and `email_scanner/alert.py`
  (old tkinter popup). Nothing in the live code references them.

### Electron → PySide6 feature mapping (nothing lost)

| Old Electron feature (`electron_popup/popup.html`)        | New native equivalent (`app/main_window.py`)                              |
|-----------------------------------------------------------|---------------------------------------------------------------------------|
| Dashboard screen (threat level, stats, recent alerts)     | Dashboard page — threat banner, stats grid, recent-alerts list            |
| Alerts screen with Critical/Warning/Info/Resolved filters | Alerts page — filter chips (All/Critical/Warning/Info/Resolved) + list     |
| Row "Contain" button (MEDIUM)                             | Row "Contain" button → `MediumDialog` (interactive)                       |
| Row "View" / detail panel + timeline                      | "View" button → `DetailDialog` (incident details + reasons)               |
| MEDIUM interactive Contain/Dismiss + countdown            | `MediumDialog` modal with 120s auto-dismiss countdown, drives `ask_medium`|
| HIGH auto-containment display                             | HIGH alerts rendered as "✓ Contained"; toast fired via tray               |
| Scan Email (.eml) screen                                  | Scan Email page — drag-drop/file-picker, **real** analyzer output          |
| Live event feed (HTTP poll of 7474)                       | Direct in-process sink (`on_alert`) — no polling, no server               |
| plyer / Electron toast notifications                      | `QSystemTrayIcon.showMessage` native Windows toasts                        |
| Always-on-top popup window                                | Main window + minimize-to-tray; toasts surface when minimized             |

## Phase 5 — Packaging

- **`requirements.txt`** — psutil, watchdog, beautifulsoup4, keyring, google-auth,
  google-auth-oauthlib, google-api-python-client, PySide6, pyinstaller, pytest.
  (plyer dropped — no longer used.)
- **`MalTracer.spec`** — one-dir build, `console=False`. `datas` bundle the three
  rule files, the logs dataset, and the OAuth client, plus googleapiclient data and
  keyring/google metadata (so keyring can discover its Windows backend inside the
  frozen app). `hiddenimports` cover the keyring backends, the google stack, and
  watchdog observers; PySide6 Qt plugins are handled by the installed
  `pyinstaller-hooks-contrib`.
- **`build.bat`** — installs requirements, runs PyInstaller, smoke-tests the exe with
  `--selftest`, and prints an optional (commented) `signtool` signing step.
- Result: `dist\MalTracer\` — a folder with `MalTracer.exe` and its dependencies.
  Double-clicking it launches the unified always-on app with no Python or Node.js
  required on the target machine.

---

## Post-delivery enhancement — "Dismiss" suppresses repeat prompts

- **New `alerts/suppression.py`.** When the user **Dismisses** a MEDIUM Contain/Dismiss
  prompt, that threat is remembered and **never prompts again**. Threats are keyed by a
  stable identity (email sender → remote IP → file path → process name+hash → title),
  *not* the per-event incident id (which is unique each time), so the exact same
  file/IP/process/sender is suppressed even though each detection is a new incident.
- The dismissed set is **persisted** to `%APPDATA%\MalTracer\dismissed.json` so the
  choice survives restarts. Reset by deleting that file or calling `suppression.clear()`.
- Wired into `MainWindow.ask_contain` (the single chokepoint for both device and email
  interactive prompts): a previously dismissed threat auto-dismisses with no modal.
- The Alerts list now **dedupes recurring threats by identity** (a repeated threat
  updates its existing row instead of stacking new ones) and shows dismissed threats
  with a muted **"Dismissed"** tag; they drop out of the active threat-level/open-incident
  counts and appear under the **Resolved** filter. A dismissed row still offers a
  **Contain** button — containing it overrides the earlier dismissal (`discard_key`).
- Security note: suppression is intentionally specific (one exact file/IP/process/sender),
  never a whole category. Covered by `tests/test_suppression.py` (7 tests).

---

## Post-delivery change — no auto-containment; every threat is human-decided

Per request, **HIGH threats no longer auto-contain.** Containment now *always*
requires an explicit human decision:

- `ContainmentEngine.handle` routes **both HIGH and MEDIUM** to a single
  `_contain_interactive` path that raises the Contain/Dismiss prompt. The actual
  actions (kill / quarantine / block; for email: label + trash) run **only if the
  analyst chooses Contain**. HIGH shows with higher urgency (danger tone + toast).
  If the prompt times out or the app is headless, the default is **Dismiss** (no
  action) — nothing is contained without consent.
- `EmailScannerService` updated to match: HIGH emails prompt instead of
  auto-labeling/trashing.
- The stored containment `mode` changed `"automatic"` → `"confirmed"`, and the log
  line `[HIGH] Auto-containment triggered` → `[CONTAIN] Analyst-confirmed containment`.
- Tests updated (HIGH prompts; confirming runs actions, dismissing does not; added
  `test_high_dismissed_no_containment`). Suite: **110 pass**.
- Corrected the documented thresholds to match `classifier.py`
  (LOW < 40, MEDIUM 40–79, HIGH ≥ 80).

---

## Post-delivery fix — live dashboard stats + quarantine move robustness

- The dashboard's four stat tiles now show **real, live numbers** instead of static
  placeholders (`app/main_window.py`):
  - **Processes** — live `len(psutil.pids())`, refreshed on a 4 s `QTimer`.
  - **Files watched** — an actual count of files under the monitored folders,
    computed once at startup in a background thread (capped at 300k, non-blocking).
  - **Quarantined** — counted from the real quarantine directory on disk
    (`%APPDATA%\MalTracer\quarantine\`), so it reflects actual quarantined files.
  - **Open incidents** — active (non-contained, non-dismissed) MEDIUM/HIGH threats
    from the live alert model (already correct; unchanged).
- **Quarantine move hardening** (`containment/quarantine_manager.py`): `quarantine`
  and `restore` now move files via `_move_with_retry` (5 attempts, short backoff).
  On Windows an antivirus scan or the search indexer can hold a transient lock on a
  freshly written executable; the retry makes moves reliable. This also removed a
  Windows-only flakiness in `tests/test_quarantine_manager.py` (whose fixture now
  also clears read-only bits before temp cleanup). Suite is stable at **110 pass**.

---

## Known limitations (documented honestly, not papered over)

1. **AV / SmartScreen flagging.** An unsigned PyInstaller executable that kills
   processes and edits the Windows Firewall will very likely be flagged by
   SmartScreen and third-party antivirus on machines other than the build machine
   (unsigned + EDR-like behavior is exactly what heuristics target). Genuine
   distribution requires **code signing with a purchased Authenticode certificate**.
   `build.bat` includes a commented `signtool` placeholder for this. Reputation with
   SmartScreen also builds over time / can be expedited via an EV certificate.
2. **Gmail OAuth for other users.** The bundled OAuth client works out-of-the-box
   only for accounts the developer has added, unless the Google Cloud OAuth consent
   screen is **published/verified**. Until then, each intended user's Gmail address
   must be added as a **Test user** in the Google Cloud project, and the requested
   scopes (`gmail.readonly`, `gmail.modify`) may show an "unverified app" warning.
   Full public distribution requires Google's app verification (privacy policy,
   scope justification, possible security assessment for restricted scopes).
3. **exe icon.** The in-app/tray icon is drawn at runtime (no binary asset needed).
   The packaged `.exe` uses PyInstaller's default icon; supply an `.ico` and set the
   `icon=` field in `MalTracer.spec` to brand it.
4. **GUI verification environment.** The GUI was validated headlessly (Qt
   `offscreen` platform) via `--selftest` and direct widget construction. Final
   on-screen appearance should be eyeballed on a real Windows desktop session.
