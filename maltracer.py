"""
maltracer.py
────────────
MalTracer entry point.

Default (double-click / no args) launches the unified always-on desktop app:
a single process that concurrently runs the process, file and network monitors
AND the Gmail scanner, all feeding one native PySide6 dashboard.

Usage:
    python maltracer.py                 # unified always-on GUI (default)
    python maltracer.py --dashboard     # same as default (open the GUI)
    python maltracer.py --monitor       # headless device monitoring (no GUI)
    python maltracer.py --email-scan     # headless Gmail scan (console)
    python maltracer.py --simulate       # replay recorded EDR logs into the GUI
    python maltracer.py --status         # print incident counts and exit
    python maltracer.py --selftest       # start everything, then exit 0 (build check)
"""

import argparse
import sys
import threading

from logging_system.logger import get_logger

logger = get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(
        prog="maltracer",
        description="MalTracer — Endpoint Detection & Response",
    )
    parser.add_argument("--dashboard",  action="store_true", help="open the desktop app (default)")
    parser.add_argument("--monitor",    action="store_true", help="headless device monitoring")
    parser.add_argument("--email-scan", action="store_true", dest="email_scan", help="headless Gmail scan")
    parser.add_argument("--simulate",   action="store_true", help="replay recorded EDR logs into the GUI")
    parser.add_argument("--status",     action="store_true", help="print incident counts and exit")
    parser.add_argument("--selftest",   action="store_true", help="start everything then exit 0")
    parser.add_argument("--level",      choices=["LOW", "MEDIUM", "HIGH", "ALL"], default="ALL")
    parser.add_argument("--delay",      type=float, default=1.5)

    args = parser.parse_args()

    if args.status:
        _print_status()
    elif args.monitor:
        _start_monitor()
    elif args.email_scan:
        _start_email_scan()
    elif args.simulate:
        from tests.simulate_from_logs import run_simulation
        run_simulation(level_filter=args.level, delay=args.delay)
    elif args.selftest:
        _selftest()
    else:
        # default (and --dashboard): the unified always-on app
        run_app()


# ── Unified always-on app (the default) ──────────────────────────────────────

def run_app():
    """Start every subsystem concurrently and open the native dashboard."""
    from PySide6.QtWidgets import QApplication

    from app.main_window        import MainWindow
    from core.engine            import MalTracerEngine
    from email_scanner.service  import EmailScannerService
    from email_scanner          import auth, credential_store
    from utils.privileges       import is_admin, reduced_features, relaunch_as_admin
    import alerts.popup_handler as ph

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)   # closing the window minimizes to tray

    admin  = is_admin()
    window = MainWindow(admin=admin, reduced=reduced_features())
    ph.set_ui_sink(window)                 # route all device alerts into the GUI

    engine = MalTracerEngine()
    email_service = EmailScannerService(
        sink=window, incident_manager=engine._incident_manager
    )

    # ── UI hooks (keep MainWindow decoupled from the services) ──
    def connect_email():
        def worker():
            try:
                auth.login(interactive=True)      # opens the browser consent flow
                email_service.start()
            except Exception as exc:
                window.set_email_status(f"Email scanning: connect failed ({exc})")
        threading.Thread(target=worker, name="EmailConnect", daemon=True).start()

    def disconnect_email():
        email_service.stop()
        try:
            auth.disconnect()
        except Exception:
            pass
        window.set_email_status("Email scanning: not connected — click to set up")

    def restart_admin():
        if relaunch_as_admin():
            window._quit()

    window.on_connect_email    = connect_email
    window.on_disconnect_email = disconnect_email
    window.on_restart_admin    = restart_admin

    window.show()

    # ── Start device monitors (graceful partial failure) ──
    try:
        engine.start(block=False)
        for name in ("Process", "File", "Network"):
            window.set_monitor_status(name, "running")
    except Exception as exc:
        logger.error(f"[App] Engine failed to start: {exc}")
        window.set_monitor_status("Process", f"error: {exc}")

    window.set_monitor_status(
        "Privileges", "Administrator" if admin else "standard (reduced)"
    )

    # ── Start email only if already connected; else stay idle ──
    try:
        if credential_store.is_connected():
            email_service.start()
        else:
            window.set_email_status("Email scanning: not connected — click to set up")
    except Exception as exc:
        logger.error(f"[App] Email service failed to start: {exc}")
        window.set_email_status(f"Email scanning: error ({exc})")

    logger.info("[App] MalTracer unified app running.")
    rc = app.exec()

    try:
        email_service.stop()
        engine.stop()
    except Exception:
        pass
    sys.exit(rc)


# ── Advanced / headless modes ────────────────────────────────────────────────

def _start_monitor():
    from core.engine import MalTracerEngine
    print("[MalTracer] Starting headless live monitor. Press Ctrl+C to stop.")
    print("[MalTracer] (No GUI — MEDIUM alerts auto-dismiss. Use the default mode for interactive alerts.)")
    engine = MalTracerEngine()
    engine.start(block=True)


def _start_email_scan():
    from email_scanner.main import run_email_monitor
    print("\n" + "=" * 55)
    print("  MalTracer — Headless Email Scan")
    print("=" * 55)
    print("  A browser window will open for Gmail login on first run.")
    print("  Press Ctrl+C to stop.\n")
    try:
        run_email_monitor()
    except KeyboardInterrupt:
        print("\n[MalTracer] Email scan stopped.")


def _print_status():
    from core.incident_manager import IncidentManager
    from utils.constants import INCIDENTS_DIR, LOG_DIR, QUARANTINE_DIR

    print("MalTracer — Status")
    print(f"  Incidents dir : {INCIDENTS_DIR}")
    print(f"  Logs dir      : {LOG_DIR}")
    print(f"  Quarantine dir: {QUARANTINE_DIR}")

    mgr = IncidentManager()
    loaded = mgr.load_from_disk()
    counts = mgr.count_by_state()
    print(f"  Incidents loaded from disk: {loaded}")
    print(f"  State breakdown: {counts}")


def _selftest():
    """
    Build the full app (offscreen), start every subsystem, pump the event loop
    briefly, then exit 0.  Used by the packaged build's smoke test.
    """
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QTimer

    from app.main_window       import MainWindow
    from core.engine           import MalTracerEngine
    from email_scanner.service import EmailScannerService
    from utils.privileges      import is_admin, reduced_features
    import alerts.popup_handler as ph

    app = QApplication(sys.argv)
    window = MainWindow(admin=is_admin(), reduced=reduced_features())
    ph.set_ui_sink(window)

    engine = MalTracerEngine()
    email_service = EmailScannerService(sink=window, incident_manager=engine._incident_manager)
    engine.start(block=False)
    email_service.start()   # returns False cleanly if not connected

    # Exercise the alert pipeline once.
    window.on_alert({
        "incident_id": "INC-SELFTEST", "threat_level": "HIGH", "threat_tone": "danger",
        "threat_title": "Self-test alert", "threat_process": "selftest.exe",
        "threat_score": 99, "contained": True,
    })

    def done():
        email_service.stop()
        engine.stop()
        print("[MalTracer] Self-test OK.")
        app.quit()

    QTimer.singleShot(1200, done)
    app.exec()
    sys.exit(0)


if __name__ == "__main__":
    main()
