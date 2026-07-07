"""
tests/simulate_from_logs.py
────────────────────────────
Replays recorded EDR log entries into the native MalTracer GUI so the dashboard
shows realistic variance (Critical / Warning / Info / Resolved) without needing
live malware.

The old HTTP-server + Electron delivery has been retired: events are now fed
directly to the in-process MainWindow via its thread-safe sink API.

Usage:
    python maltracer.py --simulate                 # mixed, 1.5s delay
    python maltracer.py --simulate --level MEDIUM   # only MEDIUM events
    python maltracer.py --simulate --delay 0.5      # faster
Direct:
    python tests/simulate_from_logs.py --delay 2
"""

import argparse
import json
import random
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from logging_system.logger import get_logger
from core.incident_manager import IncidentManager

logger = get_logger(__name__)

LOGS_FILE = ROOT / "logs" / "2026-03-13_edr_logs.json"


# ─────────────────────────────────────────────────────────────────────────────
# Threat enrichment — maps raw log events → dashboard-ready threat scenarios
# ─────────────────────────────────────────────────────────────────────────────

_ENRICHMENT_MAP = {
    "executable_modified": [
        ("danger", "Ransomware encryption pattern detected",    "Ransomware",       "Mass file modification intercepted"),
        ("warn",   "Executable tampered in user profile",       "File tampering",   "Hash mismatch vs baseline"),
        ("warn",   "Unsigned binary modified on Desktop",       "Integrity alert",  "Write to unsigned executable flagged"),
    ],
    "executable_created": [
        ("warn",   "Suspicious executable dropped",             "Dropper",          "New unsigned binary in user profile"),
        ("danger", "Malware dropper detected",                  "Dropper",          "Executable written by Office process"),
        ("warn",   "Executable created in temp directory",      "Executable drop",  "Binary created outside Program Files"),
    ],
    "executable_deleted": [
        ("info",   "Security tool binary removed",              "Tool removal",     "Known AV binary deleted from disk"),
        ("info",   "Executable removed from startup folder",    "Persistence",      "Startup persistence item deleted"),
        ("warn",   "Suspicious binary deleted after execution", "Anti-forensics",   "Binary self-deleted — possible evasion"),
    ],
    "network_connection": [
        ("warn",   "Suspicious outbound connection",            "Network anomaly",  "Connection to low-reputation IP"),
        ("danger", "C2 beacon traffic detected",                "C2 communication", "Beaconing interval matched known C2"),
        ("info",   "Unusual port usage flagged",                "Network anomaly",  "High-port outbound connection logged"),
    ],
    "process_started": [
        ("info",   "Suspicious process launched",               "Process anomaly",  "Process started from temp path"),
        ("danger", "Credential dumping tool executed",          "Credential theft", "LSASS memory access attempted"),
        ("warn",   "PowerShell with encoded command detected",  "Script execution", "Encoded payload in command line"),
        ("info",   "Scheduled task executed",                   "Routine",          "Scheduled task ran from task scheduler"),
    ],
}


def _enrich(event: dict) -> dict:
    ed      = event.get("event_data", {})
    ev_type = ed.get("event_type", "executable_modified")
    risk    = ed.get("risk_score", 0)
    level   = event.get("level", "INFO").upper()

    options = _ENRICHMENT_MAP.get(ev_type, _ENRICHMENT_MAP["executable_modified"])
    if level == "MEDIUM":
        candidates = [o for o in options if o[0] in ("warn", "danger")] or options
    elif level in ("LOW", "INFO"):
        candidates = [o for o in options if o[0] in ("ok", "info")] or options
    else:
        candidates = options

    tone, title, category, action = random.choice(candidates)
    proc = ed.get("process_name", "")
    path = ed.get("destination") or ed.get("process_path", "")

    event["threat_tone"]     = tone
    event["threat_title"]    = title
    event["threat_category"] = category
    event["threat_action"]   = action
    event["threat_process"]  = proc or (path.split("\\")[-1] if path else "unknown.exe")
    event["threat_path"]     = path or "N/A"
    event["threat_score"]    = risk
    event["threat_level"]    = level
    return event


def _build_simulation_sequence(raw_events: list, level_filter: str) -> list:
    if level_filter != "ALL":
        pool = [e for e in raw_events if e.get("level", "").upper() == level_filter]
    else:
        medium = [e for e in raw_events if e.get("level", "").upper() == "MEDIUM"]
        low    = [e for e in raw_events if e.get("level", "").upper() == "LOW"]
        pool = (random.sample(medium, min(14, len(medium)))
                + random.sample(low, min(6, len(low))))
        random.shuffle(pool)
    return [_enrich(dict(e)) for e in pool[:20]]


def _stamp(event: dict) -> dict:
    if not event.get("incident_id"):
        event["incident_id"] = IncidentManager.new_incident_id()
    return event


# ─────────────────────────────────────────────────────────────────────────────
# GUI-driven simulation
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation(level_filter: str = "ALL", delay: float = 1.5) -> None:
    print("\n" + "=" * 62)
    print("  MalTracer — Simulation (native GUI)")
    print(f"  Filter: {level_filter}   Delay: {delay}s")
    print("=" * 62)

    if not LOGS_FILE.exists():
        print(f"[ERROR] Log file not found: {LOGS_FILE}")
        sys.exit(1)

    with open(LOGS_FILE, encoding="utf-8") as fh:
        raw = json.load(fh)

    events = _build_simulation_sequence(raw, level_filter)
    if not events:
        print(f"[WARN] No events for filter '{level_filter}'. Exiting.")
        return

    from PySide6.QtWidgets import QApplication
    from app.main_window   import MainWindow
    from utils.privileges  import is_admin, reduced_features

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = MainWindow(admin=is_admin(), reduced=reduced_features())
    window.show()
    for name in ("Process", "File", "Network"):
        window.set_monitor_status(name, "simulation")
    window.set_email_status("Email scanning: simulation mode")

    def feed():
        print(f"  Streaming {len(events)} events into the dashboard…\n")
        for event in events:
            _stamp(event)
            window.on_alert(event)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  {ts}  {event['threat_tone']:7}  {event['threat_title'][:40]}")
            time.sleep(delay)
        print("\n  Simulation feed complete — window stays open. Close it to exit.")

    threading.Thread(target=feed, name="SimFeed", daemon=True).start()
    app.exec()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MalTracer simulation")
    parser.add_argument("--level", choices=["LOW", "MEDIUM", "HIGH", "ALL"], default="ALL")
    parser.add_argument("--delay", type=float, default=1.5)
    args = parser.parse_args()
    run_simulation(level_filter=args.level, delay=args.delay)
