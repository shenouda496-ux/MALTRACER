"""
utils/constants.py
──────────────────
Platform-aware constants for MalTracer.

All modules import paths from here — no more inline sys.platform checks.
Severity thresholds are the single source of truth; never hardcode 40 or 75.

Paths auto-created on first use by the modules that need them, not here.
"""

import os
import sys
from pathlib import Path

# ── Runtime base directory ────────────────────────────────────────────────────
if sys.platform == "win32":
    BASE_DIR = Path(os.environ.get("APPDATA", Path.home())) / "MalTracer"
else:
    BASE_DIR = Path.home() / ".maltracer"

QUARANTINE_DIR = BASE_DIR / "quarantine"
LOG_DIR        = BASE_DIR / "logs"
INCIDENTS_DIR  = BASE_DIR / "incidents"

# ── Severity thresholds ───────────────────────────────────────────────────────
SCORE_MEDIUM_THRESHOLD = 40   # score >= 40 → MEDIUM
SCORE_HIGH_THRESHOLD   = 75   # score >= 75 → HIGH

# ── Incident ID format ────────────────────────────────────────────────────────
INCIDENT_ID_PREFIX = "INC"    # INC-YYYYMMDD-xxxxxxxx

# ── Containment timeouts (seconds) ───────────────────────────────────────────
PROCESS_KILL_TIMEOUT    = 5   # total time before giving up on a process kill


# ── Event bus ────────────────────────────────────────────────────────────────
EVENT_BUS_MAXSIZE = 1000      # max queued events before put() blocks
