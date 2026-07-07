r"""
logger.py
─────────
Shared structured logger for all MalTracer modules.
Call get_logger(__name__) at the top of any module.

Cross-platform log paths:
  Windows : %APPDATA%/MalTracer\logs\maltracer.log
  Linux   : ~/.maltracer/logs/maltracer.log
"""

import logging
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    _LOG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "MalTracer" / "logs"
else:
    _LOG_DIR = Path.home() / ".maltracer" / "logs"

_LOG_FILE   = _LOG_DIR / "maltracer.log"
_CONFIGURED = False


def _setup():
    global _CONFIGURED
    if _CONFIGURED:
        return

    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[MALTRACER] Warning: could not create log dir {_LOG_DIR}: {e}")

    root = logging.getLogger("maltracer")
    root.setLevel(logging.DEBUG)

    try:
        fh = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_JsonFormatter())
        root.addHandler(fh)
    except Exception as e:
        print(f"[MALTRACER] Warning: could not open log file: {e}")

    # In a windowed PyInstaller build there is no console: sys.stdout / sys.stderr
    # are None, and attaching a StreamHandler to None raises at every log call.
    # Only add the console handler when a real stream is available.
    stream = sys.stdout if sys.stdout is not None else sys.stderr
    if stream is not None:
        # The Windows console defaults to cp1252, which cannot encode the Unicode
        # glyphs used in log messages (✓ ✗ — ●) and raises UnicodeEncodeError.
        # Force UTF-8 with replacement so logging never crashes a worker thread.
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        ch = logging.StreamHandler(stream)
        ch.setLevel(logging.INFO)
        ch.setFormatter(_ColorFormatter())
        root.addHandler(ch)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _setup()
    return logging.getLogger(f"maltracer.{name}")


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "level":  record.levelname,
            "module": record.name,
            "msg":    record.getMessage(),
        }
        if record.exc_info:
            log["exc"] = self.formatException(record.exc_info)
        return json.dumps(log)


class _ColorFormatter(logging.Formatter):
    _COLORS = {
        "DEBUG":    "\033[90m",
        "INFO":     "\033[36m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    _RESET = "\033[0m"

    def format(self, record):
        color = self._COLORS.get(record.levelname, "")
        ts    = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return (
            f"{color}[{ts}] [{record.levelname:<8}] "
            f"{record.name.split('.')[-1]}: {record.getMessage()}{self._RESET}"
        )
