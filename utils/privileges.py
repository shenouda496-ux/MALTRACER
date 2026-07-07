"""
utils/privileges.py
───────────────────
Administrator / root detection and (Windows) UAC self-elevation.

Design choice (see CHANGES.md): MalTracer does NOT force a UAC prompt on every
launch.  It starts with whatever privileges it has, runs every monitor, and lets
the GUI surface a banner explaining which features are reduced without admin —
plus a "Restart as Administrator" button that calls ``relaunch_as_admin()``.

Features that need elevation on Windows:
  • Network blocking via ``netsh advfirewall``
  • Watching protected paths (C:\\Windows\\Temp, C:\\ProgramData)
  • Killing system-owned processes
"""

import os
import sys

from logging_system.logger import get_logger

logger = get_logger(__name__)


def is_admin() -> bool:
    """Return True if the current process has admin (Windows) / root (POSIX)."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def reduced_features() -> list[str]:
    """
    Human-readable list of the capabilities that are unavailable when not admin.
    Shown in the dashboard's degradation banner.  Empty list when admin.
    """
    if is_admin():
        return []
    if sys.platform == "win32":
        return [
            "Network blocking (Windows Firewall / netsh)",
            "Watching protected paths (C:\\Windows\\Temp, C:\\ProgramData)",
            "Terminating system-owned processes",
        ]
    return [
        "Network blocking (iptables)",
        "Watching protected paths (/usr/local/bin, /etc/cron.d)",
        "Terminating root-owned processes",
    ]


def relaunch_as_admin() -> bool:
    """
    Relaunch the current program elevated via the Windows UAC prompt.

    Returns True if an elevated instance was launched (the caller should then
    exit so only the elevated copy keeps running).  Returns False if elevation
    is unavailable, was declined, or we are not on Windows.
    """
    if sys.platform != "win32":
        logger.info("[Privileges] relaunch_as_admin is Windows-only; ignoring.")
        return False

    if is_admin():
        return False  # already elevated — nothing to do

    try:
        import ctypes

        # When frozen (PyInstaller), sys.executable IS the app; re-run it with
        # the same args.  When running from source, re-run python with the script.
        if getattr(sys, "frozen", False):
            target = sys.executable
            params = _join_args(sys.argv[1:])
        else:
            target = sys.executable
            params = _join_args([os.path.abspath(sys.argv[0])] + sys.argv[1:])

        # ShellExecuteW verb "runas" triggers the UAC consent dialog.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, params, None, 1
        )
        # ShellExecuteW returns a value > 32 on success.
        if int(rc) > 32:
            logger.info("[Privileges] Elevated instance launched via UAC.")
            return True
        logger.warning(f"[Privileges] UAC elevation declined or failed (rc={rc}).")
        return False
    except Exception as exc:
        logger.error(f"[Privileges] relaunch_as_admin failed: {exc}")
        return False


def _join_args(args: list[str]) -> str:
    """Quote and join args for ShellExecuteW's single param string."""
    quoted = []
    for a in args:
        if a and (" " in a or '"' in a):
            quoted.append('"' + a.replace('"', r"\"") + '"')
        else:
            quoted.append(a)
    return " ".join(quoted)
