"""
process_killer.py
─────────────────
Kills a malicious process and its entire child tree.

Windows-compatible: uses psutil.terminate() + psutil.kill() instead of
SIGTERM/SIGKILL signals, which are Linux-only. psutil handles both platforms.

Safety rules (unchanged):
  - Never kills PID 1 (Linux init) or PID 4 (Windows System)
  - Never kills our own PID or our parent PID
  - Captures full process tree BEFORE killing (forensics)
  - Graceful terminate → 2s wait → force kill
"""

import os
import sys
import time
import logging
from datetime import datetime, timezone

import psutil

from logging_system.logger import get_logger

logger = get_logger(__name__)

# PIDs that must never be killed
_PROTECTED_PIDS = {
    os.getpid(),
    os.getppid(),
    1,   # Linux init / systemd
    4,   # Windows System process
}


class ProcessKiller:

    def kill(self, pid: int, incident_id: str) -> tuple:
        """
        Kill the process with the given PID and all its children.

        Returns:
            (success: bool, detail: str)
        """
        pid = int(pid)

        if pid in _PROTECTED_PIDS or pid <= 0:
            msg = f"Refused to kill protected/invalid PID {pid}"
            logger.error(f"[KILL] {msg}")
            return False, msg

        # Capture process tree before killing (forensics)
        try:
            proc = psutil.Process(pid)
            tree = self._capture_tree(proc)
            logger.info(
                f"[KILL] Process tree captured. "
                f"incident={incident_id} root_pid={pid} tree_size={len(tree)+1}"
            )
        except psutil.NoSuchProcess:
            return False, f"PID {pid} no longer exists"
        except psutil.AccessDenied:
            return False, f"Access denied reading PID {pid}"

        # Kill children first (bottom-up), then parent
        all_procs = tree + [proc]

        killed = []
        failed = []

        for p in all_procs:
            if p.pid in _PROTECTED_PIDS:
                logger.warning(f"[KILL] Skipping protected PID {p.pid}")
                continue
            success = self._kill_one(p, incident_id)
            if success:
                killed.append(p.pid)
            else:
                failed.append(p.pid)

        if killed:
            detail = f"Killed PIDs: {killed}"
            if failed:
                detail += f" | Failed PIDs: {failed}"
            return True, detail
        return False, f"All kill attempts failed. PIDs attempted: {[p.pid for p in all_procs]}"

    # ──────────────────────────────────────────────────────────────────────────

    def _kill_one(self, proc: psutil.Process, incident_id: str) -> bool:
        """
        Graceful terminate → wait 2s → force kill.
        Uses psutil methods (cross-platform — works on Windows and Linux).
        """
        try:
            pid  = proc.pid
            name = proc.name()

            # Step 1: graceful termination
            proc.terminate()   # SIGTERM on Linux, TerminateProcess on Windows
            logger.info(f"[KILL] terminate() sent. pid={pid} name={name}")

            try:
                proc.wait(timeout=2)
                logger.info(f"[KILL] Process exited after terminate(). pid={pid}")
                return True
            except psutil.TimeoutExpired:
                pass  # Still alive — escalate

            # Step 2: force kill
            proc.kill()        # SIGKILL on Linux, also TerminateProcess on Windows
            logger.warning(f"[KILL] kill() sent. pid={pid} name={name}")

            try:
                proc.wait(timeout=3)
                logger.warning(f"[KILL] Process killed. pid={pid}")
                return True
            except psutil.TimeoutExpired:
                logger.error(f"[KILL] Process did not die after kill(). pid={pid}")
                return False

        except psutil.NoSuchProcess:
            return True   # Already dead — that's fine
        except psutil.AccessDenied:
            logger.error(
                f"[KILL] Access denied. pid={proc.pid} "
                "— on Windows, run VS Code as Administrator to kill system processes"
            )
            return False
        except Exception as e:
            logger.error(f"[KILL] Unexpected error. pid={proc.pid} error={e}")
            return False

    def _capture_tree(self, proc: psutil.Process) -> list:
        """
        Return all child processes (recursive), deepest children first.
        This gives bottom-up kill order and the forensic tree.
        """
        try:
            children = proc.children(recursive=True)
            return list(reversed(children))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
