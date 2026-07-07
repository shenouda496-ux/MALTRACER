"""
containment_engine.py
"""

import os
import threading
import logging
from datetime import datetime, timezone

from containment.process_killer import ProcessKiller
from containment.network_blocker import NetworkBlocker
from containment.quarantine_manager import QuarantineManager
from alerts.popup_handler import PopupHandler
from logging_system.logger import get_logger

logger = get_logger(__name__)


class ContainmentEngine:

    def __init__(self):
        self.process_killer     = ProcessKiller()
        self.network_blocker    = NetworkBlocker()
        self.quarantine_manager = QuarantineManager()
        self.popup_handler      = PopupHandler()
        self._active_incidents  = {}
        self._lock = threading.Lock()

    def handle(self, event: dict) -> None:
        level = event.get("threat_level", "LOW").upper()

        if level in ("HIGH", "MEDIUM"):
            # Containment is ALWAYS analyst-decided — nothing auto-contains.
            # Both HIGH and MEDIUM raise the interactive Contain/Dismiss prompt;
            # actions run only if the human chooses Contain.
            t = threading.Thread(
                target=self._contain_interactive,
                args=(event,),
                daemon=True,
                name=f"contain-{level.lower()}-{event.get('incident_id', 'unknown')}"
            )
            t.start()
            self._track(event.get("incident_id"), t)

        else:
            logger.info(
                f"[LOW] No containment action. "
                f"incident={event.get('incident_id')} "
                f"score={event.get('risk_score')}"
            )
            self.popup_handler.notify_low(event)

    def _contain_high(self, event: dict) -> None:
        """Perform the actual containment actions — only ever called after the
        analyst has confirmed via the Contain/Dismiss prompt."""
        incident_id = event.get("incident_id", "UNKNOWN")
        logger.warning(
            f"[CONTAIN] Analyst-confirmed containment. "
            f"incident={incident_id} score={event.get('risk_score')}"
        )

        actions_taken = []

        pid = event.get("pid")
        if pid:
            success, detail = self.process_killer.kill(pid, incident_id)
            actions_taken.append({"action": "process_kill", "pid": pid,
                                   "success": success, "detail": detail})

        remote_ip = event.get("remote_ip") or event.get("dst_ip")
        if remote_ip:
            success, detail = self.network_blocker.block_ip(remote_ip, incident_id)
            actions_taken.append({"action": "network_block", "ip": remote_ip,
                                   "success": success, "detail": detail})

        file_path = event.get("file_path") or event.get("destination") or event.get("process_path")
        if file_path and os.path.exists(file_path):
            success, dest, detail = self.quarantine_manager.quarantine(
                file_path, incident_id
            )
            actions_taken.append({"action": "quarantine", "original": file_path,
                                   "dest": dest, "success": success, "detail": detail})

        self.popup_handler.notify_high(event, actions_taken)

        event["containment"] = {
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "mode": "confirmed",
            "actions": actions_taken,
        }

    def _contain_interactive(self, event: dict) -> None:
        """Ask the analyst to Contain or Dismiss; used for BOTH HIGH and MEDIUM.

        No threat is contained without an explicit human decision.  Containment
        actions (kill / quarantine / block) run only when the analyst confirms.
        """
        incident_id = event.get("incident_id", "UNKNOWN")
        level = event.get("threat_level", "MEDIUM").upper()
        logger.info(
            f"[{level}] Awaiting analyst decision (contain/dismiss). "
            f"incident={incident_id} score={event.get('risk_score')}"
        )

        confirmed = self.popup_handler.ask_medium(event)

        if confirmed:
            self._contain_high(event)
        else:
            logger.info(
                f"[{level}] Dismissed by analyst — no action. incident={incident_id}"
            )
            event["containment"] = {
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "mode": "dismissed",
                "actions": [],
            }

    def _track(self, incident_id: str, thread: threading.Thread) -> None:
        if not incident_id:
            return
        with self._lock:
            self._active_incidents[incident_id] = thread

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._active_incidents.values() if t.is_alive())