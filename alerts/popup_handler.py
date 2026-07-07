"""
alerts/popup_handler.py  (in-process edition)
─────────────────────────────────────────────
Bridge between the ContainmentEngine and the native desktop GUI.

The public API is unchanged so containment/containment_engine.py and the existing
tests keep working:

    PopupHandler().notify_high(event, actions_taken)
    PopupHandler().notify_low(event)
    PopupHandler().ask_medium(event) -> bool     # blocks until user decides

What changed is the *implementation*.  The old version ran a localhost HTTP server
and spawned an Electron window, exchanging JSON over stdout.  That is gone.  Now
events are handed to an in-process "UI sink" (the PySide6 MainWindow) registered
via set_ui_sink().  ask_medium() forwards the decision request to the sink and
blocks the calling containment thread on the sink's answer — identical synchronous
contract to before.

When no sink is registered (headless --monitor, unit tests), notify_* are cheap
no-ops that just log, and ask_medium() returns False (dismiss) — a safe default.

The sink is any object exposing (all optional, duck-typed):
    on_alert(event: dict)
    ask_contain(event: dict) -> bool
    notify_toast(title: str, message: str, level: str)
"""

import threading

from logging_system.logger import get_logger

logger = get_logger(__name__)

# ── Registered UI sink (set by the GUI at startup) ───────────────────────────
_ui_sink = None
_ui_lock = threading.Lock()

# How long a MEDIUM prompt waits for the analyst before defaulting to dismiss.
MEDIUM_DECISION_TIMEOUT = 120  # seconds


def set_ui_sink(sink) -> None:
    """Register the GUI (or any duck-typed sink) to receive alerts."""
    global _ui_sink
    with _ui_lock:
        _ui_sink = sink
    logger.info(f"[POPUP] UI sink registered: {type(sink).__name__}")


def get_ui_sink():
    with _ui_lock:
        return _ui_sink


def _enrich_monitor_event(event: dict) -> dict:
    """Add threat display fields to a live monitor event (unchanged behavior)."""
    ed = event.get("event_data", {})

    level = event.get("threat_level", event.get("level", "LOW")).upper()
    tone_map = {"HIGH": "danger", "MEDIUM": "warn", "LOW": "info"}
    tone = tone_map.get(level, "info")

    event.setdefault("threat_tone", tone)
    event.setdefault("threat_title", event.get("message", "Suspicious activity detected"))
    event.setdefault(
        "threat_category",
        event.get("threat_category", ed.get("event_type", "unknown")).replace("_", " ").title(),
    )
    event.setdefault(
        "threat_process",
        ed.get("process_name", event.get("process_name", event.get("source", "unknown"))),
    )
    event.setdefault(
        "threat_path",
        ed.get("destination")
        or event.get("destination")
        or event.get("file_path")
        or event.get("process_path")
        or "N/A",
    )
    event.setdefault("threat_score", event.get("risk_score", 0))
    event.setdefault("threat_action", f"Score: {event.get('risk_score', 0)}/100")
    return event


class PopupHandler:
    """Thin, stateless forwarder to the registered UI sink."""

    def __init__(self):
        # Intentionally cheap: no server, no subprocess, no GUI dependency.
        # This keeps ContainmentEngine construction (and its tests) fast and
        # side-effect-free.
        pass

    # ── Public API (called by ContainmentEngine) ─────────────────────────────

    def ask_medium(self, event: dict) -> bool:
        """
        Show the MEDIUM event and BLOCK until the user chooses Contain (True) or
        Dismiss (False).  Returns False if no GUI is attached or on timeout.
        """
        incident_id = event.get("incident_id", "UNKNOWN")
        event = _enrich_monitor_event(event)

        sink = get_ui_sink()
        if sink is None:
            logger.info(f"[POPUP] MEDIUM (headless) auto-dismiss. incident={incident_id}")
            return False

        try:
            if hasattr(sink, "on_alert"):
                sink.on_alert(event)
            logger.info(f"[POPUP] MEDIUM prompt shown. incident={incident_id}")
            if hasattr(sink, "ask_contain"):
                confirmed = bool(sink.ask_contain(event))
            else:
                confirmed = False
        except Exception as exc:
            logger.error(f"[POPUP] ask_medium sink error: {exc}")
            confirmed = False

        logger.info(f"[POPUP] MEDIUM decision: incident={incident_id} confirmed={confirmed}")
        return confirmed

    def notify_high(self, event: dict, actions_taken: list) -> None:
        incident_id = event.get("incident_id", "UNKNOWN")
        process     = event.get("process_name", event.get("source", "Unknown"))
        summary     = self._summarise_actions(actions_taken)

        event = _enrich_monitor_event(event)
        event["threat_tone"] = "danger"
        event.setdefault("contained", True)
        event["threat_action"] = f"Contained: {summary}"

        sink = get_ui_sink()
        if sink is not None:
            try:
                if hasattr(sink, "on_alert"):
                    sink.on_alert(event)
                if hasattr(sink, "notify_toast"):
                    sink.notify_toast(
                        "MalTracer — Threat Contained",
                        f"Incident: {incident_id}\nProcess: {process}\nActions: {summary}",
                        "HIGH",
                    )
            except Exception as exc:
                logger.error(f"[POPUP] notify_high sink error: {exc}")

        logger.warning(f"[POPUP] HIGH notification. incident={incident_id} actions={summary}")

    def notify_low(self, event: dict) -> None:
        event = _enrich_monitor_event(event)
        sink = get_ui_sink()
        if sink is not None and hasattr(sink, "on_alert"):
            try:
                sink.on_alert(event)
            except Exception as exc:
                logger.error(f"[POPUP] notify_low sink error: {exc}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _summarise_actions(actions: list) -> str:
        if not actions:
            return "None"
        parts = []
        for a in actions:
            ok = "✓" if a.get("success") else "✗"
            t  = a.get("action", "unknown")
            if t == "process_kill":
                parts.append(f"{ok} Kill PID {a.get('pid')}")
            elif t == "network_block":
                parts.append(f"{ok} Block {a.get('ip')}")
            elif t == "quarantine":
                parts.append(f"{ok} Quarantine")
        return " | ".join(parts) or "None"
