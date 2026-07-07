"""
email_scanner/service.py
────────────────────────
EmailScannerService — an always-on Gmail inbox scanner that feeds the SAME UI
sink as the device monitors (no separate HTTP server / dashboard).

Lifecycle:
    svc = EmailScannerService(sink=main_window, incident_manager=mgr)
    svc.start()          # connects with the stored token, scans in a daemon thread
    svc.stop()           # stops the loop cleanly

The sink is any object exposing (all optional, duck-typed):
    on_alert(event: dict)                 — display / update an alert row
    ask_contain(event: dict) -> bool      — interactive Contain/Dismiss for MEDIUM
    notify_toast(title, message, level)   — native toast
    set_email_status(text: str)           — connection status line

Email containment (Gmail label + trash) stays in email_scanner.actions; the sink
only collects the analyst's decision and renders state.
"""

import threading
import time

from logging_system.logger        import get_logger
from core.incident_manager        import IncidentManager
from email_scanner                import auth
from email_scanner.gmail          import get_emails, get_email, get_headers, get_body
from email_scanner.analyzer       import analyze
from email_scanner.actions        import contain_email

logger = get_logger(__name__)

_POLL_SECONDS = 5
_HIGH_THRESHOLD = 70   # email analyzer scale (see analyzer.py)
_MEDIUM_THRESHOLD = 40


class EmailScannerService:

    def __init__(self, sink=None, incident_manager: IncidentManager | None = None):
        self._sink    = sink
        self._mgr     = incident_manager
        self._stop    = threading.Event()
        self._thread: threading.Thread | None = None
        self._service = None
        self._seen: set[str] = set()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """
        Connect with the stored token and begin scanning.  Returns False (without
        raising) if no account is connected — the caller keeps running everything
        else and shows 'not connected' in the UI.
        """
        if self._thread and self._thread.is_alive():
            return True
        try:
            self._service = auth.login(interactive=False)
        except auth.NotConnected:
            self._set_status("Email scanning: not connected — click to set up")
            logger.info("[EmailService] No Gmail account connected; email idle.")
            return False
        except Exception as exc:
            self._set_status(f"Email scanning: error ({exc})")
            logger.error(f"[EmailService] Connect failed: {exc}")
            return False

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="EmailScanner", daemon=True
        )
        self._thread.start()
        acct = self._account_label()
        self._set_status(f"Email scanning: connected{acct}")
        logger.info("[EmailService] Started.")
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._service = None
        self._set_status("Email scanning: stopped")
        logger.info("[EmailService] Stopped.")

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── Scan loop ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                emails = get_emails(self._service, max_results=20)
                for item in reversed(emails):
                    if self._stop.is_set():
                        break
                    mid = item["id"]
                    if mid in self._seen:
                        continue
                    self._seen.add(mid)
                    self._process_one(mid)
            except Exception as exc:
                logger.error(f"[EmailService] Poll error: {exc}")
            # Sleep in short slices so stop() is responsive.
            self._stop.wait(_POLL_SECONDS)

    def _process_one(self, message_id: str) -> None:
        message = get_email(self._service, message_id)
        headers = get_headers(message)
        body    = get_body(message)
        result  = analyze(headers, body)

        score   = result["risk_score"]
        sender  = headers.get("From", "Unknown")
        subject = headers.get("Subject", "No Subject")

        if score >= _HIGH_THRESHOLD:
            level, tone = "HIGH", "danger"
        elif score >= _MEDIUM_THRESHOLD:
            level, tone = "MEDIUM", "warn"
        else:
            level, tone = "LOW", "info"

        event = {
            "incident_id":     IncidentManager.new_incident_id(),
            "gmail_id":        message_id,
            "type":            "email_threat",
            "level":           level,
            "threat_level":    level,
            "threat_tone":     tone,
            "threat_title":    f"Suspicious email: {subject}" if tone != "info" else subject,
            "threat_category": "Email Threat",
            "threat_action":   result["classification"],
            "threat_process":  sender,
            "threat_path":     ", ".join(result["urls"][:3]) or "N/A",
            "threat_score":    score,
            "risk_score":      score,
            "reasons":         result["reasons"],
            "spf":             result.get("headers", {}).get("spf"),
            "dkim":            result.get("headers", {}).get("dkim"),
            "source":          sender,
        }

        logger.info(f"[EmailService] {sender} | score={score} | {level}")

        if level in ("HIGH", "MEDIUM"):
            # Containment is analyst-decided — HIGH and MEDIUM both prompt; the
            # email is only labeled/trashed if the human chooses Contain.
            self._emit(event)
            if level == "HIGH":
                self._toast("Suspicious email detected",
                            f"{subject}\nReview and choose Contain or Dismiss.", "HIGH")
            if self._ask(event):
                actions = self._contain(message_id, event, level)
                event["threat_action"] = "CONTAINED: " + ", ".join(
                    k for k, v in actions.items() if v
                )
                self._emit(event)  # refresh row to contained state
        else:
            self._emit(event)

    def _contain(self, message_id: str, event: dict, level: str) -> dict:
        try:
            return contain_email(self._service, message_id, event, level)
        except Exception as exc:
            logger.error(f"[EmailService] contain_email failed: {exc}")
            return {}

    # ── Sink helpers (all None-safe) ─────────────────────────────────────────

    def _emit(self, event: dict) -> None:
        if self._sink and hasattr(self._sink, "on_alert"):
            try:
                self._sink.on_alert(event)
            except Exception as exc:
                logger.error(f"[EmailService] sink.on_alert failed: {exc}")

    def _ask(self, event: dict) -> bool:
        if self._sink and hasattr(self._sink, "ask_contain"):
            try:
                return bool(self._sink.ask_contain(event))
            except Exception as exc:
                logger.error(f"[EmailService] sink.ask_contain failed: {exc}")
        return False  # no UI → dismiss (safe default)

    def _toast(self, title: str, message: str, level: str) -> None:
        if self._sink and hasattr(self._sink, "notify_toast"):
            try:
                self._sink.notify_toast(title, message, level)
            except Exception:
                pass

    def _set_status(self, text: str) -> None:
        if self._sink and hasattr(self._sink, "set_email_status"):
            try:
                self._sink.set_email_status(text)
            except Exception:
                pass

    def _account_label(self) -> str:
        try:
            from email_scanner import credential_store
            acct = credential_store.load_account()
            return f" as {acct}" if acct else ""
        except Exception:
            return ""
