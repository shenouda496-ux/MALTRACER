"""
email_scanner/main.py
─────────────────────
Headless entry for `python maltracer.py --email-scan`.

Kept for backward compatibility.  The live app (default mode) runs the Gmail
scanner in-process against the native GUI; this headless path drives the SAME
EmailScannerService but with a console sink that prints results and auto-dismisses
MEDIUM prompts (no interactive UI in a terminal).
"""

import time

from logging_system.logger    import get_logger
from email_scanner            import auth
from email_scanner.service    import EmailScannerService

logger = get_logger(__name__)


class ConsoleSink:
    """Minimal duck-typed sink for headless email scanning."""

    def on_alert(self, event: dict) -> None:
        level = event.get("threat_level", "LOW")
        print(f"  [{level:6}] {event.get('threat_process','?')} — "
              f"{event.get('threat_title','')}  (score {event.get('threat_score',0)})")

    def ask_contain(self, event: dict) -> bool:
        # No terminal UI to decide MEDIUM interactively → do not auto-contain.
        print(f"  [MEDIUM] {event.get('threat_title','')} — not contained "
              f"(no interactive UI in headless mode)")
        return False

    def notify_toast(self, title: str, message: str, level: str) -> None:
        print(f"  >> {title}: {message.splitlines()[0]}")

    def set_email_status(self, text: str) -> None:
        print(f"  {text}")


def run_email_monitor():
    """Connect (browser consent if needed) and scan the inbox until interrupted."""
    # Ensure we are connected; opens the browser on first run.
    auth.login(interactive=True)

    svc = EmailScannerService(sink=ConsoleSink())
    if not svc.start():
        print("[EmailScanner] Could not start — no account connected.")
        return

    print("[EmailScanner] Scanning inbox. Press Ctrl+C to stop.")
    try:
        while svc.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EmailScanner] Stopping…")
    finally:
        svc.stop()


if __name__ == "__main__":
    run_email_monitor()
