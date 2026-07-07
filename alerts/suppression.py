"""
alerts/suppression.py
─────────────────────
Remembers threats the user has explicitly *dismissed* so the same alert does not
prompt again.

A threat is identified by a stable "key" derived from the most specific field
available (email sender, remote IP, file path, or process name+hash) rather than
the per-event incident_id (which is unique every time).  Once dismissed, that key
is suppressed: the MEDIUM Contain/Dismiss modal is not shown again for it.

The dismissed set is persisted to  <MalTracer data dir>/dismissed.json  so the
choice survives restarts.  Delete that file (or call clear()) to reset.

Security note: suppression is intentionally specific — it only silences the exact
same file/IP/process/sender the user dismissed, not a whole category.
"""

import json
import threading

from utils.constants import BASE_DIR
from logging_system.logger import get_logger

logger = get_logger(__name__)

_STORE = BASE_DIR / "dismissed.json"

_lock = threading.Lock()
_dismissed: set[str] | None = None   # lazily loaded


# ── Key derivation ───────────────────────────────────────────────────────────

def threat_key(event: dict) -> str:
    """A stable identity for a threat, independent of the per-event incident id."""
    # Email — key on the sender / gmail id.
    if event.get("gmail_id") or (event.get("type") == "email_threat"):
        sender = event.get("source") or event.get("threat_process") or "unknown"
        return f"email:{sender.lower()}"

    # Network — key on the remote IP.
    ip = event.get("remote_ip") or event.get("dst_ip")
    cat = f"{event.get('threat_category', '')} {event.get('event_type', '')}".lower()
    if ip and ("network" in cat or "c2" in cat or event.get("dst_ip")):
        return f"net:{ip}"

    # Process — key on name + hash when we have both.
    proc = event.get("process_name") or event.get("threat_process")
    sha  = event.get("sha256")
    if proc and sha:
        return f"proc:{proc.lower()}:{sha}"

    # File — key on the path.
    path = event.get("file_path") or event.get("threat_path")
    if path and path not in ("N/A", None):
        return f"path:{str(path).lower()}"

    if proc:
        return f"proc:{proc.lower()}"

    return f"title:{event.get('threat_title', 'unknown').lower()}"


# ── Persistence ──────────────────────────────────────────────────────────────

def _load() -> set[str]:
    global _dismissed
    if _dismissed is not None:
        return _dismissed
    data: set[str] = set()
    try:
        if _STORE.exists():
            data = set(json.loads(_STORE.read_text(encoding="utf-8")))
    except Exception as exc:
        logger.warning(f"[Suppression] Could not read {_STORE}: {exc}")
    _dismissed = data
    return _dismissed

def _save() -> None:
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        _STORE.write_text(json.dumps(sorted(_dismissed or [])), encoding="utf-8")
    except Exception as exc:
        logger.error(f"[Suppression] Could not write {_STORE}: {exc}")


# ── Public API ───────────────────────────────────────────────────────────────

def is_dismissed(event: dict) -> bool:
    with _lock:
        return threat_key(event) in _load()

def mark_dismissed(event: dict) -> None:
    key = threat_key(event)
    with _lock:
        store = _load()
        if key not in store:
            store.add(key)
            _save()
            logger.info(f"[Suppression] Dismissed threat suppressed: {key}")

def discard_key(key: str) -> None:
    """Un-suppress a single threat by its key (e.g. the user later contained it)."""
    if not key:
        return
    with _lock:
        store = _load()
        if key in store:
            store.discard(key)
            _save()
            logger.info(f"[Suppression] Un-suppressed threat: {key}")

def clear() -> None:
    """Forget all dismissed threats (they can prompt again)."""
    global _dismissed
    with _lock:
        _dismissed = set()
        _save()
        logger.info("[Suppression] Cleared all dismissed threats.")
