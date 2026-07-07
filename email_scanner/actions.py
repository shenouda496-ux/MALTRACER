"""
email_scanner/actions.py
─────────────────────────
Gmail containment actions for suspicious emails.
"""
import logging
logger = logging.getLogger(__name__)

_LABEL_NAME = "MALTRACER-THREAT"
_label_id_cache: dict = {}


def _get_or_create_label(service) -> str:
    cache_key = id(service)
    if cache_key in _label_id_cache:
        return _label_id_cache[cache_key]

    # ابحث عن الـ label الموجود أول
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for lbl in labels:
        if lbl["name"] == _LABEL_NAME:
            _label_id_cache[cache_key] = lbl["id"]
            return lbl["id"]

    # لو مش موجود، إنشئه
    try:
        body = {
            "name": _LABEL_NAME,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
            "color": {
                "backgroundColor": "#fb4c2f",
                "textColor": "#ffffff",
            },
        }
        created = service.users().labels().create(userId="me", body=body).execute()
        _label_id_cache[cache_key] = created["id"]
        logger.info("[EmailActions] Created Gmail label: %s", _LABEL_NAME)
        return created["id"]
    except Exception:
        # لو فشل الإنشاء، جيب الـ label الموجود
        labels = service.users().labels().list(userId="me").execute().get("labels", [])
        for lbl in labels:
            if lbl["name"] == _LABEL_NAME:
                _label_id_cache[cache_key] = lbl["id"]
                return lbl["id"]
        raise


def label_email(service, message_id: str) -> bool:
    try:
        label_id = _get_or_create_label(service)
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"addLabelIds": [label_id]},
        ).execute()
        logger.info("[EmailActions] Labeled email %s", message_id)
        return True
    except Exception as exc:
        logger.error("[EmailActions] label_email failed: %s", exc)
        return False


def trash_email(service, message_id: str) -> bool:
    try:
        service.users().messages().trash(userId="me", id=message_id).execute()
        logger.info("[EmailActions] Trashed email %s", message_id)
        return True
    except Exception as exc:
        logger.error("[EmailActions] trash_email failed: %s", exc)
        return False


def contain_email(service, message_id: str, event: dict, level: str) -> dict:
    actions = {}

    ok = label_email(service, message_id)
    actions["labeled"] = ok
    if ok:
        print(f"[EmailScanner] ✓ Labeled email as {_LABEL_NAME}")

    if level == "HIGH":
        ok = trash_email(service, message_id)
        actions["trashed"] = ok
        if ok:
            print("[EmailScanner] ✓ Moved email to Trash")

    _push_to_popup(event, actions)
    return actions


def _push_to_popup(event: dict, actions: dict) -> None:
    """
    Annotate the event with a human-readable containment summary.  The UI push
    itself is handled by EmailScannerService (which re-emits the event to the
    active UI sink after containment), so this no longer talks to any UI/server
    directly — keeping containment logic decoupled from the presentation layer.
    """
    try:
        parts = []
        if actions.get("labeled"):
            parts.append(f"Labeled as {_LABEL_NAME}")
        if actions.get("trashed"):
            parts.append("Moved to Trash")

        event["containment_summary"] = " | ".join(parts) if parts else "No action"
    except Exception as exc:
        logger.error("[EmailActions] containment summary failed: %s", exc)
