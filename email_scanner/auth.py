"""
email_scanner/auth.py
─────────────────────
Gmail OAuth2 login backed by the encrypted credential store.

Key differences from the old file-based version:
  • The OAuth *client* ("desktop app") secret is bundled with the app and located
    via resource_path, so an end user never touches credentials.json.  See
    CHANGES.md — a desktop-client secret is not a true secret.
  • The resulting *user* token is stored encrypted via credential_store (Windows
    Credential Manager / Secret Service), never as a plaintext token.json.
  • login(interactive=False) reuses/refreshes a stored token silently and raises
    NotConnected when no account is set up yet, so the app can start without email.
  • login(interactive=True) runs the browser consent flow for a first-time connect.

All google imports are lazy (inside functions) so this module imports even when
the google libraries are not installed — keeping the test suite import-safe.
"""

import os

from logging_system.logger import get_logger
from utils.resources       import resource_path
from email_scanner         import credential_store

logger = get_logger(__name__)

# gmail.readonly to scan; gmail.modify to label + trash contained threats.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

# Bundled OAuth client ("desktop app") — developer-supplied, resolved for both
# source and PyInstaller runs.  Override with the MALTRACER_OAUTH_CLIENT env var.
DEFAULT_CLIENT_PATH = resource_path("email_scanner", "credentials.json")

# Legacy plaintext token written by the old flow — migrated then deleted.
_LEGACY_TOKEN_PATH = resource_path("email_scanner", "token.json")


class NotConnected(Exception):
    """Raised by login() when no Gmail account is connected and interactive=False."""


def client_secret_path() -> str:
    return os.environ.get("MALTRACER_OAUTH_CLIENT", str(DEFAULT_CLIENT_PATH))


def is_connected() -> bool:
    return credential_store.is_connected()


def _build_service(creds):
    from googleapiclient.discovery import build
    return build("gmail", "v1", credentials=creds)


def _migrate_legacy_token() -> None:
    """Import an existing plaintext token.json into the credential store once."""
    try:
        if credential_store.load_token():
            return  # already have a stored token
        legacy = _LEGACY_TOKEN_PATH
        if os.path.exists(legacy):
            with open(legacy, encoding="utf-8") as fh:
                data = fh.read()
            if data.strip():
                credential_store.save_token(data)
                logger.info("[Auth] Migrated legacy token.json into secure store.")
            try:
                os.remove(legacy)
            except Exception:
                pass
    except Exception as exc:
        logger.warning(f"[Auth] Legacy token migration skipped: {exc}")


def login(interactive: bool = False):
    """
    Return an authorized Gmail service.

    interactive=False : reuse/refresh a stored token; raise NotConnected if none.
    interactive=True  : run the browser consent flow, persist the token, connect.
    """
    from google.oauth2.credentials       import Credentials
    from google.auth.transport.requests  import Request

    _migrate_legacy_token()

    creds = None
    token_json = credential_store.load_token()
    if token_json:
        try:
            creds = Credentials.from_authorized_user_info(_loads(token_json), SCOPES)
        except Exception as exc:
            logger.warning(f"[Auth] Stored token invalid ({exc}); will re-auth.")
            creds = None

    # Silent refresh of an expired token.
    if creds and not creds.valid and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            credential_store.save_token(creds.to_json())
            logger.info("[Auth] Refreshed Gmail token.")
        except Exception as exc:
            logger.warning(f"[Auth] Token refresh failed ({exc}).")
            creds = None

    if creds and creds.valid:
        return _build_service(creds)

    # No usable token.
    if not interactive:
        raise NotConnected("No Gmail account connected.")

    creds = _run_consent_flow()
    credential_store.save_token(creds.to_json())
    try:
        email = _account_email(creds)
        if email:
            credential_store.save_account(email)
    except Exception:
        pass
    logger.info("[Auth] Gmail account connected via consent flow.")
    return _build_service(creds)


def _run_consent_flow():
    from google_auth_oauthlib.flow import InstalledAppFlow

    path = client_secret_path()
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Bundled OAuth client not found at {path}. "
            "The developer must supply email_scanner/credentials.json."
        )
    flow = InstalledAppFlow.from_client_secrets_file(path, SCOPES)
    # port=0 → an ephemeral localhost port for the OAuth redirect.
    return flow.run_local_server(port=0)


def _account_email(creds) -> str | None:
    """Best-effort fetch of the connected address for display in the UI."""
    try:
        service = _build_service(creds)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")
    except Exception:
        return None


def disconnect() -> None:
    """Forget the connected account (used by the GUI 'Disconnect' action)."""
    credential_store.clear()


def _loads(s: str) -> dict:
    import json
    return json.loads(s)
