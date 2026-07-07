"""
email_scanner/credential_store.py
─────────────────────────────────
Secure, encrypted-at-rest storage for the Gmail account + OAuth token.

Backend: the cross-platform ``keyring`` library.
  • Windows → Windows Credential Manager (DPAPI-encrypted per-user).
  • macOS   → Keychain.
  • Linux   → Secret Service (GNOME Keyring / KWallet), with keyrings.alt as a
              possible encrypted-file fallback.

The OAuth token is a JSON blob (~1–1.5 KB).  The Windows Credential Manager caps
a single credential blob at ~2.5 KB (stored as UTF-16, so ~1280 chars).  To stay
safely under that everywhere, the token is split into fixed-size chunks and the
chunk count is stored alongside it.  No email address or token is ever written to
source or to a plaintext file.

Public API:
    save_account(email) / load_account() -> str | None
    save_token(token_json) / load_token() -> str | None
    clear()               — remove both account and token
    is_connected()        — True if a token is stored
"""

from logging_system.logger import get_logger

logger = get_logger(__name__)

SERVICE_NAME = "MalTracer"

# keyring keys ("username" field of each credential entry)
_ACCOUNT_KEY      = "gmail_account"
_TOKEN_COUNT_KEY  = "gmail_token_chunks"
_TOKEN_CHUNK_FMT  = "gmail_token_{}"

# Conservative chunk size (chars) to fit Windows Credential Manager's blob cap.
_CHUNK_SIZE = 1000


def _keyring():
    """
    Return the keyring module.  Imported lazily so this module imports even when
    keyring is not installed (and so tests can monkeypatch this function to inject
    an in-memory fake backend).
    """
    import keyring
    return keyring


# ── Account ──────────────────────────────────────────────────────────────────

def save_account(email: str) -> None:
    try:
        _keyring().set_password(SERVICE_NAME, _ACCOUNT_KEY, email or "")
    except Exception as exc:
        logger.error(f"[CredStore] Failed to save account: {exc}")


def load_account() -> str | None:
    try:
        val = _keyring().get_password(SERVICE_NAME, _ACCOUNT_KEY)
        return val or None
    except Exception as exc:
        logger.error(f"[CredStore] Failed to load account: {exc}")
        return None


# ── Token (chunked) ──────────────────────────────────────────────────────────

def save_token(token_json: str) -> None:
    """Persist the OAuth token JSON, chunked to fit backend size limits."""
    if not token_json:
        clear_token()
        return

    kr = _keyring()
    try:
        # Remove any stale chunks from a previous, longer token first.
        _clear_token_chunks(kr)

        chunks = [
            token_json[i : i + _CHUNK_SIZE]
            for i in range(0, len(token_json), _CHUNK_SIZE)
        ]
        for idx, chunk in enumerate(chunks):
            kr.set_password(SERVICE_NAME, _TOKEN_CHUNK_FMT.format(idx), chunk)
        kr.set_password(SERVICE_NAME, _TOKEN_COUNT_KEY, str(len(chunks)))
        logger.info(f"[CredStore] Saved Gmail token ({len(chunks)} chunk(s)).")
    except Exception as exc:
        logger.error(f"[CredStore] Failed to save token: {exc}")


def load_token() -> str | None:
    """Reassemble and return the stored OAuth token JSON, or None."""
    kr = _keyring()
    try:
        count_str = kr.get_password(SERVICE_NAME, _TOKEN_COUNT_KEY)
        if not count_str:
            return None
        count = int(count_str)
        parts = []
        for idx in range(count):
            part = kr.get_password(SERVICE_NAME, _TOKEN_CHUNK_FMT.format(idx))
            if part is None:
                logger.warning(f"[CredStore] Missing token chunk {idx}; token invalid.")
                return None
            parts.append(part)
        return "".join(parts)
    except Exception as exc:
        logger.error(f"[CredStore] Failed to load token: {exc}")
        return None


def clear_token() -> None:
    try:
        _clear_token_chunks(_keyring())
    except Exception as exc:
        logger.error(f"[CredStore] Failed to clear token: {exc}")


def _clear_token_chunks(kr) -> None:
    """Delete the chunk-count entry and every chunk it references."""
    try:
        count_str = kr.get_password(SERVICE_NAME, _TOKEN_COUNT_KEY)
    except Exception:
        count_str = None

    if count_str:
        try:
            count = int(count_str)
        except ValueError:
            count = 0
        for idx in range(count):
            _safe_delete(kr, _TOKEN_CHUNK_FMT.format(idx))
    _safe_delete(kr, _TOKEN_COUNT_KEY)


def _safe_delete(kr, key: str) -> None:
    try:
        kr.delete_password(SERVICE_NAME, key)
    except Exception:
        pass  # entry may not exist — that's fine


# ── Combined ─────────────────────────────────────────────────────────────────

def clear() -> None:
    """Remove both the stored token and the account (full disconnect)."""
    clear_token()
    _safe_delete(_keyring(), _ACCOUNT_KEY)
    logger.info("[CredStore] Cleared stored Gmail credentials.")


def is_connected() -> bool:
    return load_token() is not None
