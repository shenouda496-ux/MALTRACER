"""
tests/test_credential_store.py
──────────────────────────────
Round-trip + chunking tests for the encrypted credential store.

Uses an in-memory fake keyring backend (injected via monkeypatch) so the tests
never touch the real Windows Credential Manager / Secret Service.

Run from project root:
    python -m pytest tests/test_credential_store.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_scanner import credential_store as cs


class FakeKeyring:
    """Minimal in-memory keyring: dict keyed by (service, username)."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def get_password(self, service, username):
        return self.store.get((service, username))

    def delete_password(self, service, username):
        if (service, username) in self.store:
            del self.store[(service, username)]
        else:
            raise KeyError("no such password")


@pytest.fixture
def fake_kr(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setattr(cs, "_keyring", lambda: kr)
    return kr


# ── Account ──────────────────────────────────────────────────────────────────

def test_account_round_trip(fake_kr):
    assert cs.load_account() is None
    cs.save_account("user@gmail.com")
    assert cs.load_account() == "user@gmail.com"


# ── Token ────────────────────────────────────────────────────────────────────

def test_token_round_trip_small(fake_kr):
    assert cs.load_token() is None
    cs.save_token('{"token": "abc", "refresh_token": "xyz"}')
    assert cs.load_token() == '{"token": "abc", "refresh_token": "xyz"}'
    assert cs.is_connected() is True


def test_token_round_trip_large_is_chunked(fake_kr):
    # Bigger than _CHUNK_SIZE → must be split across multiple entries and
    # reassembled exactly.
    big = "x" * (cs._CHUNK_SIZE * 3 + 137)
    cs.save_token(big)
    # More than one chunk entry was written.
    count = int(fake_kr.get_password(cs.SERVICE_NAME, cs._TOKEN_COUNT_KEY))
    assert count == 4
    assert cs.load_token() == big


def test_saving_shorter_token_clears_stale_chunks(fake_kr):
    cs.save_token("y" * (cs._CHUNK_SIZE * 3))     # 3 chunks
    cs.save_token("z" * 10)                        # 1 chunk
    assert cs.load_token() == "z" * 10
    # Stale chunks 1 and 2 must be gone.
    assert fake_kr.get_password(cs.SERVICE_NAME, cs._TOKEN_CHUNK_FMT.format(2)) is None


def test_clear_removes_token_and_account(fake_kr):
    cs.save_account("user@gmail.com")
    cs.save_token("t" * (cs._CHUNK_SIZE + 5))
    cs.clear()
    assert cs.load_token() is None
    assert cs.load_account() is None
    assert cs.is_connected() is False


def test_clear_token_keeps_account(fake_kr):
    cs.save_account("user@gmail.com")
    cs.save_token("tok")
    cs.clear_token()
    assert cs.load_token() is None
    assert cs.load_account() == "user@gmail.com"


def test_empty_token_clears(fake_kr):
    cs.save_token("tok")
    cs.save_token("")
    assert cs.load_token() is None


def test_missing_chunk_returns_none(fake_kr):
    cs.save_token("a" * (cs._CHUNK_SIZE * 2))
    # Corrupt the store by deleting one chunk.
    fake_kr.delete_password(cs.SERVICE_NAME, cs._TOKEN_CHUNK_FMT.format(1))
    assert cs.load_token() is None
