"""
tests/test_auth_flow.py
───────────────────────
Tests for email_scanner.auth's stored-token login flow.

Google libraries are stubbed via sys.modules so these run even without the real
google packages installed, and never open a browser or hit the network.

Run from project root:
    python -m pytest tests/test_auth_flow.py -v
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_scanner import auth
from email_scanner import credential_store as cs


class FakeKeyring:
    def __init__(self):
        self.store = {}
    def set_password(self, s, u, p): self.store[(s, u)] = p
    def get_password(self, s, u): return self.store.get((s, u))
    def delete_password(self, s, u): self.store.pop((s, u), None)


@pytest.fixture
def fake_kr(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setattr(cs, "_keyring", lambda: kr)
    return kr


@pytest.fixture
def stub_google(monkeypatch):
    """
    Install fake google.oauth2.credentials / google.auth.transport.requests /
    googleapiclient.discovery modules so auth's lazy imports resolve to fakes.
    """
    valid = {"valid": True}

    class FakeCreds:
        def __init__(self, valid=True, expired=False, refresh_token="r"):
            self.valid = valid
            self.expired = expired
            self.refresh_token = refresh_token
        @classmethod
        def from_authorized_user_info(cls, info, scopes):
            return cls(valid=info.get("valid", True),
                       expired=info.get("expired", False),
                       refresh_token=info.get("refresh_token", "r"))
        def refresh(self, request):
            self.valid = True
            self.expired = False
        def to_json(self):
            return '{"valid": true}'

    creds_mod = types.ModuleType("google.oauth2.credentials")
    creds_mod.Credentials = FakeCreds

    req_mod = types.ModuleType("google.auth.transport.requests")
    req_mod.Request = lambda: object()

    disc_mod = types.ModuleType("googleapiclient.discovery")
    disc_mod.build = lambda *a, **k: types.SimpleNamespace(name="gmail-service")

    for name, mod in {
        "google": types.ModuleType("google"),
        "google.oauth2": types.ModuleType("google.oauth2"),
        "google.oauth2.credentials": creds_mod,
        "google.auth": types.ModuleType("google.auth"),
        "google.auth.transport": types.ModuleType("google.auth.transport"),
        "google.auth.transport.requests": req_mod,
        "googleapiclient": types.ModuleType("googleapiclient"),
        "googleapiclient.discovery": disc_mod,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)

    return FakeCreds


def test_login_non_interactive_without_token_raises(fake_kr, stub_google, monkeypatch):
    monkeypatch.setattr(auth, "_migrate_legacy_token", lambda: None)
    with pytest.raises(auth.NotConnected):
        auth.login(interactive=False)


def test_login_with_valid_stored_token_builds_service(fake_kr, stub_google, monkeypatch):
    monkeypatch.setattr(auth, "_migrate_legacy_token", lambda: None)
    cs.save_token('{"valid": true}')
    service = auth.login(interactive=False)
    assert getattr(service, "name", None) == "gmail-service"


def test_login_refreshes_expired_token(fake_kr, stub_google, monkeypatch):
    monkeypatch.setattr(auth, "_migrate_legacy_token", lambda: None)
    cs.save_token('{"valid": false, "expired": true, "refresh_token": "r"}')
    service = auth.login(interactive=False)
    assert getattr(service, "name", None) == "gmail-service"
    # A refreshed token should have been persisted.
    assert cs.load_token() == '{"valid": true}'


def test_is_connected_reflects_store(fake_kr):
    assert auth.is_connected() is False
    cs.save_token("tok")
    assert auth.is_connected() is True
