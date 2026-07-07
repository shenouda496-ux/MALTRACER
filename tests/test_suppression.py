"""
tests/test_suppression.py
─────────────────────────
Tests for alerts.suppression — dismissed threats should not prompt again, keyed
by a stable threat identity (not the per-event incident id), and persisted.

Run from project root:
    python -m pytest tests/test_suppression.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts import suppression


@pytest.fixture
def temp_store(tmp_path, monkeypatch):
    """Point the suppression store at a temp file and reset in-memory state."""
    monkeypatch.setattr(suppression, "_STORE", tmp_path / "dismissed.json")
    monkeypatch.setattr(suppression, "_dismissed", None)
    yield
    monkeypatch.setattr(suppression, "_dismissed", None)


# ── Key derivation ────────────────────────────────────────────────────────────

def test_key_is_stable_across_incident_ids():
    e1 = {"incident_id": "INC-A", "file_path": "C:/Users/x/Downloads/bad.exe"}
    e2 = {"incident_id": "INC-B", "file_path": "C:/Users/x/Downloads/bad.exe"}
    assert suppression.threat_key(e1) == suppression.threat_key(e2)


def test_key_differs_by_entity():
    a = suppression.threat_key({"file_path": "a.exe"})
    b = suppression.threat_key({"file_path": "b.exe"})
    assert a != b


def test_key_prefers_email_then_ip_then_path():
    assert suppression.threat_key({"type": "email_threat", "source": "x@y.com"}).startswith("email:")
    assert suppression.threat_key({"dst_ip": "1.2.3.4", "threat_category": "C2 communication"}).startswith("net:")
    assert suppression.threat_key({"file_path": "z.exe"}).startswith("path:")


# ── Dismiss / suppress ────────────────────────────────────────────────────────

def test_dismiss_then_suppressed(temp_store):
    ev = {"incident_id": "INC-1", "file_path": "C:/tmp/x.exe"}
    assert suppression.is_dismissed(ev) is False
    suppression.mark_dismissed(ev)
    assert suppression.is_dismissed(ev) is True
    # A different incident id for the same file is also suppressed.
    assert suppression.is_dismissed({"incident_id": "INC-2", "file_path": "C:/tmp/x.exe"}) is True


def test_dismiss_persists_across_reload(temp_store, monkeypatch):
    ev = {"file_path": "C:/tmp/persist.exe"}
    suppression.mark_dismissed(ev)
    # Simulate a fresh process: drop the in-memory cache, keep the file.
    monkeypatch.setattr(suppression, "_dismissed", None)
    assert suppression.is_dismissed(ev) is True


def test_discard_key_unsuppresses(temp_store):
    ev = {"file_path": "C:/tmp/y.exe"}
    suppression.mark_dismissed(ev)
    suppression.discard_key(suppression.threat_key(ev))
    assert suppression.is_dismissed(ev) is False


def test_clear_removes_all(temp_store):
    suppression.mark_dismissed({"file_path": "a.exe"})
    suppression.mark_dismissed({"file_path": "b.exe"})
    suppression.clear()
    assert suppression.is_dismissed({"file_path": "a.exe"}) is False
    assert suppression.is_dismissed({"file_path": "b.exe"}) is False
