"""
tests/test_incident_manager.py
───────────────────────────────
Unit tests for core/incident_manager.py

Run from project root:
    python -m pytest tests/test_incident_manager.py -v
"""

import json
import threading
import pytest
from pathlib import Path
from core.incident_manager import IncidentManager, Incident


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_incident_dir(tmp_path):
    return tmp_path / "incidents"


@pytest.fixture
def manager(tmp_incident_dir):
    return IncidentManager(incidents_dir=tmp_incident_dir)


def _make_event(
    incident_id: str = "INC-20260517-aabbccdd",
    level: str = "HIGH",
    score: int = 80,
) -> dict:
    return {
        "incident_id":     incident_id,
        "timestamp":       "2026-05-17T09:00:00+00:00",
        "threat_level":    level,
        "risk_score":      score,
        "threat_category": "ransomware",
        "source":          "process_monitor",
        "process_name":    "evil.exe",
        "pid":             1234,
        "file_path":       "C:/Users/test/evil.exe",
        "remote_ip":       "185.199.1.1",
    }


# ── ID generation ─────────────────────────────────────────────────────────────

class TestIncidentIdGeneration:

    def test_format_is_correct(self):
        iid = IncidentManager.new_incident_id()
        parts = iid.split("-")
        assert parts[0] == "INC"
        assert len(parts[1]) == 8             # YYYYMMDD
        assert len(parts[2]) == 8             # 8 hex chars
        assert all(c in "0123456789abcdef" for c in parts[2])

    def test_ids_are_unique(self):
        ids = {IncidentManager.new_incident_id() for _ in range(100)}
        assert len(ids) == 100


# ── Open ──────────────────────────────────────────────────────────────────────

class TestOpen:

    def test_opens_new_incident(self, manager):
        event = _make_event()
        incident = manager.open(event)
        assert incident.incident_id == event["incident_id"]
        assert incident.state == "OPEN"
        assert incident.threat_level == "HIGH"
        assert incident.risk_score == 80

    def test_open_is_idempotent_for_same_id(self, manager):
        event = _make_event()
        i1 = manager.open(event)
        i2 = manager.open(event)
        assert i1 is i2   # same object returned
        assert manager.total() == 1

    def test_open_raises_without_incident_id(self, manager):
        with pytest.raises(ValueError, match="incident_id"):
            manager.open({"threat_level": "HIGH"})

    def test_open_persists_to_disk(self, manager, tmp_incident_dir):
        event = _make_event()
        manager.open(event)
        path = tmp_incident_dir / f"{event['incident_id']}.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["incident_id"] == event["incident_id"]
        assert data["state"] == "OPEN"

    def test_open_creates_initial_history_entry(self, manager):
        event = _make_event()
        incident = manager.open(event)
        assert len(incident.history) == 1
        assert incident.history[0]["to_state"] == "OPEN"
        assert incident.history[0]["from_state"] is None


# ── Transition ────────────────────────────────────────────────────────────────

class TestTransition:

    def test_open_to_contained(self, manager):
        manager.open(_make_event())
        ok = manager.transition("INC-20260517-aabbccdd", "CONTAINED", reason="auto")
        assert ok is True
        assert manager.get("INC-20260517-aabbccdd").state == "CONTAINED"

    def test_open_to_dismissed(self, manager):
        manager.open(_make_event())
        ok = manager.transition("INC-20260517-aabbccdd", "DISMISSED", reason="user dismissed")
        assert ok
        assert manager.get("INC-20260517-aabbccdd").state == "DISMISSED"

    def test_open_to_failed(self, manager):
        manager.open(_make_event())
        ok = manager.transition("INC-20260517-aabbccdd", "FAILED")
        assert ok

    def test_contained_to_closed(self, manager):
        manager.open(_make_event())
        manager.transition("INC-20260517-aabbccdd", "CONTAINED")
        ok = manager.transition("INC-20260517-aabbccdd", "CLOSED")
        assert ok
        assert manager.get("INC-20260517-aabbccdd").state == "CLOSED"

    def test_closed_is_terminal(self, manager):
        manager.open(_make_event())
        manager.transition("INC-20260517-aabbccdd", "CLOSED")
        ok = manager.transition("INC-20260517-aabbccdd", "CONTAINED")
        assert ok is False   # cannot move out of CLOSED

    def test_transition_unknown_id_returns_false(self, manager):
        ok = manager.transition("INC-DOES-NOT-EXIST", "CLOSED")
        assert ok is False

    def test_transition_invalid_state_returns_false(self, manager):
        manager.open(_make_event())
        ok = manager.transition("INC-20260517-aabbccdd", "FLYING_PIGS")
        assert ok is False

    def test_transition_stores_containment_dict(self, manager):
        manager.open(_make_event())
        containment = {"mode": "automatic", "actions": []}
        manager.transition("INC-20260517-aabbccdd", "CONTAINED", containment=containment)
        incident = manager.get("INC-20260517-aabbccdd")
        assert incident.containment == containment

    def test_transition_appends_to_history(self, manager):
        manager.open(_make_event())
        manager.transition("INC-20260517-aabbccdd", "CONTAINED", reason="test")
        manager.transition("INC-20260517-aabbccdd", "CLOSED", reason="analyst")
        history = manager.get("INC-20260517-aabbccdd").history
        assert len(history) == 3   # OPEN + CONTAINED + CLOSED
        assert history[1]["from_state"] == "OPEN"
        assert history[1]["to_state"] == "CONTAINED"
        assert history[2]["to_state"] == "CLOSED"

    def test_transition_updates_disk(self, manager, tmp_incident_dir):
        manager.open(_make_event())
        manager.transition("INC-20260517-aabbccdd", "CONTAINED")
        path = tmp_incident_dir / "INC-20260517-aabbccdd.json"
        data = json.loads(path.read_text())
        assert data["state"] == "CONTAINED"


# ── Close convenience method ──────────────────────────────────────────────────

class TestClose:

    def test_close_from_contained(self, manager):
        manager.open(_make_event())
        manager.transition("INC-20260517-aabbccdd", "CONTAINED")
        ok = manager.close("INC-20260517-aabbccdd", reason="done")
        assert ok
        assert manager.get("INC-20260517-aabbccdd").state == "CLOSED"


# ── Notes ─────────────────────────────────────────────────────────────────────

class TestNotes:

    def test_add_note(self, manager):
        manager.open(_make_event())
        ok = manager.add_note("INC-20260517-aabbccdd", "False positive confirmed")
        assert ok
        notes = manager.get("INC-20260517-aabbccdd").notes
        assert len(notes) == 1
        assert "False positive confirmed" in notes[0]

    def test_add_note_unknown_id_returns_false(self, manager):
        ok = manager.add_note("INC-DOES-NOT-EXIST", "note")
        assert ok is False


# ── Lookup helpers ────────────────────────────────────────────────────────────

class TestLookup:

    def test_get_returns_none_for_unknown(self, manager):
        assert manager.get("INC-NONE") is None

    def test_get_all_returns_all_incidents(self, manager):
        manager.open(_make_event("INC-20260517-00000001"))
        manager.open(_make_event("INC-20260517-00000002"))
        all_incidents = manager.get_all()
        assert len(all_incidents) == 2

    def test_get_open_filters_state(self, manager):
        manager.open(_make_event("INC-20260517-00000001"))
        manager.open(_make_event("INC-20260517-00000002"))
        manager.transition("INC-20260517-00000001", "CONTAINED")
        open_incidents = manager.get_open()
        assert len(open_incidents) == 1
        assert open_incidents[0]["incident_id"] == "INC-20260517-00000002"

    def test_count_by_state(self, manager):
        manager.open(_make_event("INC-20260517-00000001"))
        manager.open(_make_event("INC-20260517-00000002"))
        manager.transition("INC-20260517-00000001", "CONTAINED")
        counts = manager.count_by_state()
        assert counts["OPEN"] == 1
        assert counts["CONTAINED"] == 1
        assert counts["CLOSED"] == 0

    def test_total(self, manager):
        manager.open(_make_event("INC-20260517-00000001"))
        manager.open(_make_event("INC-20260517-00000002"))
        assert manager.total() == 2


# ── Persistence / load from disk ──────────────────────────────────────────────

class TestPersistence:

    def test_load_from_disk_restores_incidents(self, tmp_incident_dir):
        # Write with manager A
        m1 = IncidentManager(incidents_dir=tmp_incident_dir)
        m1.open(_make_event("INC-20260517-persist01"))
        m1.transition("INC-20260517-persist01", "CONTAINED")

        # Read with a fresh manager B
        m2 = IncidentManager(incidents_dir=tmp_incident_dir)
        loaded = m2.load_from_disk()
        assert loaded == 1
        incident = m2.get("INC-20260517-persist01")
        assert incident is not None
        assert incident.state == "CONTAINED"
        assert incident.threat_level == "HIGH"

    def test_load_skips_corrupt_files(self, tmp_incident_dir):
        tmp_incident_dir.mkdir(parents=True, exist_ok=True)
        bad_file = tmp_incident_dir / "INC-20260517-corrupt.json"
        bad_file.write_text("{not valid json")

        m = IncidentManager(incidents_dir=tmp_incident_dir)
        loaded = m.load_from_disk()
        assert loaded == 0   # corrupt file skipped, no crash

    def test_load_from_empty_dir(self, tmp_incident_dir):
        m = IncidentManager(incidents_dir=tmp_incident_dir)
        loaded = m.load_from_disk()
        assert loaded == 0


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:

    def test_concurrent_opens_do_not_duplicate(self, manager):
        """Multiple threads opening the same incident ID must produce exactly 1."""
        event = _make_event()
        results = []
        lock = threading.Lock()

        def open_it():
            incident = manager.open(event)
            with lock:
                results.append(incident)

        threads = [threading.Thread(target=open_it) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert manager.total() == 1
        # All threads got the same object
        assert all(r is results[0] for r in results)

    def test_concurrent_different_incidents(self, manager):
        """Many threads opening different incidents — all should be stored."""
        def open_incident(n):
            manager.open(_make_event(f"INC-20260517-{n:08d}"))

        threads = [threading.Thread(target=open_incident, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert manager.total() == 50
