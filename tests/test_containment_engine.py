"""
test_containment_engine.py
──────────────────────────
Tests ContainmentEngine routing logic.
All subprocess/firewall calls are mocked — no admin rights needed.

Run from project root:
    python -m pytest tests/test_containment_engine.py -v
"""

import os
import sys
import time
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from containment.containment_engine import ContainmentEngine

# ── Shared mocks ──────────────────────────────────────────────────────────────
_ok_fw   = MagicMock(returncode=0, stderr="", stdout="Ok.")
_ok_kill = (True, "Killed PIDs: [12345]")
_ok_quar = (True, "/quarantine/INC-TEST/malware.exe", "Quarantined")
_ok_net  = (True, "Blocked 1.2.3.4")


def make_event(level="HIGH", **kwargs):
    base = {
        "incident_id":     f"INC-TEST-{level}",
        "threat_level":    level,
        "risk_score":      90 if level == "HIGH" else 55 if level == "MEDIUM" else 10,
        "threat_category": "ransomware",
        "source":          "test",
        "process_name":    "bad.exe",
    }
    base.update(kwargs)
    return base


def run_engine(event, auto_confirm=True):
    """
    Run the engine and wait for the background thread to finish.
    auto_confirm=True patches ask_medium to return True (contain).
    """
    with patch("containment.process_killer.ProcessKiller.kill",   return_value=_ok_kill), \
         patch("containment.network_blocker.NetworkBlocker.block_ip", return_value=_ok_net), \
         patch("alerts.popup_handler.PopupHandler.notify_high"), \
         patch("alerts.popup_handler.PopupHandler.ask_medium",    return_value=auto_confirm), \
         patch("subprocess.run", return_value=_ok_fw):

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with patch("containment.quarantine_manager._QUARANTINE_DIR", tmp / "q"), \
                 patch("containment.quarantine_manager._MANIFEST_FILE",  tmp / "q" / "manifest.json"):
                engine = ContainmentEngine()
                engine.handle(event)

                # Wait for background thread
                deadline = time.time() + 10
                while engine.active_count() > 0 and time.time() < deadline:
                    time.sleep(0.05)

    return event


class TestRouting:

    def test_low_does_not_trigger_containment(self):
        event = make_event("LOW")
        result = run_engine(event)
        assert "containment" not in result

    def test_high_prompts_and_contains_when_confirmed(self):
        # HIGH no longer auto-contains — it prompts; confirming runs containment.
        event = make_event("HIGH")
        result = run_engine(event, auto_confirm=True)
        assert "containment" in result
        assert result["containment"]["mode"] == "confirmed"

    def test_high_dismissed_no_containment(self):
        event = make_event("HIGH")
        result = run_engine(event, auto_confirm=False)
        assert result["containment"]["mode"] == "dismissed"
        assert result["containment"]["actions"] == []

    def test_medium_confirmed_triggers_containment(self):
        event = make_event("MEDIUM")
        result = run_engine(event, auto_confirm=True)
        assert "containment" in result
        assert result["containment"]["mode"] == "confirmed"

    def test_medium_dismissed_no_containment(self):
        event = make_event("MEDIUM")
        result = run_engine(event, auto_confirm=False)
        assert result["containment"]["mode"] == "dismissed"
        assert result["containment"]["actions"] == []

    def test_unknown_level_treated_as_low(self):
        event = make_event("UNKNOWN_LEVEL")
        result = run_engine(event)
        assert "containment" not in result


class TestHighContainmentActions:

    def test_kill_called_when_pid_present(self):
        event = make_event("HIGH", pid=9999)
        with patch("containment.process_killer.ProcessKiller.kill", return_value=_ok_kill) as mock_kill, \
             patch("containment.network_blocker.NetworkBlocker.block_ip", return_value=_ok_net), \
             patch("alerts.popup_handler.PopupHandler.notify_high"), \
             patch("alerts.popup_handler.PopupHandler.ask_medium", return_value=True), \
             patch("subprocess.run", return_value=_ok_fw):
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                with patch("containment.quarantine_manager._QUARANTINE_DIR", tmp / "q"), \
                     patch("containment.quarantine_manager._MANIFEST_FILE", tmp / "q" / "manifest.json"):
                    engine = ContainmentEngine()
                    engine.handle(event)
                    deadline = time.time() + 5
                    while engine.active_count() > 0 and time.time() < deadline:
                        time.sleep(0.05)
            mock_kill.assert_called_once_with(9999, event["incident_id"])

    def test_network_block_called_when_ip_present(self):
        event = make_event("HIGH", remote_ip="1.2.3.4")
        with patch("containment.process_killer.ProcessKiller.kill", return_value=_ok_kill), \
             patch("containment.network_blocker.NetworkBlocker.block_ip", return_value=_ok_net) as mock_net, \
             patch("alerts.popup_handler.PopupHandler.notify_high"), \
             patch("alerts.popup_handler.PopupHandler.ask_medium", return_value=True), \
             patch("subprocess.run", return_value=_ok_fw):
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                with patch("containment.quarantine_manager._QUARANTINE_DIR", tmp / "q"), \
                     patch("containment.quarantine_manager._MANIFEST_FILE", tmp / "q" / "manifest.json"):
                    engine = ContainmentEngine()
                    engine.handle(event)
                    deadline = time.time() + 5
                    while engine.active_count() > 0 and time.time() < deadline:
                        time.sleep(0.05)
            mock_net.assert_called_once_with("1.2.3.4", event["incident_id"])

    def test_no_kill_without_pid(self):
        event = make_event("HIGH")   # no pid key
        with patch("containment.process_killer.ProcessKiller.kill", return_value=_ok_kill) as mock_kill, \
             patch("containment.network_blocker.NetworkBlocker.block_ip", return_value=_ok_net), \
             patch("alerts.popup_handler.PopupHandler.notify_high"), \
             patch("alerts.popup_handler.PopupHandler.ask_medium", return_value=True), \
             patch("subprocess.run", return_value=_ok_fw):
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                with patch("containment.quarantine_manager._QUARANTINE_DIR", tmp / "q"), \
                     patch("containment.quarantine_manager._MANIFEST_FILE", tmp / "q" / "manifest.json"):
                    engine = ContainmentEngine()
                    engine.handle(event)
                    deadline = time.time() + 5
                    while engine.active_count() > 0 and time.time() < deadline:
                        time.sleep(0.05)
            mock_kill.assert_not_called()

    def test_partial_failure_does_not_stop_other_actions(self):
        """If kill fails, network block should still run."""
        event = make_event("HIGH", pid=9999, remote_ip="1.2.3.4")
        with patch("containment.process_killer.ProcessKiller.kill",        return_value=(False, "Access denied")), \
             patch("containment.network_blocker.NetworkBlocker.block_ip",  return_value=_ok_net) as mock_net, \
             patch("alerts.popup_handler.PopupHandler.notify_high"), \
             patch("alerts.popup_handler.PopupHandler.ask_medium", return_value=True), \
             patch("subprocess.run", return_value=_ok_fw):
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                with patch("containment.quarantine_manager._QUARANTINE_DIR", tmp / "q"), \
                     patch("containment.quarantine_manager._MANIFEST_FILE", tmp / "q" / "manifest.json"):
                    engine = ContainmentEngine()
                    engine.handle(event)
                    deadline = time.time() + 5
                    while engine.active_count() > 0 and time.time() < deadline:
                        time.sleep(0.05)
            # Network block should still have been attempted despite kill failure
            mock_net.assert_called_once()


class TestActiveCount:

    def test_active_count_returns_int(self):
        engine = ContainmentEngine()
        assert isinstance(engine.active_count(), int)
        assert engine.active_count() >= 0
