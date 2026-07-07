"""
test_network_blocker.py
───────────────────────
Tests NetworkBlocker with mocked firewall commands.
No admin rights needed — netsh/iptables calls are intercepted.

Run from project root:
    python -m pytest tests/test_network_blocker.py -v
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from containment.network_blocker import NetworkBlocker

# ── Mock subprocess.run for all firewall commands ────────────────────────────
_ok_result = MagicMock(returncode=0, stderr="", stdout="Ok.")
_fail_result = MagicMock(returncode=1, stderr="Access denied", stdout="")


def make_blocker(tmp_path):
    """Create a NetworkBlocker that saves its rules to a temp file."""
    rules_file = tmp_path / "network_blocks.json"
    with patch("containment.network_blocker._RULES_FILE", rules_file), \
         patch("containment.network_blocker._DATA_DIR", tmp_path):
        blocker = NetworkBlocker()
    blocker._rules_file_override = rules_file
    blocker._data_dir_override    = tmp_path
    return blocker, rules_file


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def blocker(tmp_path):
    b, _ = make_blocker(tmp_path)
    return b


class TestIPValidation:

    def test_valid_ipv4(self, blocker):
        assert blocker._is_valid_ip("192.168.1.1")
        assert blocker._is_valid_ip("0.0.0.0")
        assert blocker._is_valid_ip("255.255.255.255")

    def test_invalid_ips(self, blocker):
        assert not blocker._is_valid_ip("not_an_ip")
        assert not blocker._is_valid_ip("256.0.0.1")
        assert not blocker._is_valid_ip("192.168.1")
        assert not blocker._is_valid_ip("")
        assert not blocker._is_valid_ip("192.168.1.1.1")


class TestBlockIP:

    def test_block_valid_ip(self, blocker, tmp_path):
        with patch("subprocess.run", return_value=_ok_result), \
             patch("containment.network_blocker._RULES_FILE", tmp_path / "rules.json"), \
             patch("containment.network_blocker._DATA_DIR", tmp_path):
            ok, detail = blocker.block_ip("10.0.0.1", "INC-001")
        assert ok
        assert "10.0.0.1" in detail

    def test_block_invalid_ip_rejected(self, blocker):
        ok, detail = blocker.block_ip("999.999.999.999", "INC-002")
        assert not ok
        assert "Invalid" in detail

    def test_no_double_block(self, blocker, tmp_path):
        with patch("subprocess.run", return_value=_ok_result), \
             patch("containment.network_blocker._RULES_FILE", tmp_path / "rules.json"), \
             patch("containment.network_blocker._DATA_DIR", tmp_path):
            blocker.block_ip("10.0.0.2", "INC-003")
            ok, detail = blocker.block_ip("10.0.0.2", "INC-003")
        assert ok
        assert "Already blocked" in detail

    def test_already_blocked_check(self, blocker):
        blocker._rules = [{"ip": "1.2.3.4", "incident_id": "X", "rules": []}]
        assert blocker._already_blocked("1.2.3.4")
        assert not blocker._already_blocked("5.6.7.8")


class TestListBlocked:

    def test_list_blocked_ips(self, blocker, tmp_path):
        with patch("subprocess.run", return_value=_ok_result), \
             patch("containment.network_blocker._RULES_FILE", tmp_path / "rules.json"), \
             patch("containment.network_blocker._DATA_DIR", tmp_path):
            blocker.block_ip("10.1.1.1", "INC-A")
            blocker.block_ip("10.1.1.2", "INC-B")
        blocked = blocker.list_blocked()
        assert "10.1.1.1" in blocked
        assert "10.1.1.2" in blocked
