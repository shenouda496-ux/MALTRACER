"""
tests/test_resources.py
───────────────────────
Tests for utils.resources.resource_path.

Run from project root:
    python -m pytest tests/test_resources.py -v
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import resources


def test_resource_path_returns_absolute():
    p = resources.resource_path("detection_engine", "rules")
    assert p.is_absolute()


def test_resource_path_resolves_bundled_rules_from_source():
    for name in ("process.rules", "network.rules", "file.rules"):
        assert resources.resource_path("detection_engine", "rules", name).exists()


def test_resource_path_resolves_logs_dataset():
    assert resources.resource_path("logs", "2026-03-13_edr_logs.json").exists()


def test_base_dir_is_project_root_from_source():
    # base_dir() should point at the project root (contains maltracer.py).
    assert (resources.base_dir() / "maltracer.py").exists()


def test_meipass_override(monkeypatch, tmp_path):
    # When frozen, resource_path should resolve under sys._MEIPASS.
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    got = resources.resource_path("foo", "bar.txt")
    assert got == Path(tmp_path) / "foo" / "bar.txt"
