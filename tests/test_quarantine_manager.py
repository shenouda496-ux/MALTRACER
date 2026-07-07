"""
test_quarantine_manager.py
──────────────────────────
Tests QuarantineManager using temp directories.
No admin rights needed. Safe on Windows.

Run from project root:
    python -m pytest tests/test_quarantine_manager.py -v
"""

import os
import sys
import stat
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from containment.quarantine_manager import QuarantineManager


@pytest.fixture
def tmp_dirs():
    # NOTE: quarantined files are made read-only, which makes the default
    # TemporaryDirectory cleanup fail on Windows. Manage teardown ourselves:
    # clear write bits first, then remove ignoring any residual AV lock.
    d = tempfile.mkdtemp()
    tmp = Path(d)
    quarantine_dir  = tmp / "quarantine"
    manifest_file   = quarantine_dir / "manifest.json"
    try:
        yield tmp, quarantine_dir, manifest_file
    finally:
        for root, _dirs, files in os.walk(tmp):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def qm(tmp_dirs):
    _, q_dir, q_manifest = tmp_dirs
    with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
         patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
        return QuarantineManager()


def make_dummy_file(directory: Path, name: str = "malware.exe") -> Path:
    f = directory / name
    f.write_bytes(b"MZ" + b"\xDE\xAD\xBE\xEF" * 50)
    return f


class TestQuarantine:

    def test_quarantine_moves_file(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp)
        assert dummy.exists()

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            ok, dest, detail = qm.quarantine(str(dummy), "INC-001")

        assert ok, f"quarantine should succeed: {detail}"
        assert not dummy.exists(), "original file should be gone"
        assert Path(dest).exists(), "quarantined file should exist at dest"

    def test_quarantine_nonexistent_file(self, qm):
        ok, dest, detail = qm.quarantine("/nonexistent/path/file.exe", "INC-002")
        assert not ok
        assert "not found" in detail.lower()

    def test_quarantine_adds_to_manifest(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp, "trojan.dll")

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            ok, dest, _ = qm.quarantine(str(dummy), "INC-003")

        assert ok
        records = qm.list_quarantined("INC-003")
        assert len(records) == 1
        assert records[0]["incident_id"] == "INC-003"
        assert records[0]["sha256"] != "HASH_ERROR"

    def test_quarantine_already_quarantined(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp)

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            ok1, dest1, _ = qm.quarantine(str(dummy), "INC-004")
            # Try to quarantine the already-moved file
            ok2, _, detail2 = qm.quarantine(dest1, "INC-004")

        assert ok1
        assert not ok2
        assert "already in quarantine" in detail2.lower()

    def test_quarantine_file_is_readonly(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp)

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            ok, dest, _ = qm.quarantine(str(dummy), "INC-005")

        assert ok
        dest_path = Path(dest)
        mode = dest_path.stat().st_mode
        # Write bits should be off for owner
        assert not (mode & stat.S_IWUSR), "file should not be owner-writable"


class TestRestore:

    def test_restore_returns_file(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp, "restore_me.exe")
        original_path = str(dummy)

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            ok, dest, _ = qm.quarantine(original_path, "INC-006")
            assert ok

            ok2, detail = qm.restore("INC-006", "restore_me.exe")

        assert ok2, f"restore should succeed: {detail}"
        assert Path(original_path).exists(), "file should be back at original path"

    def test_restore_nonexistent_record(self, qm):
        ok, detail = qm.restore("INC-NOTREAL", "ghost.exe")
        assert not ok
        assert "No quarantine record" in detail

    def test_restore_marks_record(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        dummy = make_dummy_file(tmp, "mark_me.exe")

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            qm.quarantine(str(dummy), "INC-007")
            qm.restore("INC-007", "mark_me.exe")

        records = qm.list_quarantined("INC-007")
        assert records[0]["restored"] is True
        assert "restored_at" in records[0]


class TestHashAndManifest:

    def test_sha256_is_consistent(self, tmp_dirs):
        tmp, _, _ = tmp_dirs
        f = make_dummy_file(tmp, "hash_test.bin")
        h1 = QuarantineManager._sha256(f)
        h2 = QuarantineManager._sha256(f)
        assert h1 == h2
        assert len(h1) == 64

    def test_list_quarantined_filtered(self, qm, tmp_dirs):
        tmp, q_dir, q_manifest = tmp_dirs
        f1 = make_dummy_file(tmp, "a.exe")
        f2 = make_dummy_file(tmp, "b.exe")

        with patch("containment.quarantine_manager._QUARANTINE_DIR", q_dir), \
             patch("containment.quarantine_manager._MANIFEST_FILE",  q_manifest):
            qm.quarantine(str(f1), "INC-A")
            qm.quarantine(str(f2), "INC-B")

        assert len(qm.list_quarantined("INC-A")) == 1
        assert len(qm.list_quarantined("INC-B")) == 1
        assert len(qm.list_quarantined()) == 2
