"""
test_process_killer.py
──────────────────────
Tests ProcessKiller safely — spawns real disposable processes and kills them.
Never touches any real system process.

Run from project root:
    python -m pytest tests/test_process_killer.py -v
"""

import os
import sys
import time
import subprocess
import pytest
import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from containment.process_killer import ProcessKiller

PY = sys.executable   # correct python path on Windows and Linux


def spawn_dummy():
    """Spawn a sleeping process. Safe to kill."""
    proc = subprocess.Popen(
        [PY, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)
    return proc


def spawn_with_children():
    """Spawn a parent that spawns 2 children."""
    proc = subprocess.Popen(
        [PY, "-c",
         f"import subprocess,time,sys; "
         f"[subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']) for _ in range(2)]; "
         f"time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.6)
    return proc


def is_alive(pid):
    try:
        p = psutil.Process(pid)
        return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


@pytest.fixture
def killer():
    return ProcessKiller()


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSafetyChecks:

    def test_refuses_own_pid(self, killer):
        ok, detail = killer.kill(os.getpid(), "INC-TEST")
        assert not ok
        assert "protected" in detail.lower()

    def test_refuses_parent_pid(self, killer):
        ok, detail = killer.kill(os.getppid(), "INC-TEST")
        assert not ok

    def test_refuses_pid_zero(self, killer):
        ok, detail = killer.kill(0, "INC-TEST")
        assert not ok

    def test_refuses_negative_pid(self, killer):
        ok, detail = killer.kill(-1, "INC-TEST")
        assert not ok

    def test_nonexistent_pid(self, killer):
        ok, detail = killer.kill(9999999, "INC-TEST")
        assert not ok


class TestKillProcess:

    def test_kills_single_process(self, killer):
        proc = spawn_dummy()
        pid  = proc.pid
        assert is_alive(pid), "dummy should be running before kill"

        ok, detail = killer.kill(pid, "INC-TEST-001")

        assert ok, f"kill should succeed: {detail}"
        time.sleep(0.3)
        assert not is_alive(pid), "process should be dead after kill"

    def test_returns_killed_pids_in_detail(self, killer):
        proc = spawn_dummy()
        ok, detail = killer.kill(proc.pid, "INC-TEST-002")
        assert ok
        assert str(proc.pid) in detail

    def test_kill_already_dead_process(self, killer):
        proc = spawn_dummy()
        proc.kill()
        proc.wait()
        time.sleep(0.2)
        # Should not raise — process already gone
        ok, detail = killer.kill(proc.pid, "INC-TEST-003")
        # Either ok=True (process vanished) or ok=False (no such process) is acceptable
        assert isinstance(ok, bool)

    def test_kills_process_tree(self, killer):
        proc = spawn_with_children()
        parent_pid = proc.pid

        # Collect child PIDs before killing
        try:
            parent = psutil.Process(parent_pid)
            child_pids = [c.pid for c in parent.children(recursive=True)]
        except psutil.NoSuchProcess:
            pytest.skip("Parent died before we could read children")

        ok, detail = killer.kill(parent_pid, "INC-TEST-004")
        assert ok, f"tree kill should succeed: {detail}"

        time.sleep(0.5)
        assert not is_alive(parent_pid), "parent should be dead"
        for cpid in child_pids:
            assert not is_alive(cpid), f"child {cpid} should be dead"


class TestCaptureTree:

    def test_capture_returns_list(self, killer):
        proc_obj = subprocess.Popen(
            [PY, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        try:
            p = psutil.Process(proc_obj.pid)
            tree = killer._capture_tree(p)
            assert isinstance(tree, list)
        finally:
            proc_obj.kill()
            proc_obj.wait()

    def test_capture_nonexistent_returns_empty(self, killer):
        class FakeProc:
            pid = 9999999
            def children(self, recursive=True):
                raise psutil.NoSuchProcess(pid=9999999)
        assert killer._capture_tree(FakeProc()) == []
