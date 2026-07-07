"""
simulate_threat.py
──────────────────
Manual end-to-end test — safe on Windows, no admin rights needed for most tests.

Usage (run from your project root in VS Code terminal):

    # Simulate HIGH severity event (auto-contain, no popup):
    python tests/simulate_threat.py --level HIGH

    # Simulate MEDIUM severity (popup dialog appears):
    python tests/simulate_threat.py --level MEDIUM

    # Full HIGH: spawns a real dummy process to kill + creates a file to quarantine
    # + mocks the network block (no admin needed):
    python tests/simulate_threat.py --level HIGH --full

    # Test just the kill:
    python tests/simulate_threat.py --level HIGH --with-process

    # Test just the quarantine:
    python tests/simulate_threat.py --level HIGH --with-file
"""

import os
import sys
import time
import argparse
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Make sure project root is on the path ────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Mock the firewall commands so no admin rights needed for tests ────────────
_mock_result = MagicMock()
_mock_result.returncode = 0
_mock_result.stderr = ""
_mock_result.stdout = "Ok."

_original_run = subprocess.run

def _fake_run(cmd, *args, **kwargs):
    if isinstance(cmd, list) and cmd:
        tool = cmd[0].lower()
        # Mock both netsh (Windows) and iptables (Linux)
        if "netsh" in tool or "iptables" in tool:
            print(f"  [MOCK firewall] {' '.join(str(c) for c in cmd)}")
            return _mock_result
    return _original_run(cmd, *args, **kwargs)


# ── Temp quarantine dir so we don't write to AppData during tests ─────────────
_TEMP_DIR       = Path(tempfile.mkdtemp(prefix="maltracer_sim_"))
_TEMP_QUARANTINE = _TEMP_DIR / "quarantine"
_TEMP_MANIFEST   = _TEMP_QUARANTINE / "manifest.json"


def run_simulation(args):
    print("\n" + "=" * 60)
    print("  MALTRACER — THREAT SIMULATION")
    print("=" * 60)

    event = {
        "incident_id":     "INC-20260513-SIMULATE",
        "threat_level":    args.level,
        "risk_score":      92 if args.level == "HIGH" else 58,
        "threat_category": "ransomware" if args.level == "HIGH" else "c2_communication",
        "source":          "process_monitor",
        "process_name":    "malware_sim.exe",
        "pid":             None,
        "file_path":       None,
        "remote_ip":       None,
        "timestamp":       "2026-05-13T09:00:00",
    }

    dummy_proc = None
    dummy_file = None

    # ── Spawn a real dummy process to kill ────────────────────────────────
    if args.with_process or args.full:
        print("\n[SETUP] Spawning dummy process...")
        # Use 'python' on Windows, 'python3' on Linux
        py = sys.executable
        dummy_proc = subprocess.Popen(
            [py, "-c", "import time; print('dummy running'); time.sleep(120)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        time.sleep(0.3)
        event["pid"] = dummy_proc.pid
        print(f"[SETUP] Dummy process PID: {dummy_proc.pid}")

    # ── Create a dummy file to quarantine ─────────────────────────────────
    if args.with_file or args.full:
        dummy_file = _TEMP_DIR / "fake_malware.exe"
        dummy_file.write_bytes(b"MZ" + b"\xDE\xAD\xBE\xEF" * 100)
        event["file_path"] = str(dummy_file)
        print(f"[SETUP] Dummy file: {dummy_file}")

    # ── Set a fake remote IP ──────────────────────────────────────────────
    if args.full:
        event["remote_ip"] = "185.199.1.100"

    # ── Print event ───────────────────────────────────────────────────────
    print(f"\n[EVENT] Simulated event:")
    for k, v in event.items():
        if v is not None:
            print(f"  {k:<22} = {v}")

    print(f"\n[ENGINE] Passing to ContainmentEngine... (level={args.level})")
    if args.level == "HIGH":
        print("[ENGINE] → Immediate auto-containment")
    elif args.level == "MEDIUM":
        print("[ENGINE] → Popup dialog will appear — you have 60 seconds to respond")
    else:
        print("[ENGINE] → LOW: logged only, no action")

    # ── Run with mocked firewall and temp quarantine dir ──────────────────
    with patch("subprocess.run", side_effect=_fake_run), \
         patch("containment.quarantine_manager._QUARANTINE_DIR", _TEMP_QUARANTINE), \
         patch("containment.quarantine_manager._MANIFEST_FILE",  _TEMP_MANIFEST):

        from containment.containment_engine import ContainmentEngine
        engine = ContainmentEngine()
        engine.handle(event)

        print("\n[ENGINE] Waiting for containment thread to finish...")
        deadline = time.time() + 90   # 60s popup + buffer
        while engine.active_count() > 0 and time.time() < deadline:
            time.sleep(0.2)

    # ── Print results ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)

    containment = event.get("containment", {})
    if containment:
        print(f"  Mode:         {containment.get('mode', 'N/A')}")
        print(f"  Triggered at: {containment.get('triggered_at', 'N/A')}")
        print(f"  Actions taken:")
        for action in containment.get("actions", []):
            status = "✓" if action.get("success") else "✗"
            print(f"    {status} {action.get('action')} — {action.get('detail', '')}")
        if not containment.get("actions"):
            print("    (none)")
    else:
        print("  No containment record (dismissed / LOW / still running)")

    # ── Verify process was killed ─────────────────────────────────────────
    if dummy_proc:
        import psutil
        try:
            p = psutil.Process(dummy_proc.pid)
            alive = p.is_running() and p.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            alive = False
        status = "✗ STILL RUNNING" if alive else "✓ Dead"
        print(f"\n  Dummy process (PID {dummy_proc.pid}): {status}")

    # ── Verify file was quarantined ───────────────────────────────────────
    if dummy_file:
        moved = not dummy_file.exists()
        print(f"  Dummy file quarantined: {'✓ Yes' if moved else '✗ Still at original path'}")
        if moved:
            for f in _TEMP_QUARANTINE.rglob("*"):
                if f.is_file() and f.name != "manifest.json":
                    print(f"  Quarantine path: {f}")

    print("\n  Simulation complete.")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="MalTracer threat simulation")
    parser.add_argument(
        "--level", choices=["HIGH", "MEDIUM", "LOW"], default="HIGH",
        help="Threat level to simulate (default: HIGH)"
    )
    parser.add_argument("--with-process", action="store_true",
                        help="Spawn and kill a real dummy process")
    parser.add_argument("--with-file", action="store_true",
                        help="Create and quarantine a real dummy file")
    parser.add_argument("--full", action="store_true",
                        help="Full simulation: process + file + mocked network block")
    args = parser.parse_args()
    run_simulation(args)


if __name__ == "__main__":
    main()
