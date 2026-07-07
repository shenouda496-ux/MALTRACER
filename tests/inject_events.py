"""
tests/inject_events.py
──────────────────────
Deterministic, SAFE test harness for the detection + scoring + classification +
containment pipeline. It feeds crafted process / file / network events at chosen
severities through the REAL DetectionEngine and prints the resulting score, level,
and containment actions.

Safety: HIGH events auto-contain. To avoid touching real system binaries, this
harness always
  • uses a non-existent PID (kill is a graceful no-op),
  • points quarantine at a throwaway temp file it creates,
  • uses a reserved TEST-NET IP (198.51.100.0/24) for network blocking.
Nothing on your real system is killed, quarantined, or blocked.

Usage:
    python tests/inject_events.py --source all     --level all
    python tests/inject_events.py --source process --level medium
    python tests/inject_events.py --source network --level high
"""

import argparse
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection_engine.engine import DetectionEngine
from core.incident_manager import IncidentManager

FAKE_PID = 2_000_000_000          # certainly nonexistent → kill is a no-op
TESTNET_IP = "198.51.100.23"      # RFC 5737 TEST-NET-2 — safe to block


def _dummy_file(tag: str) -> str:
    p = Path(tempfile.gettempdir()) / f"maltracer_test_{tag}.exe"
    p.write_text("MALTRACER TEST DUMMY — safe to delete")
    return str(p)


def build_event(source: str, level: str) -> dict:
    base = {
        "incident_id": IncidentManager.new_incident_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "source": f"{source}_monitor",
    }

    if source == "process":
        base.update({"event_type": "process_started", "pid": FAKE_PID})
        if level == "low":       # cmd.exe (+20)
            base.update(process_name="cmd.exe",
                        process_path=r"C:\Windows\System32\cmd.exe",
                        command_line="cmd.exe /c echo maltracer-test")
        elif level == "medium":  # powershell(+30) + -enc(+40) = 70
            base.update(process_name="powershell.exe",
                        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        command_line="powershell.exe -enc VwByaXRlLU91dHB1dCBoaQ==")
        else:                    # powershell + -enc + iex + downloadstring + base64 = 180
            base.update(process_name="powershell.exe",
                        command_line="powershell.exe -enc iex downloadstring base64",
                        file_path=_dummy_file("proc_high"))

    elif source == "file":
        if level == "low":       # file_created & .exe (+15)
            base.update(event_type="executable_created",
                        destination=r"C:\ProgramData\maltracer_test.exe")
        elif level == "medium":  # Downloads(+30) + .exe(+15) = 45
            base.update(event_type="executable_created",
                        destination=r"C:\Users\test\Downloads\maltracer_test.exe")
        else:                    # Downloads(+30)+Startup(+40)+Temp(+25)+.exe(+15) = 110
            base.update(event_type="executable_created",
                        destination=r"C:\Users\test\Downloads\Temp\Startup\maltracer_test.exe",
                        file_path=_dummy_file("file_high"))

    elif source == "network":
        base.update(event_type="network_connection")
        if level == "low":       # dst_ip not local (+20)
            base.update(process_name="chrome.exe", dst_ip="198.51.100.10", dst_port=443)
        elif level == "medium":  # port 4444 (+30) + not local (+20) = 50
            base.update(process_name="chrome.exe", dst_ip="198.51.100.11", dst_port=4444)
        else:                    # powershell+netconn(+40)+port4444(+30)+not local(+20)=90
            base.update(process_name="powershell.exe", dst_ip=TESTNET_IP, dst_port=4444,
                        pid=FAKE_PID, remote_ip=TESTNET_IP, file_path=_dummy_file("net_high"))

    return base


def run(sources, levels):
    engine = DetectionEngine()
    print("\n" + "=" * 68)
    print(f"  {'SOURCE':8} {'REQUESTED':10} {'SCORE':>6}  {'LEVEL':8} INCIDENT")
    print("=" * 68)

    events = []
    for src in sources:
        for lvl in levels:
            ev = build_event(src, lvl)
            engine.process_event(ev)   # real scoring + containment
            events.append((src, lvl, ev))
            print(f"  {src:8} {lvl:10} {ev.get('risk_score', 0):>6}  "
                  f"{ev.get('threat_level', '?'):8} {ev['incident_id']}")

    # Give HIGH/MEDIUM containment daemon threads a moment to finish.
    time.sleep(3)

    print("\n  Containment results (HIGH auto-contains; MEDIUM headless = dismissed):")
    for src, lvl, ev in events:
        c = ev.get("containment")
        if c:
            acts = ", ".join(
                f"{a['action']}={'ok' if a.get('success') else 'fail'}"
                for a in c.get("actions", [])
            ) or "none"
            print(f"    {src}/{lvl}: mode={c.get('mode')} actions=[{acts}]")
    print("=" * 68 + "\n")
    print("Check incidents:  %APPDATA%\\MalTracer\\incidents\\   |  quarantine + logs alongside")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="MalTracer detection injection harness")
    ap.add_argument("--source", choices=["process", "file", "network", "all"], default="all")
    ap.add_argument("--level",  choices=["low", "medium", "high", "all"], default="all")
    args = ap.parse_args()

    sources = ["process", "file", "network"] if args.source == "all" else [args.source]
    levels  = ["low", "medium", "high"] if args.level == "all" else [args.level]
    run(sources, levels)
