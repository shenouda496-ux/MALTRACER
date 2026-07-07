"""
network_blocker.py
──────────────────
Blocks traffic to/from a malicious IP address.

Windows : uses Windows Firewall via `netsh advfirewall`
Linux   : uses iptables (kept as fallback, auto-detected)

Rules are tagged with the incident ID so they can be listed and removed.
All rules are stored in a JSON record for clean undo.

Windows note: netsh commands require Administrator privileges.
If not running as admin, block_ip() will return success=False with a clear message.
"""

import subprocess
import sys
import logging
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from logging_system.logger import get_logger

logger = get_logger(__name__)

# ── Storage path (cross-platform) ────────────────────────────────────────────
if sys.platform == "win32":
    _DATA_DIR   = Path(os.environ.get("APPDATA", Path.home())) / "MalTracer"
    _RULES_FILE = _DATA_DIR / "network_blocks.json"
else:
    _DATA_DIR   = Path.home() / ".maltracer"
    _RULES_FILE = _DATA_DIR / "network_blocks.json"

_IS_WINDOWS = sys.platform == "win32"


class NetworkBlocker:

    def __init__(self):
        self._rules: list = self._load_rules()

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def block_ip(self, ip: str, incident_id: str) -> tuple:
        """
        Block all traffic to and from the given IP address.

        Windows: adds two Windows Firewall rules (outbound + inbound)
        Linux:   adds two iptables rules (OUTPUT + INPUT)

        Returns:
            (success: bool, detail: str)
        """
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP address: {ip}"

        if self._already_blocked(ip):
            logger.info(f"[NET] IP already blocked, skipping. ip={ip}")
            return True, f"Already blocked: {ip}"

        if _IS_WINDOWS:
            return self._block_ip_windows(ip, incident_id)
        else:
            return self._block_ip_iptables(ip, incident_id)

    def unblock_ip(self, ip: str) -> tuple:
        """
        Remove all firewall rules blocking the given IP.
        """
        records = [r for r in self._rules if r["ip"] == ip]
        if not records:
            return False, f"No block record found for IP: {ip}"

        errors = []
        for record in records:
            if _IS_WINDOWS:
                ok, err = self._remove_windows_rules(ip, record["incident_id"])
            else:
                ok, err = self._remove_iptables_rules(ip, record)
            if not ok:
                errors.append(err)

        self._rules = [r for r in self._rules if r["ip"] != ip]
        self._save_rules()

        if errors:
            return False, f"Some rules not removed: {errors}"
        logger.info(f"[NET] IP unblocked. ip={ip}")
        return True, f"Unblocked: {ip}"

    def list_blocked(self) -> list:
        """Return all currently blocked IPs."""
        return [r["ip"] for r in self._rules if r["ip"] != "ALL"]

    # ──────────────────────────────────────────────────────────────────────────
    # Windows Firewall (netsh)
    # ──────────────────────────────────────────────────────────────────────────

    def _block_ip_windows(self, ip: str, incident_id: str) -> tuple:
        rule_name_out = f"MalTracer-OUT-{incident_id}-{ip}"
        rule_name_in  = f"MalTracer-IN-{incident_id}-{ip}"

        rules_added = []
        errors = []

        # Block outbound to this IP
        ok, err = self._netsh(
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_out}",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            f"description=MalTracer incident {incident_id}"
        )
        if ok:
            rules_added.append({"direction": "outbound", "rule_name": rule_name_out})
        else:
            errors.append(f"Outbound rule failed: {err}")

        # Block inbound from this IP
        ok, err = self._netsh(
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_in}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            f"description=MalTracer incident {incident_id}"
        )
        if ok:
            rules_added.append({"direction": "inbound", "rule_name": rule_name_in})
        else:
            errors.append(f"Inbound rule failed: {err}")

        if rules_added:
            record = {
                "ip":           ip,
                "incident_id":  incident_id,
                "blocked_at":   datetime.now(timezone.utc).isoformat(),
                "platform":     "windows",
                "rules":        rules_added,
            }
            self._rules.append(record)
            self._save_rules()
            detail = f"Blocked {ip} via Windows Firewall — {[r['direction'] for r in rules_added]}"
            if errors:
                detail += f" | Partial errors: {errors}"
            logger.warning(f"[NET] IP blocked (Windows Firewall). ip={ip} incident={incident_id}")
            return True, detail
        else:
            hint = " (run VS Code / terminal as Administrator)" if errors else ""
            return False, f"All firewall rules failed{hint}: {errors}"

    def _remove_windows_rules(self, ip: str, incident_id: str) -> tuple:
        for direction, rule_name in [
            ("out", f"MalTracer-OUT-{incident_id}-{ip}"),
            ("in",  f"MalTracer-IN-{incident_id}-{ip}"),
        ]:
            self._netsh(
                "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            )
        return True, ""

    def _netsh(self, *args) -> tuple:
        cmd = ["netsh"] + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, ""
            stderr = result.stderr.strip() or result.stdout.strip()
            return False, stderr
        except subprocess.TimeoutExpired:
            return False, "netsh command timed out"
        except FileNotFoundError:
            return False, "netsh not found — are you on Windows?"
        except Exception as e:
            return False, str(e)

    # ──────────────────────────────────────────────────────────────────────────
    # Linux iptables (kept as fallback)
    # ──────────────────────────────────────────────────────────────────────────

    def _block_ip_iptables(self, ip: str, incident_id: str) -> tuple:
        tag = f"maltracer:{incident_id}"
        rules_added = []
        errors = []

        for chain, flag in [("OUTPUT", "-d"), ("INPUT", "-s")]:
            ok, err = self._iptables(
                "-A", chain, flag, ip, "-j", "DROP",
                "-m", "comment", "--comment", tag
            )
            if ok:
                rules_added.append({"chain": chain, "ip": ip})
            else:
                errors.append(f"{chain} rule failed: {err}")

        if rules_added:
            self._rules.append({
                "ip": ip, "incident_id": incident_id,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "platform": "linux", "rules": rules_added,
            })
            self._save_rules()
            return True, f"Blocked {ip} — chains: {[r['chain'] for r in rules_added]}"
        return False, f"All iptables rules failed: {errors}"

    def _remove_iptables_rules(self, ip: str, record: dict) -> tuple:
        tag = f"maltracer:{record['incident_id']}"
        for rule in record.get("rules", []):
            chain = rule["chain"]
            flag  = "-d" if chain == "OUTPUT" else "-s"
            self._iptables("-D", chain, flag, ip, "-j", "DROP",
                           "-m", "comment", "--comment", tag)
        return True, ""

    def _iptables(self, *args) -> tuple:
        try:
            result = subprocess.run(
                ["iptables"] + list(args),
                capture_output=True, text=True, timeout=10,
            )
            return (result.returncode == 0, result.stderr.strip())
        except FileNotFoundError:
            return False, "iptables not found"
        except Exception as e:
            return False, str(e)

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _already_blocked(self, ip: str) -> bool:
        return any(r["ip"] == ip for r in self._rules)

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        if not pattern.match(ip):
            return False
        return all(0 <= int(p) <= 255 for p in ip.split("."))

    def _load_rules(self) -> list:
        try:
            if _RULES_FILE.exists():
                return json.loads(_RULES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    def _save_rules(self) -> None:
        try:
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            _RULES_FILE.write_text(
                json.dumps(self._rules, indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.error(f"[NET] Failed to save rules record: {e}")
