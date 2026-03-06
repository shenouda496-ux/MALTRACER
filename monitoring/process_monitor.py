import psutil
import time
import hashlib
from datetime import datetime

from logging_system.logger import log_event


known_processes = set()

# =========================
# Trusted Processes
# =========================

TRUSTED_PROCESSES = {
    "svchost.exe",
    "explorer.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "dwm.exe",
    "spoolsv.exe"
}

# =========================
# Trusted Paths
# =========================

TRUSTED_PATHS = [
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)"
]

# =========================
# Suspicious Paths
# =========================

SUSPICIOUS_PATHS = [
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\"
]

# =========================
# LOLBins
# =========================

LOLBINS = {
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe"
}

# =========================
# Hash
# =========================

def get_file_hash(path):

    try:

        sha256 = hashlib.sha256()

        with open(path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except:
        return None


# =========================
# Collect Network Connections
# =========================

def collect_connections():

    conn_map = {}

    try:

        for conn in psutil.net_connections(kind="inet"):

            if conn.pid is None or conn.pid == 0:
                continue

            conn_map.setdefault(conn.pid, []).append({
                "local": str(conn.laddr),
                "remote": str(conn.raddr),
                "status": conn.status
            })

    except:
        pass

    return conn_map


# =========================
# Suspicious Path
# =========================

def is_suspicious_path(path):

    if not path:
        return False

    path = path.lower()

    for p in SUSPICIOUS_PATHS:
        if p in path:
            return True

    return False


# =========================
# Trusted Path
# =========================

def is_trusted_path(path):

    if not path:
        return False

    path = path.lower()

    for p in TRUSTED_PATHS:
        if path.startswith(p):
            return True

    return False


# =========================
# PowerShell Attack Detection
# =========================

def detect_powershell_attack(name, cmdline):

    if not name:
        return False

    name = name.lower()

    if name in ("powershell.exe", "pwsh.exe"):

        suspicious_flags = [
            "-enc",
            "-encodedcommand",
            "-nop",
            "-noni",
            "iex",
            "downloadstring"
        ]

        cmdline = cmdline.lower()

        for flag in suspicious_flags:

            if flag in cmdline:
                return True

    return False


# =========================
# LOLBin Detection
# =========================

def detect_lolbin(name):

    if not name:
        return False

    return name.lower() in LOLBINS


# =========================
# Should Log Event
# =========================

def should_log(name, path, cmdline):

    if not name:
        return False

    name = name.lower()

    if is_suspicious_path(path):
        return True

    if detect_powershell_attack(name, cmdline):
        return True

    if detect_lolbin(name):
        return True

    if name not in TRUSTED_PROCESSES and not is_trusted_path(path):
        return True

    return False


# =========================
# Monitor Processes
# =========================

def monitor_processes():

    global known_processes

    print("[+] Process Monitor Started")

    while True:

        current_processes = set()

        connections_map = collect_connections()

        for proc in psutil.process_iter(['pid','ppid','name','exe','cmdline']):

            try:

                pid = proc.info['pid']
                if not pid:
                        continue
                ppid = proc.info['ppid']
                name = proc.info['name']
                path = proc.info['exe']
                cmdline_list = proc.info['cmdline']

                cmdline = " ".join(cmdline_list) if cmdline_list else ""

                current_processes.add(pid)

                if pid not in known_processes:

                    if not should_log(name, path, cmdline):
                        continue

                    sha256 = get_file_hash(path) if path else None

                    connections = connections_map.get(pid, [])

                    event = {
                        "event_type": "process_started",
                        "process_name": name,
                        "pid": pid,
                        "parent_pid": ppid,
                        "process_path": path,
                        "command_line": cmdline,
                        "sha256": sha256,
                        "network_connections": connections,
                        "powershell_attack": detect_powershell_attack(name, cmdline),
                        "lolbin_detected": detect_lolbin(name),
                        "timestamp": str(datetime.now())
                    }

                    log_event(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_processes = current_processes

        time.sleep(3)
