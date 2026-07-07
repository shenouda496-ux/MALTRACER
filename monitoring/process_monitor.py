import psutil
import sys
import time
import hashlib
from datetime import datetime

known_processes = set()

# =========================
# Trusted Processes
# =========================

if sys.platform == "win32":

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

else:

    TRUSTED_PROCESSES = {
        "systemd",
        "kthreadd",
        "kworker",
        "sshd",
        "cron",
        "dbus-daemon",
        "NetworkManager",
        "rsyslogd",
        "agetty"
    }

# =========================
# Trusted Paths
# =========================

if sys.platform == "win32":

    TRUSTED_PATHS = [
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)"
    ]

    SUSPICIOUS_PATHS = [
        "\\temp\\",
        "\\appdata\\",
        "\\downloads\\",
        "\\desktop\\"
    ]

else:

    TRUSTED_PATHS = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64"
    ]

    SUSPICIOUS_PATHS = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/"
    ]

# =========================
# LOLBins
# =========================

if sys.platform == "win32":

    LOLBINS = {
        "powershell.exe",
        "cmd.exe",
        "wmic.exe",
        "mshta.exe",
        "rundll32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
        "cscript.exe",
        "wscript.exe",
        "psexec.exe"
    }

else:

    LOLBINS = {
        "nc",
        "ncat",
        "netcat",
        "wget",
        "curl",
        "nmap",
        "socat",
        "python3",
        "perl",
        "ruby"
    }

SAFE_LOLBINS = {
    "powershell.exe",
    "cmd.exe"
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

    except Exception:
        return None

# =========================
# Network Connections
# =========================

def collect_connections():

    conn_map = {}

    try:

        for conn in psutil.net_connections(kind="inet"):

            if conn.pid is None or conn.pid == 0:
                continue

            local_ip = conn.laddr.ip if conn.laddr else None
            local_port = conn.laddr.port if conn.laddr else None

            remote_ip = conn.raddr.ip if conn.raddr else None
            remote_port = conn.raddr.port if conn.raddr else None

            conn_map.setdefault(conn.pid, []).append({

                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": conn.status

            })

    except Exception:
        pass

    return conn_map

# =========================
# Path Checks
# =========================

def is_suspicious_path(path):

    if not path:
        return False

    path = path.lower()

    return any(p in path for p in SUSPICIOUS_PATHS)


def is_trusted_path(path):

    if not path:
        return False

    path = path.lower()

    return any(path.startswith(p) for p in TRUSTED_PATHS)

# =========================
# PowerShell Detection
# =========================

def detect_powershell_attack(name, cmdline):

    if not name:
        return False

    name = name.lower()
    cmdline = cmdline.lower()

    if name in ("powershell.exe", "pwsh.exe"):

        suspicious_flags = [
            "-enc",
            "-encodedcommand",
            "downloadstring",
            "invoke-expression",
            "iex",
            "invoke-webrequest",
            "bypass",
            "hidden",
            "base64"
        ]

        return any(flag in cmdline for flag in suspicious_flags)

    if sys.platform != "win32":

        if name in (
            "bash",
            "sh",
            "python3",
            "python",
            "perl",
            "ruby"
        ):

            reverse_shell = [
                "/dev/tcp/",
                "/dev/udp/",
                "socket.socket",
                "base64.b64decode",
                "0>&1"
            ]

            return any(flag in cmdline for flag in reverse_shell)

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
    cmdline = cmdline.lower()

    # Ignore normal PowerShell/CMD opened interactively
    if name in SAFE_LOLBINS:

        suspicious_args = [

            "-enc",
            "-encodedcommand",
            "downloadstring",
            "invoke-expression",
            "iex",
            "invoke-webrequest",
            "hidden",
            "bypass",
            "base64",
            "http://",
            "https://"

        ]

        if not any(arg in cmdline for arg in suspicious_args):
            return False

    # Executed from Temp/AppData/Downloads/Desktop
    if is_suspicious_path(path):
        return True

    # Encoded PowerShell / Reverse Shell
    if detect_powershell_attack(name, cmdline):
        return True

    # LOLBins only with suspicious arguments
    if detect_lolbin(name):

        suspicious_args = [

            "-enc",
            "-encodedcommand",
            "downloadstring",
            "invoke-expression",
            "iex",
            "invoke-webrequest",
            "hidden",
            "bypass",
            "base64",
            "http://",
            "https://"

        ]

        if any(arg in cmdline for arg in suspicious_args):
            return True

    return False


# =========================
# Main Monitor
# =========================

def monitor_processes(callback=None):

    global known_processes

    print("[+] Process Monitor Started")

    while True:

        current_processes = set()

        connections_map = collect_connections()

        for proc in psutil.process_iter(
            ['pid', 'ppid', 'name', 'exe', 'cmdline']
        ):

            try:

                pid = proc.info["pid"]

                if not pid:
                    continue

                ppid = proc.info["ppid"]
                name = proc.info["name"]
                path = proc.info["exe"]

                cmdline_list = proc.info["cmdline"]
                cmdline = " ".join(cmdline_list) if cmdline_list else ""

                parent_name = ""

                try:
                    parent_name = psutil.Process(ppid).name().lower()
                except Exception:
                    pass

                current_processes.add(pid)

                # Skip already known processes
                if pid in known_processes:
                    continue

                # Ignore non-suspicious processes
                if not should_log(name, path, cmdline):
                    continue

                sha256 = get_file_hash(path) if path else None

                connections = connections_map.get(pid, [])

                event = {

                    "source": "process_monitor",
                    "type": "process",
                    "event_type": "process_started",

                    "process_name": name,
                    "parent_process": parent_name,

                    "pid": pid,
                    "parent_pid": ppid,

                    "process_path": path,
                    "file_path": path,

                    "command_line": cmdline,

                    "sha256": sha256,

                    "network_connections": connections,

                    "powershell_attack":
                        detect_powershell_attack(
                            name,
                            cmdline
                        ),

                    "lolbin_detected":
                        detect_lolbin(
                            name
                        ),

                    "timestamp":
                        str(datetime.now()),

                    "message":
                        f"New process detected: {name}",

                    "event_data": {

                        "event_type":
                            "process_started",

                        "process_name":
                            name,

                        "destination":
                            path,

                        "parent_process":
                            parent_name
                    }

                }

                print(
                    f"[PROCESS] "
                    f"{name} "
                    f"(PID={pid}) "
                    f"Parent={parent_name} "
                    f"path={path}"
                )

                if callback:
                    callback(event)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

            except Exception as e:

                print(
                    f"[PROCESS ERROR] {e}"
                )

        known_processes = current_processes

        # Faster detection (was: time.sleep(3))
        time.sleep(1)   