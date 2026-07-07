import psutil
import time
from datetime import datetime

known_connections = {}
process_cache = {}

WHITELIST_IPS = [
    "127.0.0.1",
    "0.0.0.0"
]

SUSPICIOUS_PORTS = [
    # Common Metasploit / RAT ports
    4444,
    1337,
    5555,
    6666,
    9001,
    # Tor
    9050,
    9150,
    # Common reverse shell ports
    1234,
    4545,
    8888,
    # Additional C2
    3333,
    6667,   # IRC-based C2
    6697
]

CACHE_TIME = 120  # seconds


def get_process_info(pid):

    if pid in process_cache:
        return process_cache[pid]

    try:
        proc = psutil.Process(pid)
        name = proc.name()
        
        try:
            exe = proc.exe()
        except:
            exe = ""
            
        try:
            cmd_list = proc.cmdline()
            cmd = " ".join(cmd_list) if cmd_list else ""
        except:
            cmd = ""
            
        info = (name, exe, cmd)
    except:
        info = ("unknown", "", "")

    process_cache[pid] = info
    return info


def monitor_connections(callback=None):

    print("[+] Network Monitor Started")

    while True:

        now = time.time()

        # cleanup old cache
        for k in list(known_connections):
            if now - known_connections[k] > CACHE_TIME:
                del known_connections[k]

        for conn in psutil.net_connections(kind="inet"):

            try:

                if not conn.raddr:
                    continue

                if not conn.pid:
                    continue

                src_ip = conn.laddr.ip
                src_port = conn.laddr.port

                dst_ip = conn.raddr.ip
                dst_port = conn.raddr.port

                pid = conn.pid

                if dst_ip in WHITELIST_IPS:
                    continue

                process_name, process_path, command_line = get_process_info(pid)

                # deduplication key
                key = (process_name, src_port, dst_ip, dst_port)

                if key in known_connections:
                    continue

                known_connections[key] = now

                suspicious = dst_port in SUSPICIOUS_PORTS

                event = {
                    "event_type": "network_connection",
                    "process_name": process_name,
                    "process_path": process_path,
                    "command_line": command_line,
                    "pid": pid,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "suspicious_port": suspicious,
                    "timestamp": str(datetime.now())
                }

                if callback:
                    callback(event)

            except Exception:
                continue

        time.sleep(5)