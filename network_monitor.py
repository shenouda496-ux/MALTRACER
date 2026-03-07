import psutil
import time
from datetime import datetime
from logging_system.logger import log_event


known_connections = {}
process_cache = {}

WHITELIST_IPS = [
    "127.0.0.1",
    "0.0.0.0"
]

SUSPICIOUS_PORTS = [
    4444,
    1337,
    5555,
    6666,
    9001
]

CACHE_TIME = 120  # seconds


def get_process_name(pid):

    if pid in process_cache:
        return process_cache[pid]

    try:
        name = psutil.Process(pid).name()
    except:
        name = "unknown"

    process_cache[pid] = name
    return name


def monitor_connections():

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

                process_name = get_process_name(pid)

                # deduplication key
                key = (process_name, src_port, dst_ip, dst_port)

                if key in known_connections:
                    continue

                known_connections[key] = now

                suspicious = dst_port in SUSPICIOUS_PORTS

                event = {
                    "event_type": "network_connection",
                    "process_name": process_name,
                    "pid": pid,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "suspicious_port": suspicious,
                    "timestamp": str(datetime.now())
                }

                log_event(event)

            except Exception:
                continue

        time.sleep(5)