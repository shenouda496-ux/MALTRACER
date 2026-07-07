import ctypes
import os
import time
import sys
import hashlib
import logging

from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

recent_deletes = {}
MOVE_TIME_WINDOW = 3
file_hash_cache = {}


# =========================
# Admin check (graceful — never auto-relaunch)
# =========================

def is_admin():
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0   # Linux: check if root
    except Exception:
        return False


# NOTE: The previous version auto-relaunched with UAC here.
# That is removed. We now log a warning and continue with reduced coverage.
if not is_admin():
    _msg = (
        "[FileMonitor] Not running as administrator. "
        "Some protected paths (C:\\Windows\\Temp, C:\\ProgramData) will be skipped. "
        "Run as admin for full coverage."
        if sys.platform == "win32" else
        "[FileMonitor] Not running as root. "
        "Some protected paths (/usr/local/bin, /etc/cron.d) will be skipped. "
        "Run with sudo for full coverage."
    )
    logger.warning(_msg)


# =========================
# Executable extensions
# =========================

if sys.platform == "win32":
    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".scr",
        ".msi"
    }
else:  # Linux
    EXECUTABLE_EXTENSIONS = {
        ".elf",
        ".sh",
        ".py",
        ".rb",
        ".pl",
        ".so"
    }


# =========================
# System paths filter (skip OS internals)
# =========================

if sys.platform == "win32":
    SYSTEM_PATHS = [
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)"
    ]
else:  # Linux
    SYSTEM_PATHS = [
        "/proc",
        "/sys",
        "/dev"
    ]


def is_system_path(path):
    path = str(path).lower()
    for p in SYSTEM_PATHS:
        if path.startswith(p):
            return True
    return False


# kept for backwards compat — engine.py may call this name
def is_windows_path(path):
    return is_system_path(path)


def is_maltracer_path(path):
    path = str(path).lower()
    return (
        "maltracer\\quarantine" in path
        or "maltracer\\logs" in path
        or "maltracer\\reports" in path
    )


# =========================
# Executable check
# =========================

def is_executable(path):
    path = Path(path)
    if path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
        return False
    if is_system_path(path):
        return False
    if is_maltracer_path(path):
        return False
    return True


# =========================
# Paths to monitor
# =========================

home = Path.home()

if sys.platform == "win32":
    user_paths = [
        home / "Desktop",
        home / "Downloads",
        home / "AppData" / "Local" / "Temp",
        home / "AppData" / "Roaming",
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        home / "OneDrive" / "Desktop"
    ]
    system_paths = []
    if is_admin():
        system_paths = [
            Path("C:/ProgramData"),
            Path("C:/Windows/Temp")
        ]
else:  # Linux
    user_paths = [
        home / "Downloads",
        home / ".local" / "bin",
        Path("/tmp"),
        Path("/var/tmp"),
        Path("/dev/shm")
    ]
    system_paths = []
    if is_admin():
        system_paths = [
            Path("/usr/local/bin"),
            Path("/etc/cron.d"),
            Path("/etc/init.d")
        ]

paths = user_paths + system_paths
valid_paths = [p for p in paths if p.exists()]


# =========================
# Cleanup old delete events
# =========================

def cleanup_deletes():
    now = time.time()
    expired = [
        name for name, data in recent_deletes.items()
        if now - data["time"] > MOVE_TIME_WINDOW
    ]
    for name in expired:
        del recent_deletes[name]


# =========================
# Hash
# =========================

def get_file_hash(path):
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def get_cached_hash(path):
    path = str(path)
    if path in file_hash_cache:
        return file_hash_cache[path]
    h = get_file_hash(path)
    file_hash_cache[path] = h
    return h


# =========================
# File size
# =========================

def get_file_size(path):
    try:
        return Path(path).stat().st_size
    except Exception:
        return None


# =========================
# File Monitor
# =========================

class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self, callback=None):
        self.callback = callback

    def on_created(self, event):
        if event.is_directory:
            return
        if not is_executable(event.src_path):
            return

        cleanup_deletes()
        name = Path(event.src_path).name

        if name in recent_deletes:
            old = recent_deletes[name]
            file_hash = get_cached_hash(event.src_path)
            file_size = get_file_size(event.src_path)
            log = {
                "event_type": "executable_moved",
                "source": old["path"],
                "destination": event.src_path,
                "file_hash": file_hash,
                "file_size_kb": round(file_size / 1024, 2) if file_size else None,
                "timestamp": str(datetime.now())
            }
            if self.callback:
                self.callback(log)
            del recent_deletes[name]
            return

        file_hash = get_cached_hash(event.src_path)
        file_size = get_file_size(event.src_path)
        log = {
            "event_type": "executable_created",
            "source": "file_monitor",
            "file_path": event.src_path,
            "destination": event.src_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2) if file_size else None,
            "timestamp": str(datetime.now())
        }
        if self.callback:
            self.callback(log)

    def on_modified(self, event):
        if event.is_directory:
            return
        if not is_executable(event.src_path):
            return

        file_hash = get_cached_hash(event.src_path)
        file_size = get_file_size(event.src_path)
        log = {
            "event_type": "executable_modified",
            "source": "file_monitor",
            "file_path": event.src_path,
            "destination": event.src_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2) if file_size else None,
            "timestamp": str(datetime.now())
        }
        if self.callback:
            self.callback(log)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
            return

        log = {
            "event_type": "executable_deleted",
            "source": "file_monitor",
            "file_path": event.src_path,
            "destination": None,
            "file_hash": None,
            "file_size": None,
            "timestamp": str(datetime.now())
        }
        if self.callback:
            self.callback(log)

        recent_deletes[path.name] = {
            "path": event.src_path,
            "time": time.time()
        }

    def on_moved(self, event):
        if event.is_directory:
            return
        if not is_executable(event.dest_path):
            return

        file_hash = get_cached_hash(event.dest_path)
        file_size = get_file_size(event.dest_path)
        log = {
            "event_type": "executable_moved",
            "source": "file_monitor",
            "file_path": event.dest_path,
            "destination": event.dest_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2) if file_size else None,
            "timestamp": str(datetime.now())
        }
        if self.callback:
            self.callback(log)


# =========================
# Start monitoring
# =========================

def start_file_monitor(callback=None):
    observer = Observer()
    handler = FileMonitorHandler(callback=callback)

    for path in valid_paths:
        try:
            observer.schedule(handler, str(path), recursive=True)
            logger.info(f"[FileMonitor] Watching: {path}")
        except PermissionError:
            logger.warning(f"[FileMonitor] Permission denied, skipping: {path}")

    observer.start()
    logger.info("[FileMonitor] File monitoring started")
    return observer