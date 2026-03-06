import ctypes
import time
import sys
import hashlib

from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from logging_system.logger import log_event



recent_deletes = {}
MOVE_TIME_WINDOW = 3
file_hash_cache = {}


# =========================
# Force Admin Mode
# =========================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():

    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        " ".join(sys.argv),
        None,
        1
    )

    sys.exit()


# =========================
# Executable extensions
# =========================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".msi"
}


# =========================
# Windows paths filter
# =========================

WINDOWS_PATHS = [
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)"
]


def is_windows_path(path):

    path = str(path).lower()

    for p in WINDOWS_PATHS:
        if path.startswith(p):
            return True

    return False


# =========================
# Executable check
# =========================

def is_executable(path):

    path = Path(path)

    if path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
        return False

    if is_windows_path(path):
        return False

    return True


# =========================
# Paths to monitor
# =========================

home = Path.home()

user_paths = [
    home / "Desktop",
    home / "Downloads",
    home / "AppData" / "Local" / "Temp",
    home / "AppData" / "Roaming",
    home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    home / "OneDrive" / "Desktop"
]

system_paths = [
    Path("C:/ProgramData"),
    Path("C:/Windows/Temp")
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

    except:
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
    except:
        return None


# =========================
# File Monitor
# =========================

class FileMonitorHandler(FileSystemEventHandler):

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
                "file_size_kb": round(file_size / 1024, 2),
                "timestamp": str(datetime.now())
            }

            log_event(log)

            del recent_deletes[name]

            return

        file_hash = get_cached_hash(event.src_path)
        file_size = get_file_size(event.src_path)

        log = {
            "event_type": "executable_created",
            "source": None,
            "destination": event.src_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2),
            "timestamp": str(datetime.now())
        }

        log_event(log)


    def on_modified(self, event):

        if event.is_directory:
            return

        if not is_executable(event.src_path):
            return

        file_hash = get_cached_hash(event.src_path)
        file_size = get_file_size(event.src_path)

        log = {
            "event_type": "executable_modified",
            "source": event.src_path,
            "destination": event.src_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2),
            "timestamp": str(datetime.now())
        }

        log_event(log)


    def on_deleted(self, event):

        if event.is_directory:
            return

        path = Path(event.src_path)

        if path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
            return

        log = {
            "event_type": "executable_deleted",
            "source": event.src_path,
            "destination": None,
            "file_hash": None,
            "file_size": None,
            "timestamp": str(datetime.now())
        }

        log_event(log)

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
            "source": event.src_path,
            "destination": event.dest_path,
            "file_hash": file_hash,
            "file_size_kb": round(file_size / 1024, 2),
            "timestamp": str(datetime.now())
        }

        log_event(log)


# =========================
# Start monitoring
# =========================

def start_file_monitor():

    observer = Observer()
    handler = FileMonitorHandler()

    for path in valid_paths:

        try:

            observer.schedule(
                handler,
                str(path),
                recursive=True
            )

            print("Monitoring:", path)

        except PermissionError:

            print("Permission denied:", path)

    observer.start()
    print("File monitoring started")

    return observer