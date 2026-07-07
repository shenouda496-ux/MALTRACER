"""
quarantine_manager.py
─────────────────────
Moves suspicious files to a locked quarantine directory.

Cross-platform paths:
  Windows : APPDATA/MalTracer/quarantine/
  Linux   : ~/.maltracer/quarantine/

Security properties:
  - Files are set to read-only after quarantine (no execute)
  - A manifest records every item with its SHA-256 hash
  - restore() moves the file back for false positives
"""

import os
import sys
import time
import shutil
import hashlib
import json
import stat
import logging
from datetime import datetime, timezone
from pathlib import Path

from logging_system.logger import get_logger

logger = get_logger(__name__)

# ── Cross-platform quarantine path ───────────────────────────────────────────
if sys.platform == "win32":
    _BASE_DIR      = Path(os.environ.get("APPDATA", Path.home())) / "MalTracer"
else:
    _BASE_DIR      = Path.home() / ".maltracer"

_QUARANTINE_DIR = _BASE_DIR / "quarantine"
_MANIFEST_FILE  = _QUARANTINE_DIR / "manifest.json"


class QuarantineManager:

    def __init__(self):
        self._ensure_quarantine_dir()
        self._manifest: list = self._load_manifest()

    # ──────────────────────────────────────────────────────────────────────────
    # Public methods
    # ──────────────────────────────────────────────────────────────────────────

    def quarantine(self, file_path: str, incident_id: str) -> tuple:
        """
        Move the file to quarantine and lock it down.

        Returns:
            (success: bool, destination_path: str, detail: str)
        """
        src = Path(file_path).resolve()

        if not src.exists():
            return False, "", f"File not found: {src}"
        if not src.is_file():
            return False, "", f"Not a regular file: {src}"

        # ── FIX: use relative_to() instead of startswith() ──────────────────
        # startswith() fails on Windows when the path contains short names
        # (e.g. "MEGAST~1" vs "Mega Store"). resolve() normalises both sides.
        try:
            src.relative_to(_QUARANTINE_DIR.resolve())
            return False, "", "File is already in quarantine"
        except ValueError:
            pass
        # ─────────────────────────────────────────────────────────────────────

        # Hash before moving (forensic + VirusTotal lookup later)
        file_hash = self._sha256(src)

        # Destination: quarantine/<incident_id>/<filename>
        dest_dir = _QUARANTINE_DIR / incident_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name

        # Handle name collision
        if dest.exists():
            dest = dest_dir / f"{file_hash[:8]}_{src.name}"

        # Move the file (retrying — on Windows an AV scanner or the search
        # indexer can hold a transient lock on a freshly written executable).
        moved, err = self._move_with_retry(src, dest)
        if not moved:
            return False, "", f"Move failed: {err}"

        # Lock: read-only, no execute
        self._make_readonly(dest)

        # Record in manifest
        record = {
            "incident_id":      incident_id,
            "original_path":    str(src),
            "quarantine_path":  str(dest),
            "sha256":           file_hash,
            "quarantined_at":   datetime.now(timezone.utc).isoformat(),
            "restored":         False,
        }
        self._manifest.append(record)
        self._save_manifest()

        logger.warning(
            f"[QUARANTINE] File quarantined. "
            f"incident={incident_id} src={src} dest={dest} hash={file_hash[:16]}..."
        )
        return True, str(dest), f"Quarantined to {dest}"

    def restore(self, incident_id: str, filename: str) -> tuple:
        """
        Restore a quarantined file to its original location.
        Use for false positive cleanup — requires manual admin action.

        Returns:
            (success: bool, detail: str)
        """
        record = next(
            (r for r in self._manifest
             if r["incident_id"] == incident_id
             and Path(r["quarantine_path"]).name == filename
             and not r["restored"]),
            None
        )
        if not record:
            return False, f"No quarantine record found for {incident_id}/{filename}"

        src  = Path(record["quarantine_path"])
        dest = Path(record["original_path"])

        if not src.exists():
            return False, f"Quarantined file no longer exists: {src}"

        # Temporarily restore write permission to allow the move
        try:
            os.chmod(src, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

        dest.parent.mkdir(parents=True, exist_ok=True)
        moved, err = self._move_with_retry(src, dest)
        if not moved:
            return False, f"Restore failed: {err}"

        record["restored"]    = True
        record["restored_at"] = datetime.now(timezone.utc).isoformat()
        self._save_manifest()

        logger.info(f"[QUARANTINE] File restored. incident={incident_id} dest={dest}")
        return True, f"Restored to {dest}"

    def list_quarantined(self, incident_id: str = None) -> list:
        """Return quarantine records, optionally filtered by incident_id."""
        if incident_id:
            return [r for r in self._manifest if r["incident_id"] == incident_id]
        return list(self._manifest)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _ensure_quarantine_dir(self) -> None:
        _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        # Best-effort: lock the quarantine dir itself
        try:
            if sys.platform != "win32":
                os.chmod(_QUARANTINE_DIR, stat.S_IRWXU)  # 700 on Linux
        except Exception as e:
            logger.warning(f"[QUARANTINE] Could not set dir permissions: {e}")

    @staticmethod
    def _move_with_retry(src: Path, dest: Path, attempts: int = 5, delay: float = 0.15):
        """Move a file, retrying a few times on transient Windows lock errors
        (AV scanning / search indexer holding a freshly written executable)."""
        last = ""
        for _ in range(attempts):
            try:
                shutil.move(str(src), str(dest))
                return True, ""
            except (PermissionError, OSError) as e:
                last = str(e)
                time.sleep(delay)
        return False, last

    def _make_readonly(self, path: Path) -> None:
        """Remove write and execute permissions from the quarantined file."""
        try:
            if sys.platform == "win32":
                # Windows: set read-only attribute
                os.chmod(path, stat.S_IREAD)
            else:
                # Linux/macOS: 400 = read-only by owner only
                os.chmod(path, stat.S_IRUSR)
        except Exception as e:
            logger.warning(f"[QUARANTINE] Could not set file permissions: {e}")

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except Exception as e:
            logger.error(f"[QUARANTINE] Hash failed for {path}: {e}")
            return "HASH_ERROR"
        return h.hexdigest()

    def _load_manifest(self) -> list:
        try:
            if _MANIFEST_FILE.exists():
                return json.loads(_MANIFEST_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    def _save_manifest(self) -> None:
        try:
            _MANIFEST_FILE.write_text(
                json.dumps(self._manifest, indent=2), encoding="utf-8"
            )
            if sys.platform != "win32":
                os.chmod(_MANIFEST_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600
        except Exception as e:
            logger.error(f"[QUARANTINE] Failed to save manifest: {e}")