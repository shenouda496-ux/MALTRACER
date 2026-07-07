"""
utils/resources.py
──────────────────
Resource-path helper that works both when running from source AND when running
from a PyInstaller bundle.

PyInstaller unpacks bundled data files (added via the .spec `datas` list) into a
temporary directory whose path it stores in ``sys._MEIPASS``.  When running from
source there is no ``_MEIPASS``; paths are resolved relative to the project root
(the parent of this ``utils`` package).

Usage:
    from utils.resources import resource_path
    rules = resource_path("detection_engine", "rules", "process.rules")
    client = resource_path("email_scanner", "credentials.json")
"""

import sys
from pathlib import Path


def base_dir() -> Path:
    """
    Return the base directory for bundled resources.

    * Frozen (PyInstaller): ``sys._MEIPASS`` (one-file) or the executable dir
      (one-dir — PyInstaller also sets ``_MEIPASS`` there, so this is safe).
    * Source: the project root (parent of the ``utils`` package).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    # utils/resources.py → parent is utils/, parent.parent is the project root
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    """
    Build an absolute path to a bundled resource.

    Accepts either a single relative string ("a/b/c") or multiple path segments
    ("a", "b", "c").  Always returns an absolute ``Path``.
    """
    return base_dir().joinpath(*parts)
