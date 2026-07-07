# -*- mode: python ; coding: utf-8 -*-
"""
MalTracer.spec — PyInstaller build recipe (one-dir).

Produces  dist/MalTracer/MalTracer.exe  plus a folder of dependencies.  One-dir
is chosen over one-file for faster startup and more reliable Qt plugin loading.

Build:   pyinstaller MalTracer.spec --noconfirm
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files, copy_metadata

# ── Bundled data files (resolved at runtime via utils.resources.resource_path) ──
datas = [
    ("detection_engine/rules/network.rules", "detection_engine/rules"),
    ("detection_engine/rules/process.rules", "detection_engine/rules"),
    ("detection_engine/rules/file.rules",    "detection_engine/rules"),
    ("logs/2026-03-13_edr_logs.json",        "logs"),
    # Bundled developer OAuth "desktop app" client (NOT a true secret — see CHANGES.md).
    ("email_scanner/credentials.json",       "email_scanner"),
]

# Gmail API discovery cache + package metadata some libs look up at runtime.
datas += collect_data_files("googleapiclient")
datas += copy_metadata("google-api-python-client")
# keyring discovers its backends via entry-point metadata — bundle it so the
# Windows Credential Manager backend is found inside the frozen app.
datas += copy_metadata("keyring")

hiddenimports = [
    "psutil",
    "bs4",
    "watchdog.observers",
    "watchdog.observers.polling",
    # keyring backends (selected at runtime by platform)
    "keyring.backends.Windows",
    "keyring.backends.macOS",
    "keyring.backends.SecretService",
    "keyring.backends.chainer",
    "keyring.backends.fail",
    # google stack
    "google.auth",
    "google.oauth2",
    "google_auth_oauthlib",
    "googleapiclient",
    "googleapiclient.discovery",
]
hiddenimports += collect_submodules("keyring.backends")
hiddenimports += collect_submodules("google")

block_cipher = None

a = Analysis(
    ["maltracer.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Trim large unused stdlib/test bits to keep the folder smaller.
    excludes=["tkinter", "pytest", "PySide6.QtQuick3D", "PySide6.Qt3D"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MalTracer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # windowed app — no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon="app/assets/maltracer.ico",   # optional — supply a .ico to brand the exe
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MalTracer",
)
