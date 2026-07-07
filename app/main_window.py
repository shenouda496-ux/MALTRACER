"""
app/main_window.py
──────────────────
The native MalTracer desktop GUI (PySide6) — a faithful replica of the old
Electron popup's three screens (Dashboard / Alerts / Scan Email), running
in-process and subscribing directly to the alert pipeline.  No HTTP bridge,
no Node.js.

Threading model
───────────────
The monitors, containment threads, and the email scanner all run OFF the Qt main
thread.  They call the MainWindow's *sink API* (on_alert / ask_contain /
notify_toast / set_monitor_status / set_email_status) from those threads.  Each
sink method simply emits a Qt Signal; the connected slot runs on the GUI thread
(Qt marshals queued signals across threads).  ask_contain additionally blocks its
caller on a threading.Event until the user answers the modal — preserving the
synchronous Contain/Dismiss contract the ContainmentEngine expects.
"""

import os
import sys
import threading
from datetime import datetime

from PySide6.QtCore import Qt, Signal, QTimer, QSize
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor, QBrush, QPolygon, QAction
from PySide6.QtCore import QPoint
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QStackedWidget, QScrollArea, QFrame, QButtonGroup,
    QDialog, QLineEdit, QFileDialog, QSystemTrayIcon, QMenu, QSizePolicy,
)

from app.style import COLORS, TONE_COLOR, TONE_LABEL, stylesheet
from alerts.popup_handler import MEDIUM_DECISION_TIMEOUT
from alerts import suppression
from logging_system.logger import get_logger

logger = get_logger(__name__)

TONE_GLYPH = {"danger": "●", "warn": "●", "info": "●", "ok": "✓"}


# ── App / tray icon (drawn at runtime — no binary asset needed) ───────────────

def make_app_icon(size: int = 64) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QBrush(QColor(COLORS["primary"])))
    p.setPen(Qt.NoPen)
    m = size * 0.14
    shield = QPolygon([
        QPoint(int(size / 2), int(m)),
        QPoint(int(size - m), int(size * 0.3)),
        QPoint(int(size - m), int(size * 0.58)),
        QPoint(int(size / 2), int(size - m)),
        QPoint(int(m), int(size * 0.58)),
        QPoint(int(m), int(size * 0.3)),
    ])
    p.drawPolygon(shield)
    # check mark
    pen = p.pen()
    p.setPen(QColor("white"))
    from PySide6.QtGui import QPen
    qp = QPen(QColor("white"))
    qp.setWidth(max(2, int(size * 0.07)))
    qp.setCapStyle(Qt.RoundCap)
    qp.setJoinStyle(Qt.RoundJoin)
    p.setPen(qp)
    p.drawPolyline(QPolygon([
        QPoint(int(size * 0.34), int(size * 0.5)),
        QPoint(int(size * 0.46), int(size * 0.62)),
        QPoint(int(size * 0.68), int(size * 0.38)),
    ]))
    p.end()
    return QIcon(pm)


# ── MEDIUM interactive Contain/Dismiss dialog (with countdown) ────────────────

class MediumDialog(QDialog):
    def __init__(self, event: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("MalTracer — Threat detected")
        self.setModal(True)
        self.setMinimumWidth(420)
        self._result = False
        self._remaining = MEDIUM_DECISION_TIMEOUT

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(10)

        title = QLabel(event.get("threat_title", "Suspicious activity detected"))
        title.setStyleSheet(f"font-size:15px;font-weight:800;color:{COLORS['warn']};")
        title.setWordWrap(True)
        lay.addWidget(title)

        meta = QLabel(
            f"Process: {event.get('threat_process','—')}\n"
            f"Path: {event.get('threat_path','—')}\n"
            f"Incident: {event.get('incident_id','—')}   Score: {event.get('threat_score',0)}/100"
        )
        meta.setStyleSheet(f"color:{COLORS['muted']};font-family:Consolas,monospace;font-size:11px;")
        meta.setWordWrap(True)
        lay.addWidget(meta)

        hint = QLabel("Contain will terminate the process, quarantine the file and block the IP.")
        hint.setStyleSheet(f"color:{COLORS['muted']};font-size:11px;")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self._count = QLabel()
        self._count.setStyleSheet(f"color:{COLORS['muted']};font-size:11px;")
        lay.addWidget(self._count)

        btns = QHBoxLayout()
        dismiss = QPushButton("Dismiss")
        dismiss.clicked.connect(self._on_dismiss)
        contain = QPushButton("Contain")
        contain.setObjectName("Warn")
        contain.clicked.connect(self._on_contain)
        btns.addWidget(dismiss)
        btns.addStretch(1)
        btns.addWidget(contain)
        lay.addLayout(btns)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._update_count()

    def _update_count(self):
        self._count.setText(f"Auto-dismiss in {self._remaining}s")

    def _tick(self):
        self._remaining -= 1
        if self._remaining <= 0:
            self._timer.stop()
            self.reject()
        else:
            self._update_count()

    def _on_contain(self):
        self._result = True
        self._timer.stop()
        self.accept()

    def _on_dismiss(self):
        self._result = False
        self._timer.stop()
        self.reject()

    def result_confirmed(self) -> bool:
        return self._result


# ── Alert detail dialog ───────────────────────────────────────────────────────

class DetailDialog(QDialog):
    def __init__(self, item: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Incident detail")
        self.setModal(True)
        self.setMinimumWidth(440)
        tone = "ok" if item.get("contained") else item.get("tone", "info")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(8)

        title = QLabel(item.get("title", "—"))
        title.setStyleSheet(f"font-size:15px;font-weight:800;color:{TONE_COLOR.get(tone)};")
        title.setWordWrap(True)
        lay.addWidget(title)

        badge = QLabel(TONE_LABEL.get(tone, "Info"))
        badge.setStyleSheet(f"color:{TONE_COLOR.get(tone)};font-weight:700;font-size:11px;")
        lay.addWidget(badge)

        for label, val in [
            ("Incident", item.get("id", "—")),
            ("Category", item.get("category", "—")),
            ("Process / Sender", item.get("process", "—")),
            ("Path / URLs", item.get("path", "—")),
            ("Score", f"{item.get('score', 0)}/100"),
            ("Action", item.get("action", "—")),
            ("State", "CONTAINED" if item.get("contained") else "OPEN"),
        ]:
            row = QLabel(f"<b>{label}:</b> {val}")
            row.setStyleSheet(f"color:{COLORS['fg']};font-size:12px;")
            row.setWordWrap(True)
            lay.addWidget(row)

        reasons = item.get("reasons") or []
        if reasons:
            rl = QLabel("<b>Detection reasons:</b>")
            rl.setStyleSheet("font-size:12px;")
            lay.addWidget(rl)
            for r in reasons[:12]:
                x = QLabel(f"• {r}")
                x.setStyleSheet(f"color:{COLORS['muted']};font-size:11px;")
                x.setWordWrap(True)
                lay.addWidget(x)

        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        lay.addWidget(close, alignment=Qt.AlignRight)


# ── Small widget helpers ──────────────────────────────────────────────────────

def _card() -> QFrame:
    f = QFrame()
    f.setObjectName("Card")
    return f


def _label(text: str, obj: str = "", extra: str = "") -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    if extra:
        lb.setStyleSheet(extra)
    return lb


# ── Main window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    # Cross-thread signals → slots run on the GUI thread.
    sig_alert          = Signal(dict)
    sig_toast          = Signal(str, str, str)
    sig_monitor_status = Signal(str, str)
    sig_email_status   = Signal(str)
    sig_medium         = Signal(object)   # holder dict

    def __init__(self, admin: bool = False, reduced: list[str] | None = None):
        super().__init__()
        self.setWindowTitle("MalTracer — Endpoint Detection & Response")
        self.setWindowIcon(make_app_icon())
        self.resize(760, 620)

        self._admin = admin
        self._reduced = reduced or []
        self._alerts: list[dict] = []
        self._index: dict[str, dict] = {}
        self._key_index: dict[str, dict] = {}   # dedup recurring threats by identity
        self._filter = "all"
        self._quarantined = 0
        self._really_quit = False

        # Hooks wired by run_app (so the window stays decoupled from services).
        self.on_connect_email = None      # callable()
        self.on_disconnect_email = None   # callable()
        self.on_restart_admin = None      # callable()

        self.setStyleSheet(stylesheet())
        self._build_ui()
        self._build_tray()

        # Connect signals to slots (queued across threads automatically).
        self.sig_alert.connect(self._on_alert_slot)
        self.sig_toast.connect(self._on_toast_slot)
        self.sig_monitor_status.connect(self._on_monitor_status_slot)
        self.sig_email_status.connect(self._on_email_status_slot)
        self.sig_medium.connect(self._on_medium_slot)

        # Live system stats (processes / files watched / quarantined).
        self._files_watched = 0
        threading.Thread(target=self._count_watched_files, name="FileCount",
                         daemon=True).start()
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._update_live_stats)
        self._stats_timer.start(4000)
        self._update_live_stats()

    # ══ UI construction ═══════════════════════════════════════════════════════

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        self._admin_banner = self._build_admin_banner()
        root.addWidget(self._admin_banner)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_dashboard())   # 0
        self.stack.addWidget(self._build_alerts())       # 1
        self.stack.addWidget(self._build_scan_email())    # 2
        root.addWidget(self.stack, 1)

        root.addWidget(self._build_nav())
        self._refresh_all()

    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Header")
        w.setFixedHeight(56)
        h = QHBoxLayout(w)
        h.setContentsMargins(16, 8, 16, 8)
        brand = QVBoxLayout()
        brand.setSpacing(0)
        brand.addWidget(_label("MalTracer", "BrandTitle"))
        brand.addWidget(_label("ENDPOINT DETECTION & RESPONSE", "BrandSub"))
        h.addLayout(brand)
        h.addStretch(1)
        self._status_pill = QLabel("Active")
        self._status_pill.setObjectName("StatusPill")
        h.addWidget(self._status_pill)
        return w

    def _build_admin_banner(self) -> QWidget:
        w = QFrame()
        w.setObjectName("AdminBanner")
        h = QHBoxLayout(w)
        h.setContentsMargins(12, 8, 12, 8)
        txt = ("Running without administrator rights — reduced protection: "
               + "; ".join(self._reduced))
        lbl = _label(txt, "AdminBannerText")
        lbl.setWordWrap(True)
        h.addWidget(lbl, 1)
        btn = QPushButton("Restart as Administrator")
        btn.setObjectName("Warn")
        btn.clicked.connect(self._restart_admin)
        h.addWidget(btn)
        w.setVisible(not self._admin)
        return w

    def _build_dashboard(self) -> QWidget:
        page = QScrollArea()
        page.setWidgetResizable(True)
        page.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        page.setWidget(inner)
        v = QVBoxLayout(inner)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(12)

        # Threat banner
        tb = QFrame()
        tb.setObjectName("ThreatBanner")
        tbl = QVBoxLayout(tb)
        tbl.setContentsMargins(16, 12, 16, 12)
        tbl.addWidget(_label("THREAT LEVEL", "ThreatLabel"))
        self._threat_value = _label("LOW", "ThreatValue")
        self._threat_value.setStyleSheet(f"color:{COLORS['ok']};")
        tbl.addWidget(self._threat_value)
        self._threat_scan = _label("Monitoring active", "ThreatScan")
        tbl.addWidget(self._threat_scan)
        v.addWidget(tb)

        # Stats grid
        grid = QGridLayout()
        grid.setSpacing(8)
        self._stat_labels = {}
        stats = [("files", "Files watched", "—"), ("procs", "Processes", "—"),
                 ("quar", "Quarantined", "0"), ("inc", "Open incidents", "0")]
        for i, (key, lbl, val) in enumerate(stats):
            card = _card()
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 10, 12, 10)
            num = _label(val, "StatNum")
            self._stat_labels[key] = num
            cl.addWidget(num)
            cl.addWidget(_label(lbl.upper(), "StatLbl"))
            grid.addWidget(card, i // 2, i % 2)
        v.addLayout(grid)

        # Monitor status panel
        v.addWidget(_label("SYSTEM STATUS", "SectionLabel"))
        status_card = _card()
        sc = QVBoxLayout(status_card)
        sc.setContentsMargins(12, 10, 12, 10)
        sc.setSpacing(6)
        self._monitor_rows = {}
        for name in ["Process", "File", "Network", "Email", "Privileges"]:
            row = QHBoxLayout()
            dot = _label("●", "Dot", f"color:{COLORS['muted']};")
            txt = _label(name, "", f"font-size:12px;")
            state = _label("starting…", "", f"color:{COLORS['muted']};font-size:11px;")
            row.addWidget(dot)
            row.addWidget(txt)
            row.addStretch(1)
            row.addWidget(state)
            sc.addLayout(row)
            self._monitor_rows[name] = (dot, state)
        v.addWidget(status_card)

        # Email connect
        self._email_btn = QPushButton("Connect Gmail account")
        self._email_btn.setObjectName("Primary")
        self._email_btn.clicked.connect(self._email_button_clicked)
        v.addWidget(self._email_btn)
        self._email_connected = False

        # Recent alerts
        v.addWidget(_label("RECENT ALERTS", "SectionLabel"))
        self._recent_box = QVBoxLayout()
        self._recent_box.setSpacing(6)
        rc = QWidget()
        rc.setLayout(self._recent_box)
        v.addWidget(rc)
        v.addStretch(1)
        return page

    def _build_alerts(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(16, 14, 16, 8)
        v.setSpacing(10)
        v.addWidget(_label("ALL ALERTS", "SectionLabel"))

        chips = QHBoxLayout()
        chips.setSpacing(6)
        self._chip_group = QButtonGroup(self)
        self._chip_group.setExclusive(True)
        self._chips = {}
        for key, lbl in [("all", "All"), ("danger", "Critical"), ("warn", "Warning"),
                         ("info", "Info"), ("ok", "Resolved")]:
            b = QPushButton(lbl)
            b.setObjectName("Chip")
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self._set_filter(k))
            if key == "all":
                b.setChecked(True)
            self._chip_group.addButton(b)
            self._chips[key] = b
            chips.addWidget(b)
        chips.addStretch(1)
        v.addLayout(chips)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        holder = QWidget()
        self._alerts_box = QVBoxLayout(holder)
        self._alerts_box.setContentsMargins(0, 0, 6, 0)
        self._alerts_box.setSpacing(6)
        self._alerts_box.addStretch(1)
        scroll.setWidget(holder)
        v.addWidget(scroll, 1)
        return page

    def _build_scan_email(self) -> QWidget:
        page = QWidget()
        page.setAcceptDrops(True)
        page.dragEnterEvent = self._drag_enter
        page.dropEvent = self._drop_event
        v = QVBoxLayout(page)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(12)
        v.addWidget(_label("SCAN EMAIL (.eml)", "SectionLabel"))

        self._drop_label = QLabel("Drop a .eml file here, or click Browse")
        self._drop_label.setObjectName("DropZone")
        self._drop_label.setAlignment(Qt.AlignCenter)
        self._drop_label.setMinimumHeight(120)
        v.addWidget(self._drop_label)

        browse = QPushButton("Browse for .eml file")
        browse.setObjectName("Primary")
        browse.clicked.connect(self._browse_eml)
        v.addWidget(browse)

        self._eml_result = QVBoxLayout()
        rc = QWidget()
        rc.setLayout(self._eml_result)
        v.addWidget(rc)
        v.addStretch(1)
        return page

    def _build_nav(self) -> QWidget:
        w = QWidget()
        w.setObjectName("NavBar")
        w.setFixedHeight(52)
        h = QHBoxLayout(w)
        h.setContentsMargins(8, 6, 8, 6)
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        for i, name in enumerate(["Dashboard", "Alerts", "Scan Email"]):
            b = QPushButton(name)
            b.setObjectName("NavBtn")
            b.setCheckable(True)
            if i == 0:
                b.setChecked(True)
            b.clicked.connect(lambda _=False, idx=i: self.stack.setCurrentIndex(idx))
            self._nav_group.addButton(b)
            h.addWidget(b)
        return w

    def _build_tray(self):
        self.tray = QSystemTrayIcon(make_app_icon(), self)
        self.tray.setToolTip("MalTracer — monitoring")
        menu = QMenu()
        act_open = QAction("Open MalTracer", self)
        act_open.triggered.connect(self._show_from_tray)
        act_quit = QAction("Quit", self)
        act_quit.triggered.connect(self._quit)
        menu.addAction(act_open)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        try:
            self.tray.show()
        except Exception:
            pass

    # ══ Sink API (called from ANY thread) ═════════════════════════════════════

    def on_alert(self, event: dict):
        self.sig_alert.emit(dict(event))

    def notify_toast(self, title: str, message: str, level: str = "INFO"):
        self.sig_toast.emit(title, message, level)

    def set_monitor_status(self, name: str, status: str):
        self.sig_monitor_status.emit(name, status)

    def set_email_status(self, text: str):
        self.sig_email_status.emit(text)

    def ask_contain(self, event: dict) -> bool:
        """Blocks the calling (worker) thread until the user answers the modal.

        If the user previously dismissed this same threat, skip the modal and
        auto-dismiss — the alert will not prompt again.
        """
        if suppression.is_dismissed(event):
            logger.info(f"[GUI] Auto-dismiss (previously dismissed): "
                        f"{suppression.threat_key(event)}")
            return False

        holder = {"event": dict(event), "done": threading.Event(), "result": False}
        self.sig_medium.emit(holder)
        if not holder["done"].wait(timeout=MEDIUM_DECISION_TIMEOUT + 5):
            confirmed = False
        else:
            confirmed = bool(holder["result"])

        if not confirmed:
            # Remember this dismissal so the same threat never prompts again.
            suppression.mark_dismissed(event)
        return confirmed

    # ══ Slots (GUI thread) ════════════════════════════════════════════════════

    def _on_alert_slot(self, event: dict):
        item = self._to_item(event)
        # Dedup recurring threats by stable identity so a repeated (e.g. dismissed)
        # threat updates its existing row instead of piling up new ones.
        existing = self._key_index.get(item["key"]) or self._index.get(item["id"])
        if existing is not None:
            existing.update(item)
        else:
            self._key_index[item["key"]] = item
            self._index[item["id"]] = item
            self._alerts.insert(0, item)
        self._refresh_all()

    def _on_toast_slot(self, title: str, message: str, level: str):
        icon = (QSystemTrayIcon.Critical if level == "HIGH"
                else QSystemTrayIcon.Warning if level == "MEDIUM"
                else QSystemTrayIcon.Information)
        try:
            self.tray.showMessage(title, message, icon, 6000)
        except Exception:
            pass

    def _on_monitor_status_slot(self, name: str, status: str):
        if name not in self._monitor_rows:
            return
        dot, state = self._monitor_rows[name]
        state.setText(status)
        color = COLORS["ok"]
        low = status.lower()
        if any(k in low for k in ("not ", "error", "stopped", "reduced", "off")):
            color = COLORS["warn"]
        if "fail" in low or "crash" in low:
            color = COLORS["danger"]
        dot.setStyleSheet(f"color:{color};")

    def _on_email_status_slot(self, text: str):
        self._email_connected = "connected" in text.lower() and "not connected" not in text.lower()
        self.set_monitor_status("Email", text.replace("Email scanning: ", ""))
        self._email_btn.setText("Disconnect Gmail account" if self._email_connected
                                else "Connect Gmail account")

    def _on_medium_slot(self, holder: dict):
        dlg = MediumDialog(holder["event"], self)
        self._surface()
        dlg.exec()
        holder["result"] = dlg.result_confirmed()
        holder["done"].set()

    # ══ Rendering ═════════════════════════════════════════════════════════════

    def _to_item(self, ev: dict) -> dict:
        tone = ev.get("threat_tone") or {
            "HIGH": "danger", "MEDIUM": "warn", "LOW": "info"
        }.get(str(ev.get("threat_level", "LOW")).upper(), "info")
        action = str(ev.get("threat_action", ""))
        contained = bool(ev.get("contained")) or "CONTAIN" in action.upper()
        return {
            "id": ev.get("incident_id", "INC-LIVE"),
            "key": suppression.threat_key(ev),
            "tone": tone,
            "title": ev.get("threat_title", "Threat detected"),
            "process": ev.get("threat_process", "unknown"),
            "category": ev.get("threat_category", "Unknown"),
            "path": ev.get("threat_path", "—"),
            "score": ev.get("threat_score", ev.get("risk_score", 0)),
            "action": action or f"Score {ev.get('threat_score', 0)}",
            "reasons": ev.get("reasons", []),
            "contained": contained,
            "dismissed": suppression.is_dismissed(ev) and not contained,
            "ts": datetime.now().strftime("%H:%M:%S"),
        }

    def _alert_row(self, item: dict) -> QWidget:
        dismissed = item.get("dismissed") and not item.get("contained")
        tone = "ok" if item.get("contained") else item["tone"]
        row = QFrame()
        row.setObjectName("AlertRow")
        h = QHBoxLayout(row)
        h.setContentsMargins(10, 8, 10, 8)
        dot_color = COLORS["muted"] if dismissed else TONE_COLOR.get(tone)
        dot = _label(TONE_GLYPH.get(tone, "●"), "Dot", f"color:{dot_color};")
        h.addWidget(dot)
        body = QVBoxLayout()
        body.setSpacing(1)
        body.addWidget(_label(item["title"], "AlertTitle"))
        body.addWidget(_label(f"{item['process']} · {item['ts']} · {item['id']}", "AlertMeta"))
        h.addLayout(body, 1)
        if item.get("contained"):
            tag = _label("✓ Contained", "", f"color:{COLORS['ok']};font-size:11px;font-weight:700;")
            h.addWidget(tag)
        elif dismissed:
            # Dismissed threats won't prompt again; user can still re-contain.
            tag = _label("Dismissed", "", f"color:{COLORS['muted']};font-size:11px;font-weight:600;")
            h.addWidget(tag)
            btn = QPushButton("Contain")
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda _=False, it=item: self._manual_contain(it))
            h.addWidget(btn)
        elif item["tone"] == "warn":
            btn = QPushButton("Contain")
            btn.setObjectName("Warn")
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda _=False, it=item: self._manual_contain(it))
            h.addWidget(btn)
        view = QPushButton("View")
        view.setFixedHeight(26)
        view.clicked.connect(lambda _=False, it=item: DetailDialog(it, self).exec())
        h.addWidget(view)
        return row

    def _refresh_all(self):
        self._refresh_dashboard()
        self._refresh_alerts()

    def _refresh_dashboard(self):
        # "Active" excludes both contained AND dismissed threats.
        active = [a for a in self._alerts if not a.get("contained") and not a.get("dismissed")]
        open_inc = len([a for a in active if a["tone"] in ("danger", "warn")])
        self._stat_labels["inc"].setText(str(open_inc))
        # Processes / Files / Quarantined are live system stats (updated on a timer).

        has_danger = any(a["tone"] == "danger" for a in active)
        has_warn = any(a["tone"] == "warn" for a in active)
        if has_danger:
            self._threat_value.setText("CRITICAL")
            self._threat_value.setStyleSheet(f"color:{COLORS['danger']};")
        elif has_warn:
            self._threat_value.setText("ELEVATED")
            self._threat_value.setStyleSheet(f"color:{COLORS['warn']};")
        else:
            self._threat_value.setText("LOW")
            self._threat_value.setStyleSheet(f"color:{COLORS['ok']};")
        if self._alerts:
            self._threat_scan.setText(f"Last event {self._alerts[0]['ts']}")

        _clear_layout(self._recent_box)
        for item in self._alerts[:4]:
            self._recent_box.addWidget(self._alert_row(item))
        if not self._alerts:
            self._recent_box.addWidget(_label("No alerts yet — monitoring…", "",
                                               f"color:{COLORS['muted']};font-size:11px;"))

    def _refresh_alerts(self):
        # An alert is "handled" if it was contained or dismissed → it drops out
        # of its tone bucket and shows under Resolved instead.
        def handled(a):
            return a.get("contained") or a.get("dismissed")

        counts = {
            "all": len(self._alerts),
            "danger": len([a for a in self._alerts if a["tone"] == "danger" and not handled(a)]),
            "warn": len([a for a in self._alerts if a["tone"] == "warn" and not handled(a)]),
            "info": len([a for a in self._alerts if a["tone"] == "info" and not handled(a)]),
            "ok": len([a for a in self._alerts if handled(a)]),
        }
        for key, chip in self._chips.items():
            base = {"all": "All", "danger": "Critical", "warn": "Warning",
                    "info": "Info", "ok": "Resolved"}[key]
            chip.setText(f"{base} ({counts[key]})")

        if self._filter == "all":
            visible = self._alerts
        elif self._filter == "ok":
            visible = [a for a in self._alerts if handled(a)]
        else:
            visible = [a for a in self._alerts if a["tone"] == self._filter and not handled(a)]

        _clear_layout(self._alerts_box, keep_stretch=True)
        for item in visible:
            self._alerts_box.insertWidget(self._alerts_box.count() - 1, self._alert_row(item))

    def _set_filter(self, key: str):
        self._filter = key
        self._refresh_alerts()

    # ══ Live system stats ═════════════════════════════════════════════════════

    def _update_live_stats(self):
        """Refresh Processes / Files watched / Quarantined with real numbers.
        Runs on the GUI thread via a QTimer; all lookups here are cheap."""
        # Running processes (live).
        try:
            import psutil
            self._stat_labels["procs"].setText(f"{len(psutil.pids()):,}")
        except Exception:
            self._stat_labels["procs"].setText("—")

        # Files under watch (computed in the background; shown once ready).
        self._stat_labels["files"].setText(
            f"{self._files_watched:,}" if self._files_watched else "…"
        )

        # Quarantined files actually on disk.
        self._stat_labels["quar"].setText(str(self._count_quarantined()))

    def _count_watched_files(self):
        """Count files inside the monitored folders (background thread, capped)."""
        try:
            from monitoring.file_monitor import valid_paths
        except Exception:
            return
        total, CAP = 0, 300_000
        for base in valid_paths:
            try:
                for _root, _dirs, files in os.walk(base):
                    total += len(files)
                    if total >= CAP:
                        break
            except Exception:
                continue
            if total >= CAP:
                break
        self._files_watched = total   # picked up by the next timer tick

    @staticmethod
    def _count_quarantined() -> int:
        try:
            from utils.constants import QUARANTINE_DIR
            n = 0
            for inc in QUARANTINE_DIR.glob("*"):
                if inc.is_dir():
                    n += sum(1 for f in inc.iterdir()
                             if f.is_file() and f.name != "manifest.json")
            return n
        except Exception:
            return 0

    # ══ Actions ═══════════════════════════════════════════════════════════════

    def _manual_contain(self, item: dict):
        """User clicked Contain on a MEDIUM (or previously dismissed) row."""
        it = self._index.get(item["id"], item)
        dlg = MediumDialog(it, self)
        dlg.exec()
        if dlg.result_confirmed():
            it["contained"] = True
            it["dismissed"] = False
            it["action"] = "Contained by analyst"
            # Re-containing overrides an earlier dismissal.
            suppression.discard_key(it.get("key", ""))
            self._refresh_all()

    def _email_button_clicked(self):
        if self._email_connected:
            if callable(self.on_disconnect_email):
                self.on_disconnect_email()
        else:
            if callable(self.on_connect_email):
                self._email_btn.setEnabled(False)
                self._email_btn.setText("Connecting… (browser will open)")
                self.on_connect_email()
                # Re-enable shortly; status updates via set_email_status.
                QTimer.singleShot(4000, lambda: self._email_btn.setEnabled(True))

    def _restart_admin(self):
        if callable(self.on_restart_admin):
            self.on_restart_admin()

    # ── .eml scanning (real local analysis) ──────────────────────────────────

    def _browse_eml(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose an .eml file", "", "Email files (*.eml);;All files (*.*)"
        )
        if path:
            self._scan_eml(path)

    def _drag_enter(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()

    def _drop_event(self, ev):
        for url in ev.mimeData().urls():
            p = url.toLocalFile()
            if p.lower().endswith(".eml"):
                self._scan_eml(p)
                break

    def _scan_eml(self, path: str):
        _clear_layout(self._eml_result)
        try:
            headers, body = _parse_eml(path)
            from email_scanner.analyzer import analyze
            res = analyze(headers, body)
        except Exception as exc:
            self._eml_result.addWidget(_label(f"Could not scan: {exc}", "",
                                               f"color:{COLORS['danger']};"))
            return

        score = res["risk_score"]
        verdict = res["classification"]
        color = (COLORS["danger"] if score >= 70 else
                 COLORS["warn"] if score >= 40 else COLORS["ok"])
        self._drop_label.setText(os.path.basename(path))
        self._eml_result.addWidget(_label(
            f"Verdict: {verdict}  ·  {score}/100", "",
            f"color:{color};font-size:15px;font-weight:800;"))
        auth = res.get("headers", {})
        self._eml_result.addWidget(_label(
            f"SPF: {auth.get('spf','?')}   DKIM: {auth.get('dkim','?')}   DMARC: {auth.get('dmarc','?')}",
            "", f"color:{COLORS['muted']};font-size:11px;"))
        reasons = res.get("reasons") or []
        if reasons:
            self._eml_result.addWidget(_label("Reasons:", "", "font-weight:700;font-size:12px;"))
            for r in reasons[:12]:
                self._eml_result.addWidget(_label(f"• {r}", "",
                                                   f"color:{COLORS['muted']};font-size:11px;"))
        else:
            self._eml_result.addWidget(_label("No suspicious indicators found.", "",
                                              f"color:{COLORS['ok']};font-size:12px;"))

    # ══ Tray / window lifecycle ═══════════════════════════════════════════════

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self._show_from_tray()

    def _show_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _surface(self):
        if not self.isVisible():
            self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, ev):
        if self._really_quit:
            ev.accept()
            return
        # Minimize to tray instead of quitting — monitoring keeps running.
        ev.ignore()
        self.hide()
        try:
            self.tray.showMessage(
                "MalTracer still running",
                "Monitoring continues in the background. Right-click the tray icon to quit.",
                QSystemTrayIcon.Information, 4000)
        except Exception:
            pass

    def _quit(self):
        self._really_quit = True
        QApplication.instance().quit()


# ── module helpers ────────────────────────────────────────────────────────────

def _clear_layout(layout, keep_stretch: bool = False):
    while layout.count():
        if keep_stretch and layout.count() == 1:
            break
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.deleteLater()


def _parse_eml(path: str):
    """Parse an .eml file into a headers dict + best-effort text body."""
    import email
    from email import policy
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)
    headers = {k: str(v) for k, v in msg.items()}
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    body += part.get_content()
        else:
            body = msg.get_content()
    except Exception:
        body = msg.get_payload(decode=False) or ""
    return headers, body
