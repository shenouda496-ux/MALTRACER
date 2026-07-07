"""
app/style.py
────────────
Dark theme for the MalTracer desktop GUI — a hex approximation of the Electron
popup's oklch palette, plus the global Qt stylesheet (QSS).
"""

# Palette (hex approximations of the original oklch tokens)
COLORS = {
    "bg":       "#14161f",
    "bg2":      "#181b26",
    "card":     "#1b1f2c",
    "card2":    "#20263a",
    "border":   "#2a3042",
    "fg":       "#f4f6fb",
    "muted":    "#9aa1bb",
    "primary":  "#4f7ef8",
    "glow":     "#5aa2ff",
    "danger":   "#f0524d",
    "warn":     "#e6a53a",
    "info":     "#4f9ef8",
    "ok":       "#2fbf78",
}

TONE_COLOR = {
    "danger": COLORS["danger"],
    "warn":   COLORS["warn"],
    "info":   COLORS["info"],
    "ok":     COLORS["ok"],
}

TONE_LABEL = {
    "danger": "Critical",
    "warn":   "Warning",
    "info":   "Info",
    "ok":     "Resolved",
}


def stylesheet() -> str:
    c = COLORS
    return f"""
    QWidget {{
        background: {c['bg']};
        color: {c['fg']};
        font-family: 'Segoe UI', -apple-system, sans-serif;
        font-size: 13px;
    }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QScrollBar:vertical {{ background: transparent; width: 8px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 4px; min-height: 24px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}

    #Header {{ background: {c['bg2']}; border-bottom: 1px solid {c['border']}; }}
    #BrandTitle {{ font-size: 16px; font-weight: 800; letter-spacing: 1px; }}
    #BrandSub {{ font-size: 10px; color: {c['muted']}; letter-spacing: 2px; }}

    #StatusPill {{
        background: rgba(47,191,120,0.16); color: {c['ok']};
        border-radius: 11px; padding: 4px 12px; font-weight: 700; font-size: 11px;
    }}

    #AdminBanner {{
        background: rgba(230,165,58,0.12); border: 1px solid rgba(230,165,58,0.5);
        border-radius: 10px;
    }}
    #AdminBannerText {{ color: {c['warn']}; font-size: 11px; }}

    QFrame#Card {{
        background: {c['card']}; border: 1px solid {c['border']}; border-radius: 12px;
    }}
    QFrame#ThreatBanner {{
        border: 1px solid {c['border']}; border-radius: 14px;
        background: {c['card2']};
    }}
    #ThreatLabel {{ font-size: 10px; letter-spacing: 2px; color: {c['muted']}; }}
    #ThreatValue {{ font-size: 26px; font-weight: 900; letter-spacing: 1px; }}
    #ThreatScan {{ font-size: 10px; color: {c['muted']}; }}

    #StatNum {{ font-size: 20px; font-weight: 800; }}
    #StatLbl {{ font-size: 10px; letter-spacing: 1px; color: {c['muted']}; }}

    #SectionLabel {{ font-size: 11px; letter-spacing: 2px; color: {c['muted']}; font-weight: 700; }}

    QFrame#AlertRow {{
        background: {c['card']}; border: 1px solid {c['border']}; border-radius: 11px;
    }}
    QFrame#AlertRow:hover {{ border: 1px solid {c['glow']}; }}
    #AlertTitle {{ font-size: 13px; font-weight: 600; }}
    #AlertMeta {{ font-size: 10px; color: {c['muted']}; }}

    #Dot {{ font-size: 15px; }}

    QPushButton {{
        background: {c['card']}; color: {c['fg']}; border: 1px solid {c['border']};
        border-radius: 9px; padding: 8px 14px; font-size: 12px; font-weight: 600;
    }}
    QPushButton:hover {{ border: 1px solid {c['glow']}; }}
    QPushButton#Primary {{
        background: {c['primary']}; border: none; color: white;
    }}
    QPushButton#Primary:hover {{ background: {c['glow']}; }}
    QPushButton#Danger {{ background: {c['danger']}; border: none; color: white; }}
    QPushButton#Warn {{ background: {c['warn']}; border: none; color: #1a1000; }}
    QPushButton:disabled {{ color: {c['muted']}; border-color: {c['border']}; }}

    QPushButton#NavBtn {{
        background: transparent; border: none; border-radius: 10px;
        color: {c['muted']}; padding: 8px; font-size: 11px; font-weight: 600;
    }}
    QPushButton#NavBtn:hover {{ color: {c['fg']}; }}
    QPushButton#NavBtn:checked {{ background: rgba(79,126,248,0.18); color: {c['glow']}; }}

    QPushButton#Chip {{
        background: {c['card']}; border: 1px solid {c['border']}; border-radius: 12px;
        color: {c['muted']}; padding: 4px 12px; font-size: 11px; font-weight: 600;
    }}
    QPushButton#Chip:checked {{ background: {c['primary']}; border-color: {c['primary']}; color: white; }}

    #NavBar {{ background: {c['bg2']}; border-top: 1px solid {c['border']}; }}

    QLineEdit {{
        background: {c['bg']}; border: 1px solid {c['border']}; border-radius: 8px;
        padding: 8px; color: {c['fg']};
    }}
    QLineEdit:focus {{ border: 1px solid {c['glow']}; }}

    #DropZone {{
        border: 2px dashed {c['border']}; border-radius: 12px; color: {c['muted']};
        background: {c['card']};
    }}

    QDialog {{ background: {c['bg2']}; }}
    """
