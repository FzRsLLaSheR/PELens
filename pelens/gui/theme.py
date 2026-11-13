"""Light/dark themes and shared GUI colors."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

FONT_DIR = Path(__file__).parent / "fonts"
UI_FONT = "Inter"
MONO_FONT = "JetBrains Mono"
UI_SIZE = 9.5
_fonts_loaded: set[str] | None = None


def load_fonts() -> set[str]:
    """Loads the bundled fonts (Inter for the interface, JetBrains Mono for code and hex); returns the families."""
    global _fonts_loaded
    if _fonts_loaded is None:
        _fonts_loaded = set()
        for f in sorted(FONT_DIR.glob("*.ttf")):
            fid = QFontDatabase.addApplicationFont(str(f))
            if fid >= 0:
                _fonts_loaded.update(QFontDatabase.applicationFontFamilies(fid))
    return _fonts_loaded


def ui_font() -> QFont:
    f = QFont(UI_FONT) if UI_FONT in load_fonts() else QFont()
    f.setPointSizeF(UI_SIZE)
    return f

SEVERITY = {"high": "#e5534b", "medium": "#d29922", "low": "#539bf5"}
SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
CONFIDENCE = {"high": "#e5534b", "medium": "#d29922", "low": "#8b949e"}
GOOD = "#3fb950"
ACCENT = "#539bf5"
STACK = "#39c5cf"


def score_color(score: int) -> str:
    if score >= 60:
        return SEVERITY["high"]
    if score >= 30:
        return SEVERITY["medium"]
    if score >= 10:
        return "#c9b52b"
    return GOOD


def apply_theme(app: QApplication, dark: bool) -> None:
    app.setStyle("Fusion")
    app.setFont(ui_font())
    pal = QPalette()
    if dark:
        c = {
            QPalette.Window: "#1f2328", QPalette.WindowText: "#d7dce2", QPalette.Base: "#16191d",
            QPalette.AlternateBase: "#1c2025", QPalette.ToolTipBase: "#2d333b", QPalette.ToolTipText: "#e6edf3",
            QPalette.Text: "#d7dce2", QPalette.Button: "#2a2f36", QPalette.ButtonText: "#d7dce2",
            QPalette.BrightText: "#ff7b72", QPalette.Highlight: "#2f5f9e", QPalette.HighlightedText: "#ffffff",
            QPalette.Link: ACCENT, QPalette.PlaceholderText: "#7d8590", QPalette.Mid: "#3d444d",
            QPalette.Dark: "#0d1014", QPalette.Light: "#3d444d", QPalette.Midlight: "#30363d",
            QPalette.Shadow: "#000000",
        }
        for role, col in c.items():
            pal.setColor(role, QColor(col))
        for role in (QPalette.Text, QPalette.WindowText, QPalette.ButtonText):
            pal.setColor(QPalette.Disabled, role, QColor("#6e7681"))
    else:
        pal = app.style().standardPalette()
        pal.setColor(QPalette.Highlight, QColor("#2f6fca"))
    app.setPalette(pal)
    if dark:
        # in Fusion the checkbox frame uses Base and a dark border: it would vanish on the dark background
        cb = QPalette(pal)
        cb.setColor(QPalette.Base, QColor("#3a414a"))
        cb.setColor(QPalette.Window, QColor("#5a636e"))
        app.setPalette(cb, "QCheckBox")
    else:
        app.setPalette(pal, "QCheckBox")
    app.setStyleSheet("""
        QTreeView, QTableView, QPlainTextEdit, QTextBrowser { border: 1px solid palette(mid); }
        QHeaderView::section { padding: 4px 6px; border: none; border-right: 1px solid palette(mid);
                               border-bottom: 1px solid palette(mid); background: palette(button); }
        QToolBar { spacing: 6px; padding: 3px; }
        QLabel#pageTitle { font-size: 15pt; font-weight: 600; }
        QLabel#muted { color: palette(placeholder-text); }
        QFrame#card { border: 1px solid palette(mid); border-radius: 6px; }
        QLineEdit { padding: 4px; }
    """)
