"""SVG icons drawn for PELens (24x24 line icons) and colored with the theme.

Each icon uses two colors: {fg} (the text color of the theme) and {ac} (the accent color). They are rendered
with QSvgRenderer at several sizes, plus a grey version for disabled actions.
"""
from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# colors of the two themes: (foreground, accent, disabled)
COLORS = {True: ("#c9d1d9", "#539bf5", "#545d68"), False: ("#3b4250", "#2f6fca", "#a8b0ba")}

_FILE = '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
_FOLDER = '<path d="M3 7.5A2 2 0 0 1 5 5.5h3.6l2 2H19a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'

PATHS = {
    # --- actions ---
    "open": _FILE + '<g stroke="{ac}"><path d="M12 18v-6"/><path d="M9.5 14.5L12 12l2.5 2.5"/></g>',
    "open_folder": _FOLDER + '<g stroke="{ac}"><path d="M12 16.5v-5"/><path d="M9.8 13.7L12 11.5l2.2 2.2"/></g>',
    "recent": '<circle cx="12" cy="12" r="8.5"/><path stroke="{ac}" d="M12 7.5V12l3 2"/>',
    "reanalyze": '<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path stroke="{ac}" d="M19.5 4.5v4h-4"/>',
    "save": '<path stroke="{ac}" d="M12 4v10.5"/><path stroke="{ac}" d="M7.5 10.5L12 15l4.5-4.5"/>'
            '<path d="M5 19.5h14"/>',
    "html": _FILE + '<g stroke="{ac}"><path d="M10 13l-2 2 2 2"/><path d="M14 13l2 2-2 2"/></g>',
    "csv": '<rect x="4" y="4.5" width="16" height="15" rx="2"/><path d="M4 9.5h16M4 14.5h16"/>'
           '<path stroke="{ac}" d="M10 9.5v10"/>',
    "close": '<path d="M7 7l10 10M17 7L7 17"/>',
    "close_all": '<rect x="3.5" y="6.5" width="13" height="13" rx="2"/><path d="M7.5 3.5H18a2.5 2.5 0 0 1 2.5 2.5v10.5"/>'
                 '<path stroke="{ac}" d="M7.5 10.5l5 5M12.5 10.5l-5 5"/>',
    "quit": '<path stroke="{ac}" d="M12 3.5v8"/><path d="M7.2 6.6a7.5 7.5 0 1 0 9.6 0"/>',
    "summary": '<path d="M9 6.5h11M9 12h11M9 17.5h11"/><g stroke="{ac}"><path d="M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01"/>'
               '</g>',
    "compare": '<rect x="3.5" y="4.5" width="7" height="15" rx="1.5"/><rect x="13.5" y="4.5" width="7" height="15" rx="1.5"/>'
               '<g stroke="{ac}"><path d="M6 9h2M6 12h2M16 9h2M16 15h2"/></g>',
    "theme": '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    "yara": '<path d="M12 3.5l7 2.8v5.2c0 4.3-3 7.6-7 9-4-1.4-7-4.7-7-9V6.3z"/>'
            '<path stroke="{ac}" d="M8.8 12l2.2 2.2 4.2-4.4"/>',
    "unmap": '<path d="M12 3.5l8.5 4.3L12 12 3.5 7.8z"/><path stroke="{ac}" d="M3.5 12.2L12 16.5l8.5-4.3"/>'
             '<path stroke="{ac}" d="M3.5 16.4L12 20.5l8.5-4.1"/>',
    "about": '<circle cx="12" cy="12" r="8.5"/><path stroke="{ac}" d="M12 11v5.5"/><path stroke="{ac}" d="M12 7.6h.01"/>',
    # --- pages ---
    "overview": '<path d="M4.5 16.5a7.5 7.5 0 1 1 15 0"/><path stroke="{ac}" d="M12 16.5l3.5-5"/>'
                '<path d="M4.5 19.5h15"/>',
    "findings": '<path d="M5.5 21V4.5"/><path stroke="{ac}" d="M5.5 4.5h12l-2.5 4 2.5 4h-12"/>',
    "ai_notes": '<path d="M5 4.5h14a1.5 1.5 0 0 1 1.5 1.5v9.5a1.5 1.5 0 0 1-1.5 1.5H10l-4.5 3.5V17H5a1.5 1.5 0 0 1-1.5-1.5V6A1.5 1.5 0 0 1 5 4.5z"/>'
                '<path stroke="{ac}" d="M12 7.5l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9z"/>',
    "attack": '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/>'
              '<path stroke="{ac}" d="M12 12h.01"/>',
    "dotnet": '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path stroke="{ac}" d="M9.5 15V9l5 6V9"/>'
              '<path stroke="{ac}" d="M6.5 15h.01"/>',
    "crypto": '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>'
              '<path stroke="{ac}" d="M12 14.5v2.5"/>',
    "code": '<path stroke="{ac}" d="M8.5 8L4.5 12l4 4M15.5 8l4 4-4 4"/><path d="M13.5 5.5l-3 13"/>',
    "strings": '<path d="M4 6.5V5h10v1.5M9 5v14M7 19h4"/><path stroke="{ac}" d="M15.5 11h4.5M15.5 15h4.5M15.5 19h3"/>',
    "sections": '<rect x="4" y="4" width="16" height="4" rx="1"/><rect x="4" y="10" width="16" height="4" rx="1"/>'
                '<rect x="4" y="16" width="16" height="4" rx="1" stroke="{ac}"/>',
    "imports": '<path d="M14 4.5h4a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-4"/><path stroke="{ac}" d="M3.5 12H14"/>'
               '<path stroke="{ac}" d="M10.5 8.5L14 12l-3.5 3.5"/>',
    "exports": '<path d="M10 4.5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h4"/><path stroke="{ac}" d="M9.5 12H20.5"/>'
               '<path stroke="{ac}" d="M17 8.5l3.5 3.5-3.5 3.5"/>',
    "resources": '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="9.5" r="1.6" stroke="{ac}"/>'
                 '<path stroke="{ac}" d="M20.5 15.5l-5-5-9 9"/>',
    "hex": '<path d="M4.5 9.5h15M4.5 14.5h15"/><path stroke="{ac}" d="M9.5 4.5l-1 15M15.5 4.5l-1 15"/>',
    "headers": _FILE + '<path stroke="{ac}" d="M8.5 12.5h7M8.5 16h5"/>',
    "json": '<path d="M8.5 4.5H8a2 2 0 0 0-2 2v3.5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v3.5a2 2 0 0 0 2 2h.5"/>'
            '<path d="M15.5 4.5h.5a2 2 0 0 1 2 2v3.5a2 2 0 0 0 2 2 2 2 0 0 0-2 2v3.5a2 2 0 0 1-2 2h-.5"/>'
            '<path stroke="{ac}" d="M12 12h.01"/>',
}

SIZES = (16, 20, 24, 32, 48)
_cache: dict[tuple[str, bool], QIcon] = {}


def _svg(name: str, fg: str, ac: str) -> bytes:
    body = PATHS[name].replace("{ac}", ac)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{fg}" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>').encode()


def _pixmap(svg: bytes, size: int) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    QSvgRenderer(QByteArray(svg)).render(p, QRectF(0, 0, size, size))
    p.end()
    return pm


def icon(name: str, dark: bool) -> QIcon:
    key = (name, dark)
    if key not in _cache:
        fg, ac, off = COLORS[dark]
        ic = QIcon()
        on, dis = _svg(name, fg, ac), _svg(name, off, off)
        for s in SIZES:
            ic.addPixmap(_pixmap(on, s), QIcon.Normal)
            ic.addPixmap(_pixmap(dis, s), QIcon.Disabled)
        _cache[key] = ic
    return _cache[key]


def svg_source(name: str, dark: bool = True) -> str:
    """The SVG of an icon (for tests and to save them as files)."""
    fg, ac, _ = COLORS[dark]
    return _svg(name, fg, ac).decode()
