"""Reusable widgets: score gauge, entropy chart, copyable tables."""
from __future__ import annotations

import bisect
import unicodedata
from typing import Any, Iterable

from PySide6.QtCore import QPointF, QRectF, Qt, QSize
from PySide6.QtGui import (QAction, QBrush, QColor, QFont, QFontDatabase, QGuiApplication, QKeySequence,
                           QLinearGradient, QPainter, QPainterPath, QPalette, QPen)
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
                               QToolTip, QTreeWidget, QVBoxLayout, QWidget)

from .theme import SEVERITY, score_color


def mono_font() -> QFont:
    from .theme import MONO_FONT, UI_SIZE, load_fonts
    if MONO_FONT in load_fonts():
        f = QFont(MONO_FONT)
        f.setPointSizeF(UI_SIZE - 0.5)
        f.setStyleHint(QFont.Monospace)
        return f
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    f.setStyleHint(QFont.Monospace)
    return f


def visible(s: str, limit: int | None = None) -> str:
    """Invisible characters (zero-width, directional, control) shown as \\uXXXX."""
    out = []
    for ch in s:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    r = "".join(out)
    return r if limit is None or len(r) <= limit else r[:limit] + "…"


def hx(v: int | None) -> str:
    return "" if v is None else f"0x{v:x}"


# --- copy ----------------------------------------------------------------------------------------

def copy_selection(view: QAbstractItemView) -> None:
    sel = view.selectionModel()
    if sel is None:
        return
    idxs = sel.selectedIndexes()
    if not idxs:
        return
    rows: dict[tuple, dict[int, str]] = {}
    order = []
    for i in idxs:
        if view.isColumnHidden(i.column()) if hasattr(view, "isColumnHidden") else False:
            continue
        key = (_path(i), i.row())
        if key not in rows:
            rows[key] = {}
            order.append(key)
        rows[key][i.column()] = str(i.data(Qt.DisplayRole) or "")
    order.sort()
    text = "\n".join("\t".join(r[c] for c in sorted(r)) for r in (rows[k] for k in order))
    QGuiApplication.clipboard().setText(text)


def _path(index) -> tuple:
    p = []
    i = index.parent()
    while i.isValid():
        p.append(i.row())
        i = i.parent()
    return tuple(reversed(p))


def copy_value(view: QAbstractItemView) -> None:
    i = view.currentIndex()
    if i.isValid():
        QGuiApplication.clipboard().setText(str(i.data(Qt.UserRole + 1) or i.data(Qt.DisplayRole) or ""))


def install_copy(view: QAbstractItemView) -> None:
    view.setContextMenuPolicy(Qt.ActionsContextMenu)
    a = QAction("Copy selected rows", view)
    a.setShortcut(QKeySequence.Copy)
    a.setShortcutContext(Qt.WidgetShortcut)
    a.triggered.connect(lambda: copy_selection(view))
    view.addAction(a)
    b = QAction("Copy cell value", view)
    b.triggered.connect(lambda: copy_value(view))
    view.addAction(b)


# --- tables --------------------------------------------------------------------------------------

class Cell:
    """Cell with text, sort key, color, tooltip and full value to copy."""
    __slots__ = ("text", "key", "color", "tip", "mono", "bold", "full")

    def __init__(self, text: Any, key: Any = None, color: str | None = None, tip: str | None = None,
                 mono: bool = False, bold: bool = False, full: str | None = None):
        self.text = "" if text is None else str(text)
        self.key = key
        self.color = color
        self.tip = tip
        self.mono = mono
        self.bold = bold
        self.full = full


class _Item(QTableWidgetItem):
    def __lt__(self, other):
        a, b = self.data(Qt.UserRole), other.data(Qt.UserRole)
        if a is not None and b is not None and type(a) is type(b):
            return a < b
        if a is not None and b is None:
            return True
        if a is None and b is not None:
            return False
        return self.text().lower() < other.text().lower()


def make_table(headers: list[str], rows: Iterable[list[Any]], *, stretch: int | None = None,
               mono_cols: Iterable[int] = (), right_cols: Iterable[int] = (), targets: list | None = None,
               on_activate=None) -> QTableWidget:
    """targets: for each row a value passed to on_activate on double-click (also after re-sorting)."""
    rows = list(rows)
    t = QTableWidget(len(rows), len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(22)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.setWordWrap(False)
    mono_cols, right_cols = set(mono_cols), set(right_cols)
    mf = mono_font()
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            cell = v if isinstance(v, Cell) else Cell(v, key=v if isinstance(v, (int, float)) else None)
            it = _Item(cell.text)
            if cell.key is not None:
                it.setData(Qt.UserRole, cell.key)
            if cell.full is not None:
                it.setData(Qt.UserRole + 1, cell.full)
            if cell.color:
                it.setForeground(QBrush(QColor(cell.color)))
            if cell.tip:
                it.setToolTip(cell.tip)
            if cell.mono or c in mono_cols:
                it.setFont(mf)
            if cell.bold:
                f = it.font()
                f.setBold(True)
                it.setFont(f)
            if c in right_cols:
                it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            if c == 0 and targets is not None:
                it.setData(Qt.UserRole + 2, targets[r])
            t.setItem(r, c, it)
    # without an indicator enabling sorting does not reorder the rows (the file order stays)
    t.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
    t.setSortingEnabled(True)
    hh = t.horizontalHeader()
    hh.setSectionResizeMode(QHeaderView.Interactive)
    t.resizeColumnsToContents()
    for c in range(len(headers)):
        if t.columnWidth(c) > 420:
            t.setColumnWidth(c, 420)
    if stretch is not None:
        hh.setSectionResizeMode(stretch, QHeaderView.Stretch)
    else:
        hh.setStretchLastSection(True)
    install_copy(t)
    if on_activate is not None and targets is not None:
        def _act(row, _col):
            tgt = t.item(row, 0).data(Qt.UserRole + 2)
            if tgt is not None:
                on_activate(tgt)
        t.cellDoubleClicked.connect(_act)
    return t


def make_tree(headers: list[str]) -> QTreeWidget:
    t = QTreeWidget()
    t.setHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setUniformRowHeights(True)
    t.setSelectionMode(QAbstractItemView.ExtendedSelection)
    install_copy(t)
    return t


def title(text: str, sub: str | None = None) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 4)
    lay.setSpacing(2)
    t = QLabel(text)
    t.setObjectName("pageTitle")
    lay.addWidget(t)
    if sub:
        s = QLabel(sub)
        s.setObjectName("muted")
        s.setWordWrap(True)
        s.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(s)
    return w


def card() -> QFrame:
    f = QFrame()
    f.setObjectName("card")
    return f


# --- score gauge -----------------------------------------------------------------------

class ScoreGauge(QWidget):
    def __init__(self, score: int, verdict: str, parent=None):
        super().__init__(parent)
        self.score, self.verdict = score, verdict
        self.setMinimumSize(190, 190)

    def sizeHint(self) -> QSize:
        return QSize(200, 200)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        side = min(self.width(), self.height()) - 24
        r = QRectF((self.width() - side) / 2, 10, side, side)
        pen_w = max(10, side / 13)
        pal = self.palette()
        col = QColor(score_color(self.score))
        p.setPen(QPen(pal.color(QPalette.Mid), pen_w, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(r, 225 * 16, -270 * 16)
        if self.score > 0:
            p.setPen(QPen(col, pen_w, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, 225 * 16, int(-270 * 16 * min(self.score, 100) / 100))
        f = self.font()
        f.setPointSizeF(side / 5.2)
        f.setBold(True)
        p.setFont(f)
        p.setPen(col)
        p.drawText(r.adjusted(0, -side * 0.08, 0, -side * 0.08), Qt.AlignCenter, str(self.score))
        f.setPointSizeF(max(8.0, side / 17))
        f.setBold(False)
        p.setFont(f)
        p.setPen(pal.color(QPalette.PlaceholderText))
        p.drawText(r.adjusted(0, side * 0.2, 0, side * 0.2), Qt.AlignCenter, "/ 100")
        f.setBold(True)
        p.setFont(f)
        p.setPen(col)
        p.drawText(QRectF(0, r.bottom() - side * 0.12, self.width(), side * 0.2), Qt.AlignCenter, self.verdict)


# --- entropy chart ------------------------------------------------------------------------

class EntropyChart(QWidget):
    """Sliding-window entropy over the whole file, with the sections as colored bands."""

    ML, MR, MT, MB = 34, 10, 22, 20

    def __init__(self, report: dict, parent=None):
        super().__init__(parent)
        pe = report["pe"]
        self.report = report
        self.on_click = None   # callable(offset): set by the page to open the hex view
        self.size_ = max(pe["size"], 1)
        pts = report.get("entropy", {}).get("points") or []
        self.xs = [p[0] for p in pts]
        self.ys = [p[1] for p in pts]
        self.sections = [s for s in pe["sections"] if s["raw_size"] > 0]
        self.overlay = pe.get("overlay")
        self.signature = pe.get("signature")
        self.setMouseTracking(True)
        self.setMinimumHeight(130)

    def sizeHint(self) -> QSize:
        return QSize(600, 220)

    def _plot(self) -> QRectF:
        return QRectF(self.ML, self.MT, self.width() - self.ML - self.MR, self.height() - self.MT - self.MB)

    def _x(self, r: QRectF, off: float) -> float:
        return r.left() + off / self.size_ * r.width()

    def _y(self, r: QRectF, e: float) -> float:
        return r.bottom() - e / 8.0 * r.height()

    @staticmethod
    def _sec_color(s: dict) -> QColor:
        if s["executable"] and s["writable"]:
            return QColor(SEVERITY["high"])
        if s["executable"]:
            return QColor("#539bf5")
        if s["writable"]:
            return QColor("#3fb950")
        return QColor("#8b949e")

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pal = self.palette()
        r = self._plot()
        p.fillRect(r, pal.color(QPalette.Base))
        small = self.font()
        small.setPointSizeF(max(7.0, small.pointSizeF() - 1))
        p.setFont(small)

        # section bands
        bands = [(s["raw_offset"], s["raw_offset"] + s["raw_size"], s["name"], self._sec_color(s)) for s in self.sections]
        if self.overlay:
            bands.append((self.overlay["offset"], self.overlay["offset"] + self.overlay["size"], "overlay", QColor("#db6d28")))
        if self.signature:
            bands.append((self.signature["offset"], self.signature["offset"] + self.signature["size"], "signature",
                          QColor("#a371f7")))
        last_label_x = -1e9
        for a, b, name, col in bands:
            x0, x1 = self._x(r, a), self._x(r, min(b, self.size_))
            fill = QColor(col)
            fill.setAlpha(38)
            p.fillRect(QRectF(x0, r.top(), max(1.0, x1 - x0), r.height()), fill)
            edge = QColor(col)
            edge.setAlpha(160)
            p.fillRect(QRectF(x0, r.top() - 4, max(1.0, x1 - x0), 3), edge)
            label = name or "?"
            tw = p.fontMetrics().horizontalAdvance(label)
            if x1 - x0 >= tw * 0.6 and x0 >= last_label_x:
                p.setPen(col.lighter(130) if pal.color(QPalette.Base).lightness() < 128 else col.darker(130))
                p.drawText(QPointF(x0 + 2, r.top() - 7), label)
                last_label_x = x0 + tw + 6

        # grid
        grid = QColor(pal.color(QPalette.Mid))
        for e in (0, 2, 4, 6, 8):
            y = self._y(r, e)
            p.setPen(QPen(grid, 1, Qt.DotLine))
            p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
            p.setPen(pal.color(QPalette.PlaceholderText))
            p.drawText(QRectF(0, y - 8, self.ML - 6, 16), Qt.AlignRight | Qt.AlignVCenter, str(e))
        y72 = self._y(r, 7.2)
        hi = QColor(SEVERITY["high"])
        hi.setAlpha(150)
        p.setPen(QPen(hi, 1, Qt.DashLine))
        p.drawLine(QPointF(r.left(), y72), QPointF(r.right(), y72))

        # curve
        if self.xs:
            path = QPainterPath(QPointF(self._x(r, self.xs[0]), self._y(r, self.ys[0])))
            for x, y in zip(self.xs[1:], self.ys[1:]):
                path.lineTo(self._x(r, x), self._y(r, y))
            area = QPainterPath(path)
            area.lineTo(self._x(r, self.xs[-1]), r.bottom())
            area.lineTo(self._x(r, self.xs[0]), r.bottom())
            area.closeSubpath()
            g = QLinearGradient(0, r.top(), 0, r.bottom())
            c1 = QColor("#539bf5")
            c1.setAlpha(110)
            c2 = QColor("#539bf5")
            c2.setAlpha(10)
            g.setColorAt(0, c1)
            g.setColorAt(1, c2)
            p.fillPath(area, g)
            p.setPen(QPen(QColor("#79b8ff"), 1.3))
            p.drawPath(path)

        # x axis
        p.setPen(pal.color(QPalette.PlaceholderText))
        for frac in (0, 0.25, 0.5, 0.75, 1.0):
            off = int(self.size_ * frac)
            x = self._x(r, off)
            align = Qt.AlignLeft if frac == 0 else Qt.AlignRight if frac == 1 else Qt.AlignHCenter
            rect = QRectF(x - 60 if frac else x, r.bottom() + 2, 120 if 0 < frac < 1 else 60, 16)
            if frac == 1:
                rect = QRectF(x - 80, r.bottom() + 2, 80, 16)
            p.drawText(rect, align | Qt.AlignTop, f"0x{off:x}")
        p.setPen(QPen(pal.color(QPalette.Mid)))
        p.setBrush(Qt.NoBrush)
        p.drawRect(r)

    def mousePressEvent(self, ev):
        r = self._plot()
        x = ev.position().x()
        if self.on_click and ev.button() == Qt.LeftButton and r.left() <= x <= r.right():
            self.on_click(int((x - r.left()) / r.width() * self.size_))

    def mouseMoveEvent(self, ev):
        r = self._plot()
        x = ev.position().x()
        if not self.xs or not (r.left() <= x <= r.right()):
            QToolTip.hideText()
            return
        off = int((x - r.left()) / r.width() * self.size_)
        i = min(max(bisect.bisect_left(self.xs, off) - 1, 0), len(self.xs) - 1)
        where = "headers"
        for s in self.sections:
            if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
                where = f"section {s['name']} ({s['flags']})"
        if self.overlay and off >= self.overlay["offset"]:
            where = "overlay"
        if self.signature and self.signature["offset"] <= off < self.signature["offset"] + self.signature["size"]:
            where = "Authenticode signature"
        QToolTip.showText(ev.globalPosition().toPoint(),
                          f"offset 0x{off:x}\nentropy {self.ys[i]:.2f}\n{where}"
                          + ("\nclick to open in the hex view" if self.on_click else ""), self)
