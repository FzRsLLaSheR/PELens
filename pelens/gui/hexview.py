"""HxD-style hex view: offset | 16 bytes | ASCII, colored regions, search, data inspector."""
from __future__ import annotations

import bisect
import datetime as _dt
import math
import os
import re
import struct

from PySide6.QtCore import QRect, Qt, Signal
from PySide6.QtGui import QAction, QColor, QGuiApplication, QKeySequence, QPainter, QPalette
from PySide6.QtWidgets import (QAbstractScrollArea, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from .theme import SEVERITY
from .widgets import install_copy, mono_font, title

BPR = 16  # bytes per row


# --- offset <-> RVA/VA map ------------------------------------------------------------------------

class AddressMap:
    def __init__(self, report: dict):
        pe = report["pe"]
        self.base = pe["image_base"]
        self.size = pe["size"]
        self.sections = sorted(pe["sections"], key=lambda s: s["raw_offset"])
        self.headers_end = min([s["raw_offset"] for s in self.sections if s["raw_size"]] or [pe["size"]])
        self.overlay = pe.get("overlay")
        self.signature = pe.get("signature")

    def section_at(self, off: int) -> dict | None:
        for s in self.sections:
            if s["raw_size"] and s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
                return s
        return None

    def describe(self, off: int) -> tuple[int | None, str]:
        """(RVA, region) of the file offset."""
        if self.signature and self.signature["offset"] <= off < self.signature["offset"] + self.signature["size"]:
            return None, "Authenticode signature"
        s = self.section_at(off)
        if s:
            return s["virtual_address"] + off - s["raw_offset"], s["name"]
        if off < self.headers_end:
            return off, "headers"
        if self.overlay and off >= self.overlay["offset"]:
            return None, "overlay"
        return None, "outside sections"

    def rva_to_offset(self, rva: int) -> int | None:
        if rva < self.headers_end:
            return rva
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= rva < s["virtual_address"] + span:
                d = rva - s["virtual_address"]
                return s["raw_offset"] + d if d < s["raw_size"] else None
        return None

    def va_to_offset(self, va: int) -> int | None:
        return self.rva_to_offset(va - self.base) if va >= self.base else None

    def regions(self) -> list[tuple[int, int, str, QColor]]:
        out = [(0, self.headers_end, "headers", QColor("#a371f7"))]
        for s in self.sections:
            if not s["raw_size"]:
                continue
            if s["executable"] and s["writable"]:
                c = QColor(SEVERITY["high"])
            elif s["executable"]:
                c = QColor("#539bf5")
            elif s["writable"]:
                c = QColor("#3fb950")
            else:
                c = QColor("#8b949e")
            out.append((s["raw_offset"], min(s["raw_offset"] + s["raw_size"], self.size), s["name"], c))
        if self.overlay:
            out.append((self.overlay["offset"], self.size, "overlay", QColor("#db6d28")))
        if self.signature:
            out.append((self.signature["offset"], self.signature["offset"] + self.signature["size"], "signature",
                        QColor("#d2a8ff")))
        return sorted(out, key=lambda r: r[0])


# --- widget -----------------------------------------------------------------------------------------

class HexView(QAbstractScrollArea):
    cursorMoved = Signal()

    def __init__(self, data: bytes, regions: list, parent=None):
        super().__init__(parent)
        self.data = data
        self.regions = regions
        self.reg_starts = [r[0] for r in regions]
        self.cursor = 0
        self.anchor = 0
        self.dragging = False
        self.setFont(mono_font())
        self.viewport().setCursor(Qt.IBeamCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._metrics()
        self.verticalScrollBar().setSingleStep(3)

    # geometry
    def _metrics(self):
        fm = self.fontMetrics()
        self.cw = fm.horizontalAdvance("0")
        self.lh = fm.height() + 3
        self.asc = fm.ascent()
        self.x_off = 8
        self.x_hex = self.x_off + self.cw * 11
        self.x_asc = self._hex_x(BPR) + self.cw * 2
        self.top = self.lh + 6
        self.setMinimumWidth(self.x_asc + BPR * self.cw + 30)

    def _hex_x(self, i: int) -> int:
        return self.x_hex + i * 3 * self.cw + (self.cw if i >= 8 else 0)

    def rows(self) -> int:
        return max(1, math.ceil(len(self.data) / BPR))

    def visible_rows(self) -> int:
        return max(1, (self.viewport().height() - self.top) // self.lh)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._update_scroll()

    def _update_scroll(self):
        sb = self.verticalScrollBar()
        sb.setRange(0, max(0, self.rows() - self.visible_rows() + 1))
        sb.setPageStep(self.visible_rows())

    def sel(self) -> tuple[int, int]:
        a, b = sorted((self.anchor, self.cursor))
        return a, b + 1

    def _region(self, off: int):
        # regions are sorted by start: the last one containing the offset is the most specific
        # (e.g. the signature inside the overlay)
        i = bisect.bisect_right(self.reg_starts, off) - 1
        while i >= 0:
            r = self.regions[i]
            if r[0] <= off < r[1]:
                return r
            i -= 1
        return None

    # painting
    def paintEvent(self, _):
        p = QPainter(self.viewport())
        pal = self.palette()
        dark = pal.color(QPalette.Base).lightness() < 128
        p.fillRect(self.viewport().rect(), pal.color(QPalette.Base))
        p.setFont(self.font())
        dim = pal.color(QPalette.PlaceholderText)
        text = pal.color(QPalette.Text)
        zero = QColor(text)
        zero.setAlpha(110)
        hl = QColor(pal.color(QPalette.Highlight))
        cur_col = QColor(SEVERITY["medium"])

        # header
        p.fillRect(QRect(0, 0, self.viewport().width(), self.lh + 2), pal.color(QPalette.Button))
        p.setPen(dim)
        p.drawText(self.x_off, self.asc + 2, "Offset")
        for i in range(BPR):
            p.drawText(self._hex_x(i), self.asc + 2, f"{i:02X}")
        p.drawText(self.x_asc, self.asc + 2, "Decoded text")

        first = self.verticalScrollBar().value()
        lo, hi = self.sel()
        n = len(self.data)
        for vr in range(self.visible_rows() + 1):
            row = first + vr
            base = row * BPR
            if base >= n:
                break
            y = self.top + vr * self.lh
            p.setPen(dim)
            p.drawText(self.x_off, y + self.asc, f"{base:08X}")
            chunk = self.data[base:base + BPR]
            for i, b in enumerate(chunk):
                off = base + i
                hx_rect = QRect(self._hex_x(i) - self.cw // 2, y, 3 * self.cw, self.lh)
                as_rect = QRect(self.x_asc + i * self.cw, y, self.cw, self.lh)
                reg = self._region(off)
                if reg:
                    c = QColor(reg[3])
                    c.setAlpha(34 if dark else 28)
                    p.fillRect(hx_rect, c)
                    p.fillRect(as_rect, c)
                if lo <= off < hi and hi - lo > 1:
                    p.fillRect(hx_rect, hl)
                    p.fillRect(as_rect, hl)
                if off == self.cursor:
                    p.setPen(cur_col)
                    p.drawRect(hx_rect.adjusted(1, 0, -2, -1))
                    p.drawRect(as_rect.adjusted(0, 0, -1, -1))
                sel = lo <= off < hi and hi - lo > 1
                p.setPen(pal.color(QPalette.HighlightedText) if sel else (zero if b == 0 else text))
                p.drawText(self._hex_x(i), y + self.asc, f"{b:02X}")
                p.drawText(self.x_asc + i * self.cw, y + self.asc, chr(b) if 0x20 <= b < 0x7F else ".")
        # separators
        p.setPen(pal.color(QPalette.Mid))
        x1 = self.x_hex - self.cw
        x2 = self.x_asc - self.cw
        h = self.viewport().height()
        p.drawLine(x1, 0, x1, h)
        p.drawLine(x2, 0, x2, h)
        p.drawLine(0, self.lh + 2, self.viewport().width(), self.lh + 2)

    # position from the mouse
    def _hit(self, pos) -> int | None:
        y = pos.y() - self.top
        if y < 0:
            row = self.verticalScrollBar().value()
        else:
            row = self.verticalScrollBar().value() + y // self.lh
        x = pos.x()
        if x >= self.x_asc - self.cw // 2:
            col = (x - self.x_asc) // self.cw
        else:
            col = 0
            for i in range(BPR):
                if x >= self._hex_x(i) - self.cw // 2:
                    col = i
        col = max(0, min(BPR - 1, col))
        return max(0, min(len(self.data) - 1, row * BPR + col))

    def mousePressEvent(self, e):
        if e.button() != Qt.LeftButton or not self.data:
            return super().mousePressEvent(e)
        off = self._hit(e.position().toPoint())
        self.cursor = off
        if not (e.modifiers() & Qt.ShiftModifier):
            self.anchor = off
        self.dragging = True
        self._changed()

    def mouseMoveEvent(self, e):
        if self.dragging:
            pos = e.position().toPoint()
            if pos.y() < self.top:
                self.verticalScrollBar().setValue(self.verticalScrollBar().value() - 1)
            elif pos.y() > self.viewport().height():
                self.verticalScrollBar().setValue(self.verticalScrollBar().value() + 1)
            self.cursor = self._hit(pos)
            self._changed()

    def mouseReleaseEvent(self, e):
        self.dragging = False

    def keyPressEvent(self, e):
        k = e.key()
        step = {Qt.Key_Left: -1, Qt.Key_Right: 1, Qt.Key_Up: -BPR, Qt.Key_Down: BPR,
                Qt.Key_PageUp: -BPR * self.visible_rows(), Qt.Key_PageDown: BPR * self.visible_rows()}.get(k)
        ctrl = e.modifiers() & Qt.ControlModifier
        if step is not None:
            new = self.cursor + step
        elif k == Qt.Key_Home:
            new = 0 if ctrl else self.cursor - self.cursor % BPR
        elif k == Qt.Key_End:
            new = len(self.data) - 1 if ctrl else self.cursor - self.cursor % BPR + BPR - 1
        else:
            return super().keyPressEvent(e)
        self.cursor = max(0, min(len(self.data) - 1, new))
        if not (e.modifiers() & Qt.ShiftModifier):
            self.anchor = self.cursor
        self.ensure_visible(self.cursor)
        self._changed()

    def _changed(self):
        self.viewport().update()
        self.cursorMoved.emit()

    def ensure_visible(self, off: int, center: bool = False):
        row = off // BPR
        sb = self.verticalScrollBar()
        vis = self.visible_rows()
        if center:
            sb.setValue(max(0, row - vis // 3))
        elif row < sb.value():
            sb.setValue(row)
        elif row >= sb.value() + vis:
            sb.setValue(row - vis + 1)

    def goto(self, off: int, length: int = 1):
        if not self.data:
            return
        off = max(0, min(len(self.data) - 1, off))
        self.anchor = off
        self.cursor = max(off, min(len(self.data) - 1, off + max(1, length) - 1))
        self._update_scroll()
        self.ensure_visible(off, center=True)
        self._changed()
        self.setFocus()

    def selected(self) -> bytes:
        lo, hi = self.sel()
        return self.data[lo:hi]


# --- search ----------------------------------------------------------------------------------------

def build_pattern(text: str, mode: str) -> re.Pattern | None:
    text = text.strip() if mode == "hex" else text
    if not text:
        return None
    if mode == "hex":
        toks = re.findall(r"\?\?|[0-9a-fA-F]{2}", text.replace(" ", "")) if " " not in text else text.split()
        parts = []
        for t in toks:
            if t in ("??", "?"):
                parts.append(b".")
            elif re.fullmatch(r"[0-9a-fA-F]{2}", t):
                parts.append(re.escape(bytes([int(t, 16)])))
            else:
                raise ValueError(f"not a hex byte: {t}")
        return re.compile(b"".join(parts), re.S)
    if mode == "utf16":
        # case-insensitive: each ASCII letter becomes [Aa]\x00
        parts = []
        for ch in text:
            if ch.isascii() and ch.isalpha():
                parts.append(b"[" + ch.lower().encode() + ch.upper().encode() + b"]\x00")
            else:
                parts.append(re.escape(ch.encode("utf-16-le")))
        return re.compile(b"".join(parts), re.S)
    return re.compile(re.escape(text.encode("latin-1", "replace")), re.S | re.I)


# --- page -----------------------------------------------------------------------------------------

def _fmt_int(v: int, bits: int) -> str:
    return f"{v}  (0x{v & ((1 << bits) - 1):0{bits // 4}X})"


class HexPage(QWidget):
    def __init__(self, report: dict, data: bytes):
        super().__init__()
        self.report = report
        self.amap = AddressMap(report)
        self.hex = HexView(data, self.amap.regions())
        self.hex.cursorMoved.connect(self._update_info)

        # barra: go to + find
        self.goto_edit = QLineEdit()
        self.goto_edit.setPlaceholderText("0x1000")
        self.goto_edit.setMaximumWidth(150)
        self.goto_mode = QComboBox()
        self.goto_mode.addItems(["Offset", "RVA", "VA"])
        go = QPushButton("Go to")
        go.clicked.connect(self.do_goto)
        self.goto_edit.returnPressed.connect(self.do_goto)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("4D 5A ?? 00   or text")
        self.find_mode = QComboBox()
        self.find_mode.addItem("Hex bytes", "hex")
        self.find_mode.addItem("Text (ASCII)", "ascii")
        self.find_mode.addItem("Text (UTF-16)", "utf16")
        prev_b = QPushButton("◀")
        prev_b.setMaximumWidth(34)
        prev_b.setToolTip("Find previous (Shift+F3)")
        next_b = QPushButton("Find ▶")
        next_b.setToolTip("Find next (F3)")
        prev_b.clicked.connect(lambda: self.do_find(back=True))
        next_b.clicked.connect(lambda: self.do_find())
        self.find_edit.returnPressed.connect(lambda: self.do_find())
        bar = QHBoxLayout()
        bar.addWidget(self.goto_mode)
        bar.addWidget(self.goto_edit)
        bar.addWidget(go)
        bar.addSpacing(18)
        bar.addWidget(self.find_mode)
        bar.addWidget(self.find_edit, 1)
        bar.addWidget(prev_b)
        bar.addWidget(next_b)
        bw = QWidget()
        bw.setLayout(bar)

        # data inspector
        self.insp = QTreeWidget()
        self.insp.setHeaderLabels(["Type", "Value (little endian)"])
        self.insp.setRootIsDecorated(False)
        self.insp.setAlternatingRowColors(True)
        self.insp.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        install_copy(self.insp)
        self.insp.setMinimumWidth(300)

        # region legend
        leg = QLabel(" ".join(f"<span style='color:{c.name()}'>■</span> {n}" for n, c in
                              {r[2]: r[3] for r in self.amap.regions()}.items()))
        leg.setObjectName("muted")
        leg.setWordWrap(True)

        self.status = QLabel()
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.status.setFont(mono_font())

        split = QSplitter()
        split.addWidget(self.hex)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        lab = QLabel("Data inspector")
        f = lab.font()
        f.setBold(True)
        lab.setFont(f)
        rl.addWidget(lab)
        rl.addWidget(self.insp, 1)
        rl.addWidget(leg)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setSizes([900, 320])

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.addWidget(title("Hex", f"{len(data):,} bytes · click and drag or Shift+arrows to select · right click "
                                   "to copy or save the selection · Ctrl+G go to · Ctrl+F find · F3 next"))
        lay.addWidget(bw)
        lay.addWidget(split, 1)
        lay.addWidget(self.status)

        self._actions()
        self._update_info()

    def _actions(self):
        def act(text, slot, key=None, ctx=Qt.WidgetWithChildrenShortcut):
            a = QAction(text, self)
            if key:
                a.setShortcut(QKeySequence(key))
                a.setShortcutContext(ctx)
            a.triggered.connect(slot)
            self.addAction(a)
            return a

        self.a_copy_hex = act("Copy as hex", lambda: self._copy("hex"), QKeySequence.Copy)
        self.a_copy_txt = act("Copy as text", lambda: self._copy("text"))
        self.a_copy_c = act("Copy as C array", lambda: self._copy("c"))
        self.a_copy_py = act("Copy as Python bytes", lambda: self._copy("py"))
        self.a_save = act("Save selection to file…", self.save_selection)
        self.a_goto = act("Go to…", lambda: (self.goto_edit.setFocus(), self.goto_edit.selectAll()), "Ctrl+G")
        self.a_find = act("Find…", lambda: (self.find_edit.setFocus(), self.find_edit.selectAll()), QKeySequence.Find)
        act("Find next", lambda: self.do_find(), "F3")
        act("Find previous", lambda: self.do_find(back=True), "Shift+F3")
        self.hex.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hex.customContextMenuRequested.connect(self._menu)

    def _menu(self, pos):
        m = QMenu(self)
        lo, hi = self.hex.sel()
        m.addSection(f"{hi - lo:,} bytes selected")
        for a in (self.a_copy_hex, self.a_copy_txt, self.a_copy_c, self.a_copy_py):
            m.addAction(a)
        m.addSeparator()
        m.addAction(self.a_save)
        m.addSeparator()
        m.addAction(self.a_goto)
        m.addAction(self.a_find)
        m.exec(self.hex.mapToGlobal(pos))

    def _copy(self, how: str):
        b = self.hex.selected()
        if how == "hex":
            s = " ".join(f"{x:02X}" for x in b)
        elif how == "text":
            s = "".join(chr(x) if 0x20 <= x < 0x7F or x in (9, 10, 13) else "." for x in b)
        elif how == "c":
            rows = [", ".join(f"0x{x:02X}" for x in b[i:i + 16]) for i in range(0, len(b), 16)]
            s = f"unsigned char data[{len(b)}] = {{\n    " + ",\n    ".join(rows) + "\n};"
        else:
            rows = ["".join(f"\\x{x:02x}" for x in b[i:i + 32]) for i in range(0, len(b), 32)]
            s = "data = (\n" + "\n".join(f'    b"{r}"' for r in rows) + "\n)"
        QGuiApplication.clipboard().setText(s)
        self.status.setText(f"Copied {len(b):,} bytes ({how})")

    def save_selection(self):
        lo, hi = self.hex.sel()
        name = f"{self.report['file']['name']}_0x{lo:x}-0x{hi:x}.bin"
        start = os.path.join(os.path.dirname(self.report["file"].get("path", "")), name)
        out, _ = QFileDialog.getSaveFileName(self, "Save selection", start, "Binary (*.bin);;All files (*)")
        if out:
            with open(out, "wb") as f:
                f.write(self.hex.selected())
            self.status.setText(f"Saved {hi - lo:,} bytes to {out}")

    def do_goto(self):
        # as in HxD numbers are always hex: "1000", "0x1000" and "1000h" are the same thing
        txt = self.goto_edit.text().strip().lower().removesuffix("h").removeprefix("0x")
        try:
            v = int(txt, 16)
        except ValueError:
            self.status.setText(f"Not a hex number: {self.goto_edit.text()}")
            return
        mode = self.goto_mode.currentText()
        off = v if mode == "Offset" else self.amap.rva_to_offset(v) if mode == "RVA" else self.amap.va_to_offset(v)
        if off is None or off >= len(self.hex.data):
            self.status.setText(f"{mode} 0x{v:x} is not stored in the file (outside sections or virtual-only data)")
            return
        self.hex.goto(off)

    def goto_va(self, va: int, length: int = 1) -> bool:
        off = self.amap.va_to_offset(va)
        if off is None:
            self.status.setText(f"VA 0x{va:x} is not stored in the file")
            return False
        self.hex.goto(off, length)
        return True

    def do_find(self, back: bool = False):
        try:
            rx = build_pattern(self.find_edit.text(), self.find_mode.currentData())
        except ValueError as e:
            self.status.setText(str(e))
            return
        if rx is None:
            return
        data = self.hex.data
        lo, _hi = self.hex.sel()
        m = None
        if back:
            last = None
            for x in rx.finditer(data, 0, max(0, lo)):
                last = x
            m = last
            if m is None:  # from the start, from the end
                for x in rx.finditer(data, lo + 1):
                    m = x
        else:
            m = rx.search(data, lo + 1) or rx.search(data, 0)
        if m is None:
            self.status.setText("Not found")
            return
        self.hex.goto(m.start(), max(1, m.end() - m.start()))
        wrapped = (m.start() <= lo) if not back else (m.start() >= lo)
        n = sum(1 for _ in rx.finditer(data)) if len(data) < 64 * 1024 * 1024 else None
        self.status.setText(self.status.text() + (f"   ·   match {self._idx(rx, m.start())} of {n}" if n else "")
                            + ("   ·   wrapped around" if wrapped else ""))

    def _idx(self, rx, start):
        return 1 + sum(1 for x in rx.finditer(self.hex.data, 0, start))

    def _update_info(self):
        h = self.hex
        lo, hi = h.sel()
        # with a selection its first byte counts (after a jump it is the start of the searched object)
        off = lo if hi - lo > 1 else h.cursor
        rva, where = self.amap.describe(off)
        va = f"0x{self.amap.base + rva:X}" if rva is not None else "-"
        rv = f"0x{rva:X}" if rva is not None else "-"
        sel = f"   selection 0x{lo:X}-0x{hi - 1:X} ({hi - lo:,} bytes)" if hi - lo > 1 else ""
        self.status.setText(f"offset 0x{off:X}   RVA {rv}   VA {va}   [{where}]{sel}")

        d = h.data[off:off + 8]
        self.insp.clear()

        def row(k, v):
            it = QTreeWidgetItem([k, v])
            it.setFont(1, mono_font())
            self.insp.addTopLevelItem(it)

        if not d:
            return
        b = d[0]
        row("Binary (8 bit)", f"{b:08b}")
        row("Int8", _fmt_int(struct.unpack("<b", d[:1])[0], 8))
        row("UInt8", _fmt_int(b, 8))
        for name, fmt, n in (("Int16", "<h", 2), ("UInt16", "<H", 2), ("Int32", "<i", 4), ("UInt32", "<I", 4),
                             ("Int64", "<q", 8), ("UInt64", "<Q", 8)):
            if len(d) >= n:
                row(name, _fmt_int(struct.unpack(fmt, d[:n])[0], n * 8))
        if len(d) >= 4:
            row("Float32", f"{struct.unpack('<f', d[:4])[0]:.6g}")
        if len(d) >= 8:
            row("Float64", f"{struct.unpack('<d', d[:8])[0]:.10g}")
        if len(d) >= 4:
            u32 = struct.unpack("<I", d[:4])[0]
            if 946684800 <= u32 <= 2208988800:
                row("Unix time (32)", _dt.datetime.fromtimestamp(u32, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        ptr_n = 8 if self.report["pe"]["format"] == "PE32+" else 4
        if len(d) >= ptr_n:
            ptr = int.from_bytes(d[:ptr_n], "little")
            o = self.amap.va_to_offset(ptr)
            if o is not None:
                _r, w = self.amap.describe(o)
                row("Pointer (VA)", f"0x{ptr:X} → {w}, offset 0x{o:X}")
            elif 0 < ptr < self.amap.base and self.amap.rva_to_offset(ptr) is not None:
                _r, w = self.amap.describe(self.amap.rva_to_offset(ptr))
                row("As RVA", f"0x{ptr:X} → {w}")
        tail = h.data[off:off + 96]
        asc = re.match(rb"[\x20-\x7e]{1,64}", tail)
        if asc:
            row("ASCII string", asc.group().decode())
        u16 = re.match(rb"(?:[\x20-\x7e]\x00){1,64}", tail)
        if u16 and len(u16.group()) >= 4:
            row("UTF-16 string", u16.group().decode("utf-16-le"))


def hex_page(report: dict) -> QWidget:
    path = report["file"].get("path", "")
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        lab = QLabel(f"The file is not available ({e}).\nThe hex view reads the original file from disk.")
        lab.setObjectName("muted")
        lab.setAlignment(Qt.AlignCenter)
        return lab
    if report["pe"].get("hashes", {}).get("sha256"):
        import hashlib
        if hashlib.sha256(data).hexdigest() != report["pe"]["hashes"]["sha256"]:
            lab = QLabel(f"{path} has changed since it was analyzed. Re-analyze it (F5) to see its bytes.")
            lab.setObjectName("muted")
            lab.setAlignment(Qt.AlignCenter)
            return lab
    return HexPage(report, data)
