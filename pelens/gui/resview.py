"""Resource preview: images (icons, bitmaps, PNGs in .NET resources), text, string tables, hex."""
from __future__ import annotations

import hashlib

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QScrollArea, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import resdata
from .widgets import mono_font

HEX_PREVIEW = 4096


def load_file(report: dict) -> bytes | None:
    """The bytes of the analyzed file, only if it is still the same file (same SHA-256)."""
    try:
        with open(report["file"].get("path", ""), "rb") as f:
            data = f.read()
    except OSError:
        return None
    want = report["pe"].get("hashes", {}).get("sha256")
    if want and hashlib.sha256(data).hexdigest() != want:
        return None
    return data


def hexdump(blob: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(blob), 16):
        ch = blob[i:i + 16]
        lines.append(f"{base + i:08x}  {ch.hex(' '):<47}  " + "".join(chr(b) if 32 <= b < 127 else "." for b in ch))
    return "\n".join(lines)


class ResourcePreview(QWidget):
    """Panel on the right of the resource table."""

    def __init__(self, report: dict, data: bytes | None, on_hex=None):
        super().__init__()
        self.report, self.data, self.on_hex = report, data, on_hex
        self.target = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 0, 0, 0)
        head = QHBoxLayout()
        self.info = QLabel("Select a resource to preview it.")
        self.info.setObjectName("muted")
        self.info.setWordWrap(True)
        self.info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        head.addWidget(self.info, 1)
        self.hex_btn = QPushButton("Open in hex view")
        self.hex_btn.setEnabled(False)
        self.hex_btn.clicked.connect(lambda: self.on_hex and self.target and self.on_hex(self.target))
        head.addWidget(self.hex_btn, 0, Qt.AlignTop)
        lay.addLayout(head)
        self.notes = QLabel()
        self.notes.setWordWrap(True)
        self.notes.setVisible(False)
        lay.addWidget(self.notes)

        self.stack = QStackedWidget()
        self.image = QLabel()
        self.image.setAlignment(Qt.AlignCenter)
        # dark background to see transparency
        self.image.setStyleSheet("QLabel { background-color: #2b2b2b; }")
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setWidget(self.image)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(mono_font())
        self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.empty = QLabel("" if data is not None else
                            "The file is not available or has changed since it was analyzed: no preview.")
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignCenter)
        for w in (self.empty, sa, self.text):
            self.stack.addWidget(w)
        lay.addWidget(self.stack, 1)

    def _blob(self, offset, size) -> bytes:
        if self.data is None or offset is None:
            return b""
        return self.data[offset:offset + size]

    def _set_notes(self, notes):
        self.notes.setText("<br>".join(f"• {n}" for n in notes))
        self.notes.setVisible(bool(notes))

    def show_pe_resource(self, res: dict, all_res: list):
        idx = {(r["type"], str(r["name"])): r for r in all_res}

        def read(t, n):
            r = idx.get((t, n))
            return self._blob(r["offset"], r["size"]) if r else None

        blob = self._blob(res["offset"], res["size"])
        p = resdata.preview(res, blob, read, self.report["pe"].get("version_info")) if blob else None
        self._show(f"{res['type']} / {res['name']} · lang {res['lang']} · {res['size']:,} bytes at 0x{res['offset']:x}",
                   p, blob, res["offset"], res["size"])

    def show_blob(self, label: str, offset: int | None, size: int):
        blob = self._blob(offset, size)
        p = None
        if blob:
            fmt = resdata.image_format(blob)
            if fmt:
                p = {"kind": "image", "data": blob, "format": fmt, "notes": []}
            else:
                t = resdata.decode_text(blob) if len(blob) <= 1 << 20 else None
                p = {"kind": "text", "data": t, "format": "text", "notes": []} if t else \
                    {"kind": "hex", "data": blob, "format": "", "notes": []}
        where = f" at 0x{offset:x}" if offset is not None else ""
        self._show(f"{label} · {size:,} bytes{where}", p, blob, offset, size)

    def _show(self, info, p, blob, offset, size):
        self.target = ("offset", offset, size) if offset is not None else None
        self.hex_btn.setEnabled(self.target is not None and self.on_hex is not None)
        if p is None:
            self.info.setText(info)
            self._set_notes([])
            self.stack.setCurrentWidget(self.empty)
            return
        notes = list(p.get("notes") or [])
        if p["kind"] == "image":
            img = QImage.fromData(p["data"])
            if not img.isNull():
                pm = QPixmap.fromImage(img)
                # small icons enlarged (without smoothing) to see them
                if pm.width() <= 64 and pm.height() <= 64:
                    pm = pm.scaled(pm.width() * 4, pm.height() * 4, Qt.KeepAspectRatio, Qt.FastTransformation)
                self.image.setPixmap(pm)
                self.info.setText(f"{info} · {p['format']} {img.width()}x{img.height()}, {img.depth()} bit")
                self._set_notes(notes)
                self.stack.setCurrentIndex(1)
                return
            notes.append(f"{p['format']} header found but the image cannot be decoded")
        if p["kind"] == "text":
            self.text.setPlainText(p["data"])
            self.info.setText(f"{info} · {p['format']}")
        else:
            more = f"\n… {len(blob) - HEX_PREVIEW:,} more bytes: open it in the hex view" if len(blob) > HEX_PREVIEW else ""
            self.text.setPlainText(hexdump(blob[:HEX_PREVIEW], offset or 0) + more)
            self.info.setText(info)
        self._set_notes(notes)
        self.stack.setCurrentWidget(self.text)
