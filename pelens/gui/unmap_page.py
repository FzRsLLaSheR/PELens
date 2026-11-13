"""The "Unmapper" page: rebuilds a PE dumped from memory."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QSplitter, QTextBrowser, QVBoxLayout, QWidget)

from .. import unmapper
from .theme import GOOD, SEVERITY
from .widgets import Cell, make_table, mono_font, title


def _hex(text: str) -> int | None:
    t = text.strip().lower().removeprefix("0x").removesuffix("h").replace("`", "")
    return int(t, 16) if t else None


class UnmapperPage(QWidget):
    def __init__(self, settings, on_analyze):
        super().__init__()
        self.settings = settings
        self.on_analyze = on_analyze
        self.result: unmapper.UnmapResult | None = None
        self.setAcceptDrops(True)

        self.dump_edit = QLineEdit()
        self.dump_edit.setPlaceholderText("Memory dump (.bin, .dmp, .exe…) — or drop it on this page")
        b1 = QPushButton("Browse…")
        b1.clicked.connect(lambda: self._browse(self.dump_edit, "Open a memory dump"))
        self.ref_edit = QLineEdit()
        self.ref_edit.setPlaceholderText("Optional: original file to take the PE headers from (if the dump's headers were wiped)")
        b2 = QPushButton("Browse…")
        b2.clicked.connect(lambda: self._browse(self.ref_edit, "File with the original headers"))

        self.mode = QComboBox()
        self.mode.addItem("Auto", "auto")
        self.mode.addItem("Unmap — sections at the raw offsets of the headers", "unmap")
        self.mode.addItem("Realign — raw = virtual (robust with damaged headers)", "realign")
        self.layout_box = QComboBox()
        self.layout_box.addItem("Auto-detect", "auto")
        self.layout_box.addItem("Mapped (dumped from memory)", "mapped")
        self.layout_box.addItem("Raw (file layout)", "raw")
        self.load_base = QLineEdit()
        self.load_base.setPlaceholderText("auto (from the relocations)")
        self.new_base = QLineEdit()
        self.new_base.setPlaceholderText("same as the load base (addresses match the debugger)")
        self.iat = QCheckBox("Restore the IAT from the import name table (OriginalFirstThunk)")
        self.iat.setChecked(True)
        for w in (self.load_base, self.new_base):
            w.setFont(mono_font())
            w.setMaximumWidth(360)

        form = QFormLayout()
        r1 = QHBoxLayout()
        r1.addWidget(self.dump_edit, 1)
        r1.addWidget(b1)
        r2 = QHBoxLayout()
        r2.addWidget(self.ref_edit, 1)
        r2.addWidget(b2)
        form.addRow("Dump", r1)
        form.addRow("Headers from", r2)
        form.addRow("Mode", self.mode)
        form.addRow("Dump layout", self.layout_box)
        form.addRow("Load base", self.load_base)
        form.addRow("New ImageBase", self.new_base)
        form.addRow("", self.iat)
        box = QGroupBox("Input and options")
        box.setLayout(form)

        self.run_b = QPushButton("Rebuild")
        self.run_b.setDefault(True)
        self.run_b.clicked.connect(self.rebuild)
        self.save_b = QPushButton("Save as…")
        self.save_b.clicked.connect(lambda: self.save(False))
        self.an_b = QPushButton("Save and analyze")
        self.an_b.clicked.connect(lambda: self.save(True))
        for b in (self.save_b, self.an_b):
            b.setEnabled(False)
        bar = QHBoxLayout()
        bar.addWidget(self.run_b)
        bar.addStretch(1)
        bar.addWidget(self.save_b)
        bar.addWidget(self.an_b)

        self.log = QTextBrowser()
        self.log.setPlaceholderText("Choose a dump and press Rebuild.")
        self.table_box = QVBoxLayout()
        tw = QWidget()
        tw.setLayout(self.table_box)
        self.table_box.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.log)
        split.addWidget(tw)
        split.setSizes([180, 260])

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.addWidget(title("Unmapper", "Rebuild a PE file dumped from memory (x64dbg, Process Hacker…): "
                                        "sections back to the file layout, base fixed with the relocations, IAT "
                                        "restored. Nothing is executed."))
        lay.addWidget(box)
        lay.addLayout(bar)
        lay.addWidget(split, 1)
        self.dump_edit.returnPressed.connect(self.rebuild)

    # --- input ------------------------------------------------------------------------------------

    def _browse(self, edit: QLineEdit, caption: str):
        start = self.settings.value("last_dir", "")
        path, _ = QFileDialog.getOpenFileName(self, caption, start, "All files (*)")
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
            edit.setText(path)
            if edit is self.dump_edit:
                self.rebuild()

    def set_dump(self, path: str):
        self.dump_edit.setText(path)
        self.rebuild()

    def dragEnterEvent(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        urls = [u.toLocalFile() for u in ev.mimeData().urls() if u.isLocalFile()]
        if urls:
            ev.acceptProposedAction()
            self.set_dump(urls[0])

    # --- rebuilding ----------------------------------------------------------------------------

    def _error(self, msg: str):
        self.result = None
        self.log.setHtml(f"<p style='color:{SEVERITY['high']}'><b>Cannot rebuild the dump:</b> {msg}</p>")
        for b in (self.save_b, self.an_b):
            b.setEnabled(False)

    def rebuild(self):
        path = self.dump_edit.text().strip()
        if not path:
            return
        try:
            data = open(path, "rb").read()
            ref = open(self.ref_edit.text().strip(), "rb").read() if self.ref_edit.text().strip() else None
            r = unmapper.unmap(data, mode=self.mode.currentData(), layout=self.layout_box.currentData(),
                               load_base=_hex(self.load_base.text()), new_base=_hex(self.new_base.text()),
                               restore_imports=self.iat.isChecked(), headers_from=ref)
        except ValueError as e:
            self._error(str(e))
            return
        except OSError as e:
            self._error(f"cannot read the file: {e}")
            return
        self.result = r
        items = "".join(f"<li>{line}</li>" for line in r.log)
        warns = "".join(f"<li style='color:{SEVERITY['medium']}'>{w}</li>" for w in r.warnings)
        self.log.setHtml(f"<p><b style='color:{GOOD}'>Rebuilt</b> — {os.path.basename(path)}: {r.layout} dump, "
                         f"mode <b>{r.mode}</b>, ImageBase <code>0x{r.image_base:x}</code></p><ul>{items}{warns}</ul>")
        while self.table_box.count():
            w = self.table_box.takeAt(0).widget()
            if w:
                w.deleteLater()
        rows = []
        for s in r.sections:
            moved = s["new_raw_ptr"] != s["raw_ptr"] or s["new_raw_size"] != s["raw_size"]
            col = SEVERITY["medium"] if moved else None
            rows.append([Cell(s["name"], bold=True), Cell(f"0x{s['va']:x}", key=s["va"], mono=True),
                         Cell(f"0x{s['vsize']:x}", key=s["vsize"], mono=True),
                         Cell(f"0x{s['raw_ptr']:x}", key=s["raw_ptr"], mono=True),
                         Cell(f"0x{s['raw_size']:x}", key=s["raw_size"], mono=True),
                         Cell(f"0x{s['new_raw_ptr']:x}", key=s["new_raw_ptr"], mono=True, color=col),
                         Cell(f"0x{s['new_raw_size']:x}", key=s["new_raw_size"], mono=True, color=col)])
        self.table_box.addWidget(QLabel("<b>Sections</b> (raw offset and size in the dump's headers → in the rebuilt file)"))
        self.table_box.addWidget(make_table(["Name", "VA", "Virtual size", "Raw offset", "Raw size",
                                             "New raw offset", "New raw size"], rows))
        for b in (self.save_b, self.an_b):
            b.setEnabled(True)

    def save(self, analyze: bool):
        if not self.result:
            return
        src = self.dump_edit.text().strip()
        base, _ext = os.path.splitext(src)
        start = f"{base}_unmapped.{'dll' if src.lower().endswith('.dll') else 'exe'}"
        out, _ = QFileDialog.getSaveFileName(self, "Save the rebuilt PE", start, "PE files (*.exe *.dll);;All files (*)")
        if not out:
            return
        with open(out, "wb") as f:
            f.write(self.result.data)
        self.log.append(f"<p>Saved to <code>{out}</code></p>")
        if analyze:
            self.on_analyze(out)
