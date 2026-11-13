"""Compare page: two open files side by side (ssdeep, imphash, Rich header, sections, imports, resources, strings)."""
from __future__ import annotations

import traceback

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QListWidget, QPushButton, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

from .theme import SEVERITY
from .widgets import Cell, make_table, title

GREEN, GREY = "#3fb950", "#8b949e"


def _sim_color(v):
    if v is None:
        return GREY
    return SEVERITY["high"] if v >= 70 else SEVERITY["medium"] if v >= 30 else GREY


class CompareThread(QThread):
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, ra, rb):
        super().__init__()
        self.ra, self.rb = ra, rb

    def run(self):
        try:
            from ..compare import compare
            from .resview import load_file
            self.done.emit(compare(self.ra, load_file(self.ra) or b"", self.rb, load_file(self.rb) or b""))
        except Exception:
            self.failed.emit(traceback.format_exc())


class ComparePage(QWidget):
    def __init__(self, reports: dict, a: str | None = None, b: str | None = None):
        super().__init__()
        self.reports = reports
        self.thread = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.addWidget(title("Compare two files"))
        bar = QHBoxLayout()
        self.ca, self.cb = QComboBox(), QComboBox()
        for c in (self.ca, self.cb):
            for path, rep in reports.items():
                c.addItem(rep["file"]["name"], path)
                c.setItemData(c.count() - 1, path, Qt.ToolTipRole)
            c.setMinimumWidth(220)
        paths = list(reports)
        self._select(self.ca, a or (paths[0] if paths else None))
        self._select(self.cb, b or next((p for p in paths if p != (a or paths[0])), None))
        swap = QPushButton("⇄")
        swap.setToolTip("Swap A and B")
        swap.setFixedWidth(36)
        swap.clicked.connect(self._swap)
        self.go = QPushButton("Compare")
        self.go.setDefault(True)
        self.go.clicked.connect(self.run)
        bar.addWidget(QLabel("A"))
        bar.addWidget(self.ca, 1)
        bar.addWidget(swap)
        bar.addWidget(QLabel("B"))
        bar.addWidget(self.cb, 1)
        bar.addWidget(self.go)
        lay.addLayout(bar)
        self.summary = QLabel("Choose two files and press Compare.")
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.summary)
        self.body = QWidget()
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.body, 1)
        if a and b and a != b:
            self.run()

    @staticmethod
    def _select(combo, path):
        i = combo.findData(path)
        if i >= 0:
            combo.setCurrentIndex(i)

    def _swap(self):
        a, b = self.ca.currentData(), self.cb.currentData()
        self._select(self.ca, b)
        self._select(self.cb, a)
        if self.body_lay.count():
            self.run()

    def run(self):
        a, b = self.ca.currentData(), self.cb.currentData()
        if not a or not b or a == b:
            self.summary.setText("Choose two different files.")
            return
        self.go.setEnabled(False)
        self.summary.setText("Comparing… (ssdeep of the file and of every section)")
        self.thread = CompareThread(self.reports[a], self.reports[b])
        self.thread.done.connect(self._show)
        self.thread.failed.connect(lambda msg: (self.summary.setText("Comparison failed:\n" + msg),
                                                self.go.setEnabled(True)))
        self.thread.start()

    def _show(self, c: dict):
        from ..compare import summary_lines
        self.go.setEnabled(True)
        while self.body_lay.count():
            w = self.body_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        lines = summary_lines(c)
        self.summary.setText(f"<b>A</b> = {c['a']} &nbsp;&nbsp; <b>B</b> = {c['b']}")
        self.body_lay.addWidget(self._cards(c, lines))
        notes = [x for x in lines if x.startswith(("Both", "Same Rich", "The two files", "Go function names"))]
        if notes:
            n = QLabel(" · ".join(notes))
            n.setObjectName("muted")
            n.setWordWrap(True)
            self.body_lay.addWidget(n)

        rows = []
        for f in c["overview"]:
            mark = "" if f["same"] is None else ("=" if f["same"] else "≠")
            rows.append([Cell(f["field"], bold=True), Cell(str(f["a"]), mono=True, full=str(f["a"])),
                         Cell(str(f["b"]), mono=True, full=str(f["b"])),
                         Cell(mark, color=GREEN if f["same"] else GREY)])
        ov = make_table(["", "A", "B", ""], rows)
        ov.setSortingEnabled(False)
        ov.setColumnWidth(0, 140)
        ov.setColumnWidth(1, 330)
        ov.setColumnWidth(2, 330)

        srows = []
        for r in c["sections"]:
            a, b = r["a"] or {}, r["b"] or {}
            sim_t = "identical" if r["identical"] else ("-" if r["similarity"] is None else f"{r['similarity']}/100")
            key = 101 if r["identical"] else (r["similarity"] if r["similarity"] is not None else -1)
            srows.append([Cell(r["name"], bold=True),
                          Cell(f"{a['raw_size']:,}" if a else "-", key=a.get("raw_size", -1)),
                          Cell(f"{b['raw_size']:,}" if b else "-", key=b.get("raw_size", -1)),
                          f"{a['entropy']:.2f}" if a else "-", f"{b['entropy']:.2f}" if b else "-",
                          a.get("flags", "-"), b.get("flags", "-"),
                          Cell(sim_t, key=key, color=GREEN if r["identical"] else _sim_color(r["similarity"]))])
        secs = make_table(["Section", "Size A", "Size B", "Entropy A", "Entropy B", "Flags A", "Flags B",
                           "Similarity (ssdeep)"], srows, right_cols=(1, 2, 3, 4, 7))

        tabs = QTabWidget()
        rrows = [[str(r["type"]), str(r["name"]), str(r["lang"] or ""),
                  Cell(f"{r['size_a']:,}" if r["size_a"] is not None else "-", key=r["size_a"] or -1),
                  Cell(f"{r['size_b']:,}" if r["size_b"] is not None else "-", key=r["size_b"] or -1),
                  Cell(r["state"], color=GREEN if r["state"] == "identical" else None)]
                 for r in c["resources"]]
        lists = [("imports", "Imports"), ("strings", "Interesting strings"), ("findings", "Findings")]
        if c.get("go_functions"):
            lists.insert(0, ("go_functions", "Go functions"))
        for key, label in lists:
            d = c[key]
            w = QSplitter(Qt.Horizontal)
            for side in ("a", "b"):
                box = QWidget()
                bl = QVBoxLayout(box)
                bl.setContentsMargins(0, 4, 0, 0)
                items = d[f"only_{side}"]
                bl.addWidget(QLabel(f"Only in {side.upper()} ({len(items)})"))
                lst = QListWidget()
                lst.addItems(items)
                bl.addWidget(lst)
                w.addWidget(box)
            if key == "findings" and d["common"]:
                box = QWidget()
                bl = QVBoxLayout(box)
                bl.setContentsMargins(0, 4, 0, 0)
                bl.addWidget(QLabel(f"In both ({len(d['common'])})"))
                lst = QListWidget()
                lst.addItems(d["common"])
                bl.addWidget(lst)
                w.addWidget(box)
            tabs.addTab(w, f"{label}  ({len(d['only_a'])} | {len(d['only_b'])})")
        if rrows:
            tabs.addTab(make_table(["Type", "Name", "Lang", "Size A", "Size B", "State"], rrows,
                                   right_cols=(3, 4)), f"Resources ({len(rrows)})")

        split = QSplitter(Qt.Vertical)
        split.setChildrenCollapsible(False)
        split.addWidget(ov)
        split.addWidget(secs)
        split.addWidget(tabs)
        # the overview all visible; the sections up to 8 rows; the tabs get the rest
        rh = ov.verticalHeader().defaultSectionSize()
        hh = ov.horizontalHeader().sizeHint().height()
        split.setSizes([hh + rh * ov.rowCount() + 6, hh + rh * min(max(secs.rowCount(), 3), 8) + 6, 300])
        self.body_lay.addWidget(split, 1)

    @staticmethod
    def _cards(c: dict, lines: list[str]) -> QWidget:
        """The results as a row of small cards (like the Overview), with the full sentence as tooltip."""
        def pct(v):
            return "-" if v is None else f"{v}%"

        same = {f["field"]: f["same"] for f in c["overview"]}
        secs = [r for r in c["sections"] if r["a"] and r["b"]]
        res = [r for r in c["resources"]]
        sim = c["ssdeep_similarity"]
        cards = [(f"{sim}/100" if sim is not None else "-", "ssdeep (whole file)", _sim_color(sim), "ssdeep"),
                 (f"{sum(r['identical'] for r in secs)}/{len(secs)}", "identical sections", None, "Sections"),
                 ("-" if c.get("dotnet") or same.get("imphash") is None else "same" if same["imphash"] else "different",
                  "imphash", GREEN if same.get("imphash") and not c.get("dotnet") else None, "imphash"),
                 (pct(c["imports"]["similarity"]), "imports in common", None, "Imports"),
                 (pct(c["strings"]["similarity"]), "strings in common", None, "Strings")]
        if res:
            cards.append((f"{sum(r['state'] == 'identical' for r in res)}/{len(res)}", "identical resources", None,
                          "Resources"))
        if c.get("go_functions"):
            cards.append((pct(c["go_functions"]["similarity"]), "Go functions in common", None, "Go functions"))
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        for value, label, color, key in cards:
            f = QFrame()
            f.setObjectName("card")
            v = QVBoxLayout(f)
            v.setContentsMargins(10, 5, 10, 5)
            v.setSpacing(0)
            n = QLabel(value)
            fn = n.font()
            fn.setPointSizeF(fn.pointSizeF() * 1.3)
            fn.setBold(True)
            n.setFont(fn)
            if color:
                n.setStyleSheet(f"color:{color}")
            t = QLabel(label)
            t.setObjectName("muted")
            v.addWidget(n)
            v.addWidget(t)
            f.setToolTip("\n".join(x for x in lines if x.lower().startswith(key.lower())) or label)
            h.addWidget(f, 1)
        return row
