"""Summary page of all the open files (batch analysis)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QVBoxLayout, QWidget

from .. import batch
from .theme import score_color
from .widgets import Cell, make_table, title


class SummaryPage(QWidget):
    def __init__(self, reports: dict, on_open, on_csv):
        super().__init__()
        rows, targets = [], []
        for path, rep in reports.items():
            r = batch.summary(rep)
            rows.append([Cell(r["file"], bold=True, tip=path), Cell(r["score"], key=r["score"],
                                                                     color=score_color(r["score"]), bold=True),
                         r["verdict"], r["type"], r["identified"], r["top_findings"], r["crypto"],
                         Cell(r["hidden_pe"], color="#e5534b" if r["hidden_pe"] else None),
                         r["yara"], r["attack"], Cell(r["imphash"], mono=True), Cell(r["sha256"], mono=True)])
            targets.append(path)
        self.table = make_table(["File", "Score", "Verdict", "Type", "Identified", "Top findings", "Crypto",
                                 "Hidden PE", "YARA", "ATT&CK", "Imphash", "SHA-256"], rows,
                                right_cols=(1,), targets=targets, on_activate=on_open)
        self.table.sortItems(1, Qt.DescendingOrder)
        for c, w in ((5, 380), (6, 160), (7, 200)):
            self.table.setColumnWidth(c, w)
        flt = QLineEdit()
        flt.setPlaceholderText("Filter by any column…")
        flt.textChanged.connect(self._filter)
        csv_b = QPushButton("Export CSV…")
        csv_b.clicked.connect(on_csv)
        bar = QHBoxLayout()
        bar.addWidget(flt, 1)
        bar.addWidget(csv_b)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        n_hi = sum(1 for r in reports.values() if r["score"]["score"] >= 60)
        lay.addWidget(title("Summary", f"{len(reports)} files · {n_hi} highly suspicious · "
                                       "double-click a row to open the file"))
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)

    def _filter(self, text: str):
        q = text.lower()
        t = self.table
        for r in range(t.rowCount()):
            hit = not q or any(q in (t.item(r, c).text().lower() if t.item(r, c) else "")
                               for c in range(t.columnCount()))
            t.setRowHidden(r, not hit)
