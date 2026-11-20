"""Main window: file/page tree on the left, page on the right, analysis in a separate thread."""
from __future__ import annotations

import io
import json
import os
import traceback

from PySide6.QtCore import QObject, QSettings, QSize, Qt, QThread, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QIcon, QKeySequence, QPainter, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QSplitter, QStackedWidget, QToolBar,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import __version__
from .. import batch, yara_scan
from . import pages
from .theme import apply_theme, score_color

ROLE_PATH = Qt.UserRole
ROLE_PAGE = Qt.UserRole + 1


def dot_icon(color: str) -> QIcon:
    pm = QPixmap(14, 14)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(2, 2, 10, 10)
    p.end()
    return QIcon(pm)


def app_icon() -> QIcon:
    """Icon drawn on the fly: a magnifying glass over a sheet."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        s = size / 64
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#2d333b"))
        p.drawRoundedRect(8 * s, 4 * s, 38 * s, 50 * s, 5 * s, 5 * s)
        p.setBrush(QColor("#539bf5"))
        for i, w in enumerate((26, 20, 24, 14)):
            p.drawRect(14 * s, (12 + i * 7) * s, w * s, 3 * s)
        from PySide6.QtGui import QPen
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor("#e5534b"), 6 * s, Qt.SolidLine, Qt.RoundCap))
        p.drawLine(48 * s, 48 * s, 58 * s, 58 * s)
        p.setPen(QPen(QColor("#f0f3f6"), 5 * s))
        p.setBrush(QColor(83, 155, 245, 70))
        p.drawEllipse(26 * s, 26 * s, 24 * s, 24 * s)
        p.end()
        icon.addPixmap(pm)
    return icon


class _NotesSignal(QObject):
    changed = Signal(str)                            # sha256 of a file whose AI notes changed (any thread)


class AnalyzeThread(QThread):
    progress = Signal(str)
    done = Signal(str, dict)
    failed = Signal(str, str)

    def __init__(self, path: str, code: bool, yara_paths: list[str] | None = None):
        super().__init__()
        self.path, self.code, self.yara_paths = path, code, yara_paths

    def run(self):
        try:
            if self.path.lower().endswith(".json"):
                with open(self.path, encoding="utf-8") as f:
                    rep = json.load(f)
                if not isinstance(rep, dict) or "pe" not in rep or "score" not in rep:
                    raise ValueError("not a PELens JSON report")
            else:
                from ..analyzer import analyze
                rep = analyze(self.path, code_analysis=self.code, progress=self.progress.emit,
                              yara_paths=self.yara_paths)
            self.done.emit(self.path, rep)
        except Exception as e:
            import pefile
            msg = f"Not a valid PE file: {e}" if isinstance(e, pefile.PEFormatError) else f"{type(e).__name__}: {e}"
            self.failed.emit(self.path, msg if isinstance(e, (pefile.PEFormatError, OSError, ValueError))
                             else msg + "\n\n" + traceback.format_exc())


class Welcome(QWidget):
    def __init__(self, open_cb):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addStretch(1)
        ic = QLabel()
        ic.setPixmap(app_icon().pixmap(96, 96))
        ic.setAlignment(Qt.AlignCenter)
        lay.addWidget(ic)
        t = QLabel(f"PELens {__version__}")
        t.setObjectName("pageTitle")
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)
        s = QLabel("Static PE analyzer for malware triage.\nDrop one or more files here, or open them.")
        s.setObjectName("muted")
        s.setAlignment(Qt.AlignCenter)
        lay.addWidget(s)
        b = QPushButton("Open file…")
        b.setFixedWidth(160)
        b.clicked.connect(open_cb)
        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(b)
        h.addStretch(1)
        lay.addLayout(h)
        lay.addStretch(2)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("PELens", "PELens")
        self.setWindowTitle(f"PELens {__version__}")
        self.setWindowIcon(app_icon())
        self.setAcceptDrops(True)
        self.reports: dict[str, dict] = {}
        self.page_cache: dict[tuple[str, str], QWidget] = {}
        self.queue: list[str] = []
        self.thread: AnalyzeThread | None = None

        self.nav = QTreeWidget()
        self.nav.setHeaderHidden(True)
        self.nav.setIndentation(14)
        self.nav.setMinimumWidth(200)
        self.nav.currentItemChanged.connect(self._on_nav)
        self.nav.setContextMenuPolicy(Qt.CustomContextMenu)
        self.nav.customContextMenuRequested.connect(self._nav_menu)
        self.stack = QStackedWidget()
        self.welcome = Welcome(self.open_dialog)
        self.stack.addWidget(self.welcome)
        split = QSplitter()
        split.addWidget(self.nav)
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setSizes([240, 1000])
        self.split = split
        self.setCentralWidget(split)

        self.status = QLabel("Ready")
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)
        self.busy.setMaximumWidth(160)
        self.busy.setVisible(False)
        self.statusBar().addWidget(self.status, 1)
        self.statusBar().addPermanentWidget(self.busy)

        self.bridge = None
        self.bridge_label = QLabel("")
        self.bridge_label.setObjectName("muted")
        self.statusBar().addPermanentWidget(self.bridge_label)
        from ..notes import STORE
        self.notes_signal = _NotesSignal()
        self.notes_signal.changed.connect(self._notes_changed)
        STORE.listeners.append(self.notes_signal.changed.emit)

        self._build_actions()
        self._restore()
        pages.JUMP = self.jump
        pages.CHOOSE_YARA = self.choose_yara

    # --- actions and menus ----------------------------------------------------------------------------

    def _build_actions(self):
        self.a_open = QAction("&Open…", self, shortcut=QKeySequence.Open,
                              triggered=self.open_dialog)
        self.a_open_dir = QAction("Open &folder…", self,
                                  shortcut=QKeySequence("Ctrl+Shift+O"), triggered=self.open_folder)
        self.a_summary = QAction("&Summary", self,
                                 shortcut=QKeySequence("Ctrl+T"), triggered=self.show_summary)
        self.a_csv = QAction("Export summary as &CSV…", self, triggered=self.export_csv)
        self.a_yara = QAction("&YARA rules folder…", self, triggered=self.choose_yara)
        self.a_reanalyze = QAction("&Re-analyze", self,
                                   shortcut=QKeySequence("F5"), triggered=self.reanalyze)
        self.a_json = QAction("Export &JSON…", self,
                              shortcut=QKeySequence.Save, triggered=self.export_json)
        self.a_html = QAction("Export &HTML report…", self, shortcut=QKeySequence("Ctrl+E"), triggered=self.export_html)
        self.a_close = QAction("&Close file", self,
                               shortcut=QKeySequence.Close, triggered=self.close_current)
        self.a_close_all = QAction("Close &all files", self, shortcut=QKeySequence("Ctrl+Shift+W"),
                                   triggered=self.close_all)
        self.a_compare = QAction("Co&mpare…", self,
                                 shortcut=QKeySequence("Ctrl+D"), triggered=lambda: self.show_compare())
        self.a_quit = QAction("&Quit", self, shortcut=QKeySequence.Quit, triggered=self.close)
        self.a_dark = QAction("&Dark theme", self, checkable=True, triggered=self._set_theme)
        self.a_about = QAction("&About PELens", self, triggered=self.about)
        self.a_unmap = QAction("&Rebuild PE from memory dump…", self, shortcut=QKeySequence("Ctrl+U"),
                               triggered=self.show_unmapper)
        self.a_ai_start = QAction("&Start AI bridge…", self, triggered=self.start_bridge)
        self.a_ai_stop = QAction("S&top AI bridge", self, triggered=self.stop_bridge)
        self.a_ai_cfg = QAction("&Configure the AI machine…", self, triggered=self.show_bridge_config)
        self.a_ai_save = QAction("Save &MCP server for the AI machine…", self, triggered=self.save_mcp_server)
        self.code_box = QCheckBox("Code analysis")
        self.code_box.setToolTip("Disassemble the code: stack strings, RC4/XOR routines, loader techniques.\n"
                                 "Turn off for a faster, structure-only analysis.")

        m = self.menuBar().addMenu("&File")
        m.addAction(self.a_open)
        m.addAction(self.a_open_dir)
        self.recent_menu = m.addMenu("Open &recent")
        m.addAction(self.a_reanalyze)
        m.addSeparator()
        m.addAction(self.a_json)
        m.addAction(self.a_html)
        m.addAction(self.a_csv)
        m.addSeparator()
        m.addAction(self.a_close)
        m.addAction(self.a_close_all)
        m.addAction(self.a_quit)
        v = self.menuBar().addMenu("&View")
        v.addAction(self.a_summary)
        v.addAction(self.a_compare)
        v.addAction(self.a_dark)
        o = self.menuBar().addMenu("&Options")
        o.addAction(self.a_yara)
        u = self.menuBar().addMenu("&Unmapper")
        u.addAction(self.a_unmap)
        ai = self.menuBar().addMenu("&AI")
        for a in (self.a_ai_start, self.a_ai_stop, None, self.a_ai_cfg, self.a_ai_save):
            ai.addSeparator() if a is None else ai.addAction(a)
        h = self.menuBar().addMenu("&Help")
        h.addAction(self.a_about)

        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for a in (self.a_open, self.a_open_dir, self.a_reanalyze, self.a_json, self.a_close, self.a_summary,
                  self.a_compare):
            tb.addAction(a)
        tb.addSeparator()
        tb.addWidget(self.code_box)
        self.addToolBar(tb)
        self._update_actions()

    _ICONS = {"a_open": "open", "a_open_dir": "open_folder", "a_summary": "summary", "a_csv": "csv", "a_yara": "yara",
              "a_reanalyze": "reanalyze", "a_json": "save", "a_html": "html", "a_close": "close",
              "a_close_all": "close_all", "a_compare": "compare", "a_quit": "quit", "a_dark": "theme",
              "a_about": "about", "a_unmap": "unmap"}

    def _apply_icons(self, dark: bool):
        """SVG icons in the colors of the theme (actions, recent files menu, page list)."""
        from . import icons
        for attr, name in self._ICONS.items():
            getattr(self, attr).setIcon(icons.icon(name, dark))
        self.recent_menu.setIcon(icons.icon("recent", dark))
        for i in range(self.nav.topLevelItemCount()):
            top = self.nav.topLevelItem(i)
            for j in range(top.childCount()):
                ch = top.child(j)
                key = ch.data(0, ROLE_PAGE)
                if key in icons.PATHS:
                    ch.setIcon(0, icons.icon(key, dark))

    def _restore(self):
        s = self.settings
        g = s.value("geometry")
        if g is not None:
            self.restoreGeometry(g)
        else:
            self.resize(1280, 820)
        dark = s.value("dark", True, type=bool)
        self.a_dark.setChecked(dark)
        self._apply_icons(dark)
        self.code_box.setChecked(s.value("code_analysis", True, type=bool))
        self._refresh_recent()

    def closeEvent(self, ev):
        self.stop_bridge()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("code_analysis", self.code_box.isChecked())
        if self.thread and self.thread.isRunning():
            self.queue.clear()
            self.thread.wait(3000)
        super().closeEvent(ev)

    def _set_theme(self, dark: bool):
        self.settings.setValue("dark", dark)
        apply_theme(QApplication.instance(), dark)
        self._apply_icons(dark)
        # pages use colors computed at creation: they are rebuilt
        self._drop_pages()
        self._on_nav(self.nav.currentItem(), None)

    def _drop_pages(self):
        for w in self.page_cache.values():
            self.stack.removeWidget(w)
            w.deleteLater()
        self.page_cache.clear()

    def _refresh_recent(self):
        self.recent_menu.clear()
        rec = [p for p in (self.settings.value("recent", [], type=list) or []) if p]
        for p in rec:
            self.recent_menu.addAction(p, lambda p=p: self.open_paths([p]))
        if rec:
            self.recent_menu.addSeparator()
            self.recent_menu.addAction("Clear list", self._clear_recent)
        self.recent_menu.setEnabled(bool(rec))

    def _clear_recent(self):
        self.settings.setValue("recent", [])
        self._refresh_recent()

    def _add_recent(self, path: str):
        rec = [p for p in (self.settings.value("recent", [], type=list) or []) if p and p != path]
        self.settings.setValue("recent", [path] + rec[:9])
        self._refresh_recent()

    def _update_actions(self):
        has = self._current_path() is not None
        for a in (self.a_reanalyze, self.a_json, self.a_html, self.a_close):
            a.setEnabled(has)
        self.a_summary.setEnabled(bool(self.reports))
        self.a_compare.setEnabled(len(self.reports) >= 2)
        self.a_close_all.setEnabled(bool(self.reports))
        self.a_csv.setEnabled(bool(self.reports))
        on = getattr(self, "bridge", None) is not None
        if hasattr(self, "a_ai_stop"):
            self.a_ai_start.setEnabled(not on)
            self.a_ai_stop.setEnabled(on)
            self.a_ai_cfg.setEnabled(on)

    # --- opening and analysis -----------------------------------------------------------------------

    def open_dialog(self):
        start = self.settings.value("last_dir", "")
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Open PE files", start,
            "PE files (*.exe *.dll *.sys *.ocx *.scr *.cpl *.drv *.efi *.bin *.mui);;"
            "PELens JSON report (*.json);;All files (*)")
        if paths:
            self.settings.setValue("last_dir", os.path.dirname(paths[0]))
            self.open_paths(paths)

    def open_paths(self, paths: list[str]):
        for p in paths:
            p = os.path.abspath(p)
            if os.path.isdir(p):
                continue
            if p not in self.queue:
                self.queue.append(p)
        self._next()

    def open_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Open a folder of PE files", self.settings.value("last_dir", ""))
        if not d:
            return
        self.settings.setValue("last_dir", d)
        rec = QMessageBox.question(self, "PELens", "Include subfolders?",
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes
        files = batch.collect([d], recursive=rec)
        if not files:
            QMessageBox.information(self, "PELens", "No PE files in this folder.")
            return
        self.batch_pending = len(files)
        self.open_paths(files)

    def choose_yara(self):
        cur = self.settings.value("yara_dir", "") or ""
        box = QMessageBox(self)
        box.setWindowTitle("YARA rules")
        found = yara_scan.rule_files(([cur] if cur else []) + yara_scan.default_paths())
        box.setText(f"Current folder: {cur or '(none)'}\n{len(found)} rule files will be used"
                    + ("" if yara_scan.available() else "\n\nyara-python is not installed."))
        box.setInformativeText("Rules are also read from the 'yara' folder next to pelens-gui.exe and from the "
                               "PELENS_YARA environment variable. Files that do not compile are skipped.")
        choose = box.addButton("Choose folder…", QMessageBox.AcceptRole)
        clear = box.addButton("Don't use a folder", QMessageBox.DestructiveRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is choose:
            d = QFileDialog.getExistingDirectory(self, "YARA rules folder", cur)
            if d:
                self.settings.setValue("yara_dir", d)
                self.status.setText(f"YARA rules: {len(yara_scan.rule_files([d]))} files in {d} (re-analyze with F5)")
        elif box.clickedButton() is clear:
            self.settings.setValue("yara_dir", "")

    def show_summary(self):
        if not self.reports:
            return
        from .summary import SummaryPage
        old = self.page_cache.pop(("*", "summary"), None)
        if old is not None:
            self.stack.removeWidget(old)
            old.deleteLater()
        w = SummaryPage(self.reports, self.select_file, self.export_csv)
        self.page_cache[("*", "summary")] = w
        self.stack.addWidget(w)
        self.nav.clearSelection()
        self.stack.setCurrentWidget(w)
        self.setWindowTitle(f"Summary of {len(self.reports)} files — PELens {__version__}")

    def show_compare(self, a: str | None = None, b: str | None = None):
        if len(self.reports) < 2:
            self.status.setText("Open at least two files to compare them.")
            return
        from .compare_page import ComparePage
        old = self.page_cache.pop(("*", "compare"), None)
        if old is not None:
            self.stack.removeWidget(old)
            old.deleteLater()
        w = ComparePage(self.reports, a or self._current_path(), b)
        self.page_cache[("*", "compare")] = w
        self.stack.addWidget(w)
        self.nav.clearSelection()
        self.nav.setCurrentItem(None)
        self.stack.setCurrentWidget(w)
        self.setWindowTitle(f"Compare — PELens {__version__}")

    def _nav_menu(self, pos):
        """Right click on a file: close, re-analyze, compare, copy, open the folder."""
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtWidgets import QMenu
        it = self.nav.itemAt(pos)
        if it is None:
            return
        top = it if it.parent() is None else it.parent()
        path = top.data(0, ROLE_PATH)
        rep = self.reports.get(path)
        if rep is None:
            return
        self.nav.setCurrentItem(it)
        m = QMenu(self)
        m.addAction(self.a_reanalyze)
        others = [(p, r) for p, r in self.reports.items() if p != path]
        cm = m.addMenu("Compare with")
        cm.setEnabled(bool(others))
        for p, r in others:
            cm.addAction(r["file"]["name"], lambda p=p: self.show_compare(path, p)).setToolTip(p)
        m.addSeparator()
        clip = QApplication.clipboard()
        m.addAction("Copy path", lambda: clip.setText(path))
        m.addAction("Copy SHA-256", lambda: clip.setText(rep["pe"]["hashes"]["sha256"]))
        if rep["pe"]["hashes"].get("ssdeep"):
            m.addAction("Copy ssdeep", lambda: clip.setText(rep["pe"]["hashes"]["ssdeep"]))
        folder = os.path.dirname(path)
        a = m.addAction("Open containing folder",
                        lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(folder)))
        a.setEnabled(os.path.isdir(folder))
        m.addSeparator()
        m.addAction(self.a_json)
        m.addAction(self.a_html)
        m.addSeparator()
        m.addAction(self.a_close)
        m.addAction(self.a_close_all)
        m.exec(self.nav.viewport().mapToGlobal(pos))

    def show_unmapper(self):
        from .unmap_page import UnmapperPage
        w = self.page_cache.get(("*", "unmapper"))
        if w is None:
            w = UnmapperPage(self.settings, lambda p: self.open_paths([p]))
            self.page_cache[("*", "unmapper")] = w
            self.stack.addWidget(w)
        self.nav.clearSelection()
        self.nav.setCurrentItem(None)
        self.stack.setCurrentWidget(w)
        self.setWindowTitle(f"Unmapper — PELens {__version__}")
        return w

    def select_file(self, path: str):
        for i in range(self.nav.topLevelItemCount()):
            top = self.nav.topLevelItem(i)
            if top.data(0, ROLE_PATH) == path:
                self.nav.setCurrentItem(top.child(0) or top)
                return

    def export_csv(self):
        if not self.reports:
            return
        out, _ = QFileDialog.getSaveFileName(self, "Export summary", os.path.join(
            self.settings.value("last_export_dir", "") or "", "pelens_summary.csv"), "CSV (*.csv)")
        if out:
            self.settings.setValue("last_export_dir", os.path.dirname(out))
            batch.write_csv([batch.summary(r) for r in self.reports.values()], out)
            self.status.setText(f"Summary of {len(self.reports)} files saved to {out}")

    def reanalyze(self):
        p = self._current_path()
        if p:
            self.open_paths([p])

    def _next(self):
        if self.thread and self.thread.isRunning():
            return
        if not self.queue:
            self.busy.setVisible(False)
            if getattr(self, "batch_pending", 0):
                self.batch_pending = 0
                self.show_summary()
            self._update_actions()
            return
        path = self.queue.pop(0)
        self.busy.setVisible(True)
        left = f" ({len(self.queue) + 1} left)" if self.queue else ""
        self.status.setText(f"Analyzing {os.path.basename(path)}…{left}")
        yp = self.settings.value("yara_dir", "") or ""
        self.thread = AnalyzeThread(path, self.code_box.isChecked(), ([yp] + yara_scan.default_paths()) if yp else None)
        self.thread.progress.connect(lambda m, n=os.path.basename(path): self.status.setText(f"{n}: {m}"))
        self.thread.done.connect(self._done)
        self.thread.failed.connect(self._failed)
        self.thread.finished.connect(self._next)
        self.thread.start()

    def _done(self, path: str, report: dict):
        self.reports[path] = report
        for k in [k for k in self.page_cache if k[0] == path]:
            w = self.page_cache.pop(k)
            self.stack.removeWidget(w)
            w.deleteLater()
        self._add_nav(path, report)
        self._add_recent(path)
        t = sum((report.get("timings") or {}).values())
        sc = report["score"]
        self.status.setText(f"{report['file']['name']}: {sc['score']}/100, {sc['verdict']} ({t:.2f} s)")
        for e in report.get("errors") or []:
            self.status.setText(self.status.text() + f" · error: {e}")

    def _failed(self, path: str, msg: str):
        self.status.setText(f"{os.path.basename(path)}: analysis failed")
        if getattr(self, "batch_pending", 0):
            # analysis of a folder: no error dialogs, the error is recorded and we go on
            self.batch_errors = getattr(self, "batch_errors", []) + [(path, msg.split("\n\n")[0])]
            return
        box = QMessageBox(QMessageBox.Warning, "PELens", f"Could not analyze {os.path.basename(path)}.", parent=self)
        first, _, rest = msg.partition("\n\n")
        box.setInformativeText(first)
        if rest:
            box.setDetailedText(rest)
        box.exec()

    # --- navigation ------------------------------------------------------------------------------

    def _add_nav(self, path: str, report: dict):
        existing = None
        for i in range(self.nav.topLevelItemCount()):
            if self.nav.topLevelItem(i).data(0, ROLE_PATH) == path:
                existing = self.nav.topLevelItem(i)
        sc = report["score"]
        top = existing or QTreeWidgetItem()
        top.takeChildren()
        top.setText(0, f"{report['file']['name']}   {sc['score']}")
        top.setIcon(0, dot_icon(score_color(sc["score"])))
        top.setToolTip(0, f"{path}\n{sc['score']}/100 — {sc['verdict']}")
        top.setData(0, ROLE_PATH, path)
        top.setData(0, ROLE_PAGE, "overview")
        f = top.font(0)
        f.setBold(True)
        top.setFont(0, f)
        for key, label, _builder, cond in pages.PAGES:
            if not cond(report):
                continue
            ch = QTreeWidgetItem([pages.page_label(report, key, label)])
            ch.setData(0, ROLE_PATH, path)
            ch.setData(0, ROLE_PAGE, key)
            from . import icons
            if key in icons.PATHS:
                ch.setIcon(0, icons.icon(key, self.a_dark.isChecked()))
            col = pages.page_color(report, key)
            if col:
                ch.setForeground(0, QBrush(QColor(col)))
            top.addChild(ch)
        if not existing:
            self.nav.addTopLevelItem(top)
        if getattr(self, "batch_pending", 0):
            # analysis of a folder: the tree stays collapsed, the summary opens at the end
            top.setExpanded(False)
            return
        for i in range(self.nav.topLevelItemCount()):
            other = self.nav.topLevelItem(i)
            if other is not top and self.nav.topLevelItemCount() > 3:
                other.setExpanded(False)
        top.setExpanded(True)
        self.nav.setCurrentItem(top.child(0))
        self._on_nav(self.nav.currentItem(), None)

    def _current_path(self) -> str | None:
        it = self.nav.currentItem()
        return it.data(0, ROLE_PATH) if it else None

    def _on_nav(self, cur, _prev):
        self._update_actions()
        if cur is None:
            self.stack.setCurrentWidget(self.welcome)
            self.setWindowTitle(f"PELens {__version__}")
            return
        path, key = cur.data(0, ROLE_PATH), cur.data(0, ROLE_PAGE)
        (cur if cur.parent() is None else cur.parent()).setExpanded(True)
        rep = self.reports.get(path)
        if rep is None:
            return
        if cur.parent() is None:
            key = "overview"
        w = self.page_cache.get((path, key))
        if w is None:
            builder = next(b for k, _l, b, _c in pages.PAGES if k == key)
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                w = builder(rep)
            except Exception:
                w = QLabel("Could not build this page:\n\n" + traceback.format_exc())
                w.setTextInteractionFlags(Qt.TextSelectableByMouse)
            finally:
                QApplication.restoreOverrideCursor()
            self.page_cache[(path, key)] = w
            self.stack.addWidget(w)
        self.stack.setCurrentWidget(w)
        self.setWindowTitle(f"{rep['file']['name']} — PELens {__version__}")

    def jump(self, report: dict, kind: str, value: int, length: int = 1):
        """Opens the hex view of the file the report belongs to, at the given place."""
        from .hexview import HexPage
        path = next((p for p, r in self.reports.items() if r is report), None)
        if path is None:
            return
        target = None
        for i in range(self.nav.topLevelItemCount()):
            top = self.nav.topLevelItem(i)
            if top.data(0, ROLE_PATH) == path:
                target = next((top.child(j) for j in range(top.childCount())
                               if top.child(j).data(0, ROLE_PAGE) == "hex"), None)
        if target is None:
            return
        self.nav.setCurrentItem(target)
        page = self.page_cache.get((path, "hex"))
        if not isinstance(page, HexPage):
            return
        if kind == "offset":
            page.hex.goto(value, length)
        elif kind == "va":
            page.goto_va(value, length)
        elif kind == "rva":
            off = page.amap.rva_to_offset(value)
            if off is None:
                page.status.setText(f"RVA 0x{value:x} is not stored in the file")
            else:
                page.hex.goto(off, length)

    def close_current(self):
        it = self.nav.currentItem()
        if not it:
            return
        self._close_item(it if it.parent() is None else it.parent())

    def close_all(self):
        while self.nav.topLevelItemCount():
            self._close_item(self.nav.topLevelItem(0))
        for k in [k for k in self.page_cache if k[0] == "*" and k[1] in ("summary", "compare")]:
            w = self.page_cache.pop(k)
            self.stack.removeWidget(w)
            w.deleteLater()
        self.stack.setCurrentWidget(self.welcome)
        self.setWindowTitle(f"PELens {__version__}")

    def _close_item(self, top):
        path = top.data(0, ROLE_PATH)
        for k in [k for k in self.page_cache if k[0] == path]:
            w = self.page_cache.pop(k)
            self.stack.removeWidget(w)
            w.deleteLater()
        self.reports.pop(path, None)
        self.nav.takeTopLevelItem(self.nav.indexOfTopLevelItem(top))
        if self.nav.topLevelItemCount() == 0:
            self.stack.setCurrentWidget(self.welcome)
        self._update_actions()

    # --- export -----------------------------------------------------------------------------

    def _save_name(self, ext: str, filt: str) -> str | None:
        path = self._current_path()
        rep = self.reports.get(path)
        if not rep:
            return None
        start = os.path.join(self.settings.value("last_export_dir", os.path.dirname(path)) or "",
                             f"{rep['file']['name']}.pelens.{ext}")
        out, _ = QFileDialog.getSaveFileName(self, "Export", start, filt)
        if out:
            self.settings.setValue("last_export_dir", os.path.dirname(out))
        return out or None

    def export_json(self):
        out = self._save_name("json", "JSON (*.json)")
        if out:
            rep = dict(self.reports[self._current_path()])
            from ..notes import STORE
            notes = STORE.get(rep["pe"]["hashes"]["sha256"])
            if notes:
                rep["ai_notes"] = notes
            with open(out, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2, ensure_ascii=False)
            self.status.setText(f"Report saved to {out}")

    def export_html(self):
        out = self._save_name("html", "HTML (*.html)")
        if not out:
            return
        from rich.console import Console
        from ..cli import render
        con = Console(record=True, width=160, file=io.StringIO(), force_terminal=True, color_system="truecolor")
        render(self.reports[self._current_path()], con)
        with open(out, "w", encoding="utf-8") as f:
            f.write(con.export_html(inline_styles=True))
        self.status.setText(f"HTML report saved to {out}")

    # --- AI bridge ---------------------------------------------------------------------------------------

    def start_bridge(self):
        from ..bridge import Bridge, local_addresses
        from .ai_page import BridgeDialog
        if self.bridge is not None:
            self.show_bridge_config()
            return
        dlg = BridgeDialog(self, self.settings, local_addresses())
        if dlg.exec() != BridgeDialog.Accepted:
            return
        try:
            b = Bridge(lambda: dict(self.reports), dlg.host.currentText().strip(), dlg.port.value(),
                       dlg.token.text().strip(), dlg.client.text().strip())
            b.start()
        except OSError as e:
            QMessageBox.warning(self, "PELens", f"Cannot start the AI bridge on {dlg.host.currentText()}:"
                                                f"{dlg.port.value()}:\n{e}")
            return
        self.bridge = b
        self.bridge_label.setText(f"AI bridge: {b.url}")
        self._update_actions()
        self.show_bridge_config()

    def stop_bridge(self):
        if self.bridge is not None:
            self.bridge.stop()
            self.bridge = None
            self.bridge_label.setText("")
            self._update_actions()

    def show_bridge_config(self):
        from .ai_page import ClientConfigDialog
        if self.bridge is None:
            QMessageBox.information(self, "PELens", "Start the AI bridge first (AI → Start AI bridge).")
            return
        ClientConfigDialog(self, self.bridge.url, self.bridge.token).exec()

    def save_mcp_server(self):
        """Writes the MCP server (and its configuration, when the bridge runs) for the AI machine."""
        import shutil
        from .ai_page import mcp_script_path
        out = QFileDialog.getExistingDirectory(self, "Folder to copy to the AI machine")
        if not out:
            return
        src = mcp_script_path()
        shutil.copy2(src, os.path.join(out, "pelens_mcp.py"))
        readme = os.path.join(os.path.dirname(src), "README.md")
        if os.path.exists(readme):
            shutil.copy2(readme, os.path.join(out, "README.md"))
        if self.bridge is not None:
            with open(os.path.join(out, "pelens-mcp.json"), "w", encoding="utf-8") as fh:
                json.dump(self.bridge.client_config(), fh, indent=2)
        self.status.setText(f"MCP server saved to {out}" + ("" if self.bridge else
                                                             " (start the AI bridge to also write pelens-mcp.json)"))

    def _notes_changed(self, sha: str):
        """An AI note arrived (from the bridge thread) or was edited: refresh the AI Notes page of that file."""
        cur = self.nav.currentItem()
        for path, rep in self.reports.items():
            if rep.get("pe", {}).get("hashes", {}).get("sha256") != sha:
                continue
            w = self.page_cache.pop((path, "ai_notes"), None)
            showing = w is not None and self.stack.currentWidget() is w
            for i in range(self.nav.topLevelItemCount()):
                top = self.nav.topLevelItem(i)
                if top.data(0, ROLE_PATH) != path:
                    continue
                for j in range(top.childCount()):
                    ch = top.child(j)
                    if ch.data(0, ROLE_PAGE) == "ai_notes":
                        ch.setText(0, pages.page_label(rep, "ai_notes", None))
            if showing:
                self._on_nav(cur, None)
            if w is not None:
                self.stack.removeWidget(w)
                w.deleteLater()
            self.status.setText(f"AI notes of {rep['file']['name']} updated")

    def about(self):
        QMessageBox.about(self, "About PELens",
                          f"<h3>PELens {__version__}</h3><p>Static PE analyzer for malware triage: structure, "
                          "entropy, strings, crypto detection, loader techniques, .NET metadata and a "
                          "suspicion score.</p><p>Nothing is executed or decrypted.</p>"
                          "<p>Made by <b>FzRsLLaSheR</b></p>"
                          "<p style='color:gray'>Fonts: Inter and JetBrains Mono (SIL Open Font License 1.1).</p>")

    # --- drag & drop ------------------------------------------------------------------------------

    def dragEnterEvent(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        paths = [u.toLocalFile() for u in ev.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.open_paths(paths)
