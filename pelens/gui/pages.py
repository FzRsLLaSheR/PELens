"""The GUI pages: each one is a function that takes the report and returns a widget."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Callable

import yaml
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QScrollArea, QSplitter, QTableView,
                               QTableWidgetItem, QTextBrowser, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..scoring import DEFAULT_RULES
from ..strings import SUSPICIOUS_TAGS
from .hexview import hex_page
from .theme import CONFIDENCE, GOOD, SEV_LABEL, SEVERITY, STACK, score_color
from .widgets import (Cell, EntropyChart, ScoreGauge, card, hx, install_copy, make_table, make_tree, mono_font,
                      title, visible)

# set by the window: JUMP(report, kind, value, length) opens the hex view
# at a file offset ("offset"), an RVA ("rva") or a VA ("va")
JUMP = None


def jump(report: dict, kind: str, value, length: int = 1) -> None:
    if JUMP is not None and value is not None:
        JUMP(report, kind, value, length)


def _chart(report: dict) -> EntropyChart:
    c = EntropyChart(report)
    c.on_click = lambda off: jump(report, "offset", off)
    return c


HINT = "Double-click a row to open it in the hex view."

CAT_LABEL = {"stream_cipher": "stream cipher", "block_cipher": "block cipher", "asymmetric": "asymmetric",
             "hash": "hash", "checksum": "checksum", "encoding": "encoding", "xor": "XOR obfuscation",
             "payload": "loader", "compression": "compression"}


def _page(*widgets, stretch_last: bool = True) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(12, 10, 12, 10)
    for i, x in enumerate(widgets):
        lay.addWidget(x, 1 if (stretch_last and i == len(widgets) - 1) else 0)
    return w


def _empty(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("muted")
    lab.setAlignment(Qt.AlignCenter)
    return lab


def _sel_label(text: str, mono: bool = False) -> QLabel:
    lab = QLabel(text)
    lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lab.setWordWrap(True)
    if mono:
        lab.setFont(mono_font())
    return lab


def _addr(va, offset=None) -> Cell:
    if va is not None:
        return Cell(f"0x{va:x}", key=va, mono=True)
    if offset is not None:
        return Cell(f"off 0x{offset:x}", key=offset, mono=True)
    return Cell("", key=-1)


@lru_cache(maxsize=1)
def suspicious_apis() -> dict[str, str]:
    """APIs cited by the rules (api_group / api_combo) -> rule title."""
    with open(DEFAULT_RULES, encoding="utf-8") as f:
        rules = yaml.safe_load(f).get("rules", [])
    out: dict[str, str] = {}
    for r in rules:
        p = r.get("params") or {}
        names = list(p.get("apis") or [])
        for g in p.get("groups") or []:
            names.extend(g)
        for n in names:
            if isinstance(n, str):
                out.setdefault(n.lower(), r.get("title", r.get("id", "")))
    return out


# --- Overview ---------------------------------------------------------------------------------------

def overview(report: dict) -> QWidget:
    pe, sc = report["pe"], report["score"]
    top = QHBoxLayout()
    top.addWidget(ScoreGauge(sc["score"], sc["verdict"]), 0, Qt.AlignTop)

    form = QFormLayout()
    form.setLabelAlignment(Qt.AlignRight)
    form.setHorizontalSpacing(14)
    form.setVerticalSpacing(5)

    def row(k, v, mono=False):
        lab = QLabel(k)
        lab.setObjectName("muted")
        form.addRow(lab, _sel_label(v, mono))

    if pe.get("memory_dump"):
        warn = QLabel(f"<b style='color:{SEVERITY['medium']}'>This looks like a memory dump</b> (sections at their "
                      f"virtual addresses). Imports, sections and strings are read in the wrong place: rebuild it "
                      f"with <b>Unmapper → Rebuild PE from memory dump</b> (Ctrl+U) and analyze the result.")
        warn.setWordWrap(True)
        form.addRow(warn)
    row("File", report["file"]["name"])
    row("Path", report["file"].get("path", ""))
    row("Type", f"{pe['format']} {pe['kind']}  ·  {pe['machine']}  ·  {pe['subsystem']}"
        + ("  ·  .NET" if pe["is_dotnet"] else ""))
    row("Size", f"{pe['size']:,} bytes")
    row("Compiled", f"{pe['timestamp_utc']} UTC")
    for k in ("md5", "sha1", "sha256"):
        row(k.upper(), pe["hashes"][k], True)
    row("Imphash", pe["imphash"] or "-", True)
    if pe["hashes"].get("ssdeep"):
        row("ssdeep", pe["hashes"]["ssdeep"], True)
    row("Entropy", f"{pe['entropy']:.3f}")
    ident = report.get("identification") or []
    row("Identified", ", ".join(f"{i['name']} ({i['type']})" for i in ident) or "-")
    row("Entry point", f"0x{pe['entry_point_rva']:x} in {pe['entry_point_section'] or 'no section'}")
    pdb = [d["pdb"] for d in pe.get("debug") or [] if d.get("pdb")]
    if pdb:
        row("PDB", pdb[0], True)
    if (pe.get("rich") or {}).get("summary"):
        row("Toolchain", pe["rich"]["summary"] + ("  ·  Rich header forged" if pe["rich"].get("checksum_ok") is False else ""))
    if pe.get("signature"):
        from ..cli import signature_text
        row("Signature", signature_text(pe["signature"]))
    if pe.get("protections"):
        form.addRow(_muted_label("Protections"), protections_row(pe["protections"]))
    t = report.get("timings", {})
    row("Analysis", f"{sum(t.values()):.2f} s  ·  PELens {report.get('tool', {}).get('version', '')}")
    fw = QWidget()
    fw.setLayout(form)
    top.addWidget(fw, 1)

    # counters
    strings = report.get("strings", [])
    n_int = sum(1 for s in strings if s["source"] == "static" and SUSPICIOUS_TAGS & set(s["tags"]))
    n_stack = sum(1 for s in strings if s["source"] == "stack")
    stats = [("Findings", len(sc["findings"])), ("Crypto", len(report.get("crypto") or [])),
             ("Interesting strings", n_int), ("Stack strings", n_stack),
             ("Imports", sum(len(i["functions"]) for i in pe["imports"])), ("Sections", len(pe["sections"]))]
    grid = QGridLayout()
    for i, (k, v) in enumerate(stats):
        c = card()
        cl = QVBoxLayout(c)
        cl.setContentsMargins(10, 6, 10, 6)
        n = QLabel(str(v))
        f = n.font()
        f.setPointSizeF(f.pointSizeF() * 1.6)
        f.setBold(True)
        n.setFont(f)
        lab = QLabel(k)
        lab.setObjectName("muted")
        cl.addWidget(n)
        cl.addWidget(lab)
        grid.addWidget(c, 0, i)
    gw = QWidget()
    gw.setLayout(grid)

    # main findings: all of them at their natural height, the page scrolls if needed
    if sc["findings"]:
        html = []
        for f in sc["findings"]:
            col = SEVERITY[f["severity"]]
            ev = visible(f["evidence"][0], 160) if f["evidence"] else ""
            if len(f["evidence"]) > 1:
                ev += f"   (+{len(f['evidence']) - 1} more in Findings)"
            html.append(f"<p style='margin:0 0 10px 0; line-height:135%'>"
                        f"<b style='color:{col}'>+{f['weight']}&nbsp;&nbsp;{SEV_LABEL[f['severity']]}</b>"
                        f"&nbsp;&nbsp;<b>{_h(f['title'])}</b><br>"
                        f"<span style='color:gray; font-size:92%'>{_h(ev)}</span></p>")
        text = "".join(html)
    else:
        text = f"<p style='color:{GOOD}'>No suspicious indicators.</p>"
    fl = QLabel(text)
    fl.setTextFormat(Qt.RichText)
    fl.setWordWrap(True)
    fl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    fl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
    ind = QFrame()
    ind.setObjectName("card")
    il = QVBoxLayout(ind)
    il.setContentsMargins(12, 10, 12, 2)
    il.addWidget(fl)

    chart = _chart(report)
    chart.setMinimumHeight(200)
    topw = QWidget()
    topw.setLayout(top)
    page = _page(topw, gw, _section_label("Indicators"), ind,
                 _section_label("Entropy (256-byte window; dashed line = 7.2, packed/encrypted data)"), chart,
                 stretch_last=False)
    page.layout().addStretch(1)
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.NoFrame)
    sa.setWidget(page)
    return sa


def _h(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _section_label(text: str) -> QLabel:
    lab = QLabel(text)
    f = lab.font()
    f.setBold(True)
    lab.setFont(f)
    return lab


# --- Findings ---------------------------------------------------------------------------------------

def findings(report: dict) -> QWidget:
    sc = report["score"]
    if not sc["findings"]:
        return _page(title("Findings", "How the score was computed."), _empty("No suspicious indicators."))
    tree = make_tree(["Weight", "Severity", "Indicator / evidence"])
    for f in sc["findings"]:
        it = QTreeWidgetItem([f"+{f['weight']}", SEV_LABEL[f["severity"]], f["title"]])
        it.setForeground(1, QBrush(QColor(SEVERITY[f["severity"]])))
        it.setTextAlignment(0, Qt.AlignRight | Qt.AlignVCenter)
        fnt = it.font(2)
        fnt.setBold(True)
        it.setFont(2, fnt)
        it.setData(0, Qt.UserRole, f)
        for e in f["evidence"]:
            ch = QTreeWidgetItem(["", "", visible(e, 400)])
            ch.setToolTip(2, visible(e))
            ch.setData(0, Qt.UserRole, f)
            it.addChild(ch)
        tree.addTopLevelItem(it)
    tree.expandAll()
    tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
    tree.resizeColumnToContents(0)
    tree.resizeColumnToContents(1)
    tree.setColumnWidth(0, max(tree.columnWidth(0), 56))

    detail = QTextBrowser()
    detail.setOpenExternalLinks(True)

    def show(cur, _prev=None):
        f = cur.data(0, Qt.UserRole) if cur else None
        if not f:
            return
        ev = "".join(f"<li><code>{_h(visible(e))}</code></li>" for e in f["evidence"])
        detail.setHtml(f"<h3 style='margin:0'>{_h(f['title'])}</h3>"
                       f"<p><b style='color:{SEVERITY[f['severity']]}'>{SEV_LABEL[f['severity']]}</b> · weight +{f['weight']}"
                       f" · rule <code>{_h(f['id'])}</code>"
                       + ("".join(f" · <a href='{attack_url(t)}'>{t}</a>" for t in f.get("attack") or []))
                       + f"</p><p>{_h(f['description'])}</p><ul>{ev}</ul>")

    tree.currentItemChanged.connect(show)
    split = QSplitter(Qt.Vertical)
    split.addWidget(tree)
    split.addWidget(detail)
    split.setSizes([420, 160])
    total = sum(f["weight"] for f in sc["findings"])
    sub = f"Score {sc['score']}/100 ({sc['verdict']}) — sum of weights {total}, capped at 100."
    tree.setCurrentItem(tree.topLevelItem(0))
    return _page(title("Findings", sub), split)


# --- Sections ---------------------------------------------------------------------------------------

def sections(report: dict) -> QWidget:
    pe = report["pe"]
    ep = pe["entry_point_section"]
    rows = []
    for s in pe["sections"]:
        e = s["entropy"]
        ecol = SEVERITY["high"] if e >= 7.2 else SEVERITY["medium"] if e >= 6.5 else None
        rwx = s["executable"] and s["writable"]
        rows.append([
            Cell(visible(s["name"]), bold=s["name"] == ep, tip="entry point section" if s["name"] == ep else None),
            Cell(f"0x{s['virtual_address']:x}", key=s["virtual_address"], mono=True),
            Cell(f"{s['virtual_size']:,}", key=s["virtual_size"]),
            Cell(f"0x{s['raw_offset']:x}", key=s["raw_offset"], mono=True),
            Cell(f"{s['raw_size']:,}", key=s["raw_size"], color=SEVERITY["medium"] if s["raw_size"] == 0 and s["virtual_size"] else None),
            Cell(s["flags"], color=SEVERITY["high"] if rwx else None, mono=True, tip="writable and executable" if rwx else None),
            Cell(f"0x{s['characteristics']:08x}", key=s["characteristics"], mono=True),
            Cell(f"{e:.3f}", key=e, color=ecol),
            Cell(s["md5"], mono=True),
        ])
    t = make_table(["Name", "VA", "Virtual size", "Raw offset", "Raw size", "Flags", "Characteristics", "Entropy", "MD5"],
                   rows, right_cols=(2, 4, 7),
                   targets=[("offset", s["raw_offset"], s["raw_size"]) if s["raw_size"] else None for s in pe["sections"]],
                   on_activate=lambda tg: jump(report, *tg))
    split = QSplitter(Qt.Vertical)
    split.addWidget(t)
    split.addWidget(_chart(report))
    split.setSizes([260, 240])
    sub = (f"{len(pe['sections'])} sections · entry point in {ep or 'no section'} (bold) · red: RWX or entropy ≥ 7.2 · "
           "double-click a section or click the graph to open the hex view")
    return _page(title("Sections", sub), split)


# --- Imports / exports ------------------------------------------------------------------------------

def imports(report: dict) -> QWidget:
    pe = report["pe"]
    sus = suspicious_apis()
    tree = make_tree(["DLL / function", "Note"])
    n_sus = 0
    for imp in pe["imports"]:
        dll = QTreeWidgetItem([imp["dll"], ("delay-loaded · " if imp["delayed"] else "") + f"{len(imp['functions'])} functions"])
        f = dll.font(0)
        f.setBold(True)
        dll.setFont(0, f)
        hits = 0
        ords = imp.get("by_ordinal") or {}
        for fn in imp["functions"]:
            ch = QTreeWidgetItem([fn, ""])
            if fn in ords:
                ch.setText(1, "by ordinal" if fn.startswith("ordinal_") else f"by ordinal #{ords[fn]} (name resolved)")
                ch.setForeground(1, QBrush(QColor("#8b949e")))
            rule = sus.get(fn.lower()) or (sus.get(fn[:-1].lower()) if fn[-1:] in "AW" else None)
            if rule:
                hits += 1
                ch.setText(1, rule + (f"  ·  by ordinal #{ords[fn]}" if fn in ords else ""))
                ch.setForeground(0, QBrush(QColor(SEVERITY["medium"])))
                ch.setForeground(1, QBrush(QColor(SEVERITY["medium"])))
            dll.addChild(ch)
        if hits:
            n_sus += hits
            dll.setForeground(0, QBrush(QColor(SEVERITY["medium"])))
        tree.addTopLevelItem(dll)
    tree.header().setSectionResizeMode(0, QHeaderView.Interactive)
    tree.setColumnWidth(0, 340)
    if tree.topLevelItemCount() <= 12:
        tree.expandAll()
    filt = QLineEdit()
    filt.setPlaceholderText("Filter DLLs and functions…")
    only = QCheckBox("Only APIs used by the rules")

    def apply():
        q = filt.text().strip().lower()
        o = only.isChecked()
        for i in range(tree.topLevelItemCount()):
            dll = tree.topLevelItem(i)
            dll_match = bool(q) and q in dll.text(0).lower()
            any_vis = False
            for j in range(dll.childCount()):
                ch = dll.child(j)
                ok = (not q or dll_match or q in ch.text(0).lower()) and (not o or bool(ch.text(1)))
                ch.setHidden(not ok)
                any_vis |= ok
            dll.setHidden(not any_vis)
            if (q or o) and any_vis:
                dll.setExpanded(True)

    filt.textChanged.connect(apply)
    only.toggled.connect(apply)
    bar = QHBoxLayout()
    bar.addWidget(filt, 1)
    bar.addWidget(only)
    bw = QWidget()
    bw.setLayout(bar)
    nf = sum(len(i["functions"]) for i in pe["imports"])
    sub = f"{nf} functions from {len(pe['imports'])} DLLs · imphash {pe['imphash'] or '-'} · {n_sus} highlighted APIs appear in the scoring rules"
    return _page(title("Imports", sub), bw, tree)


def exports(report: dict) -> QWidget:
    ex = report["pe"]["exports"]
    if not ex:
        return _page(title("Exports"), _empty("No exports."))
    base = report["pe"]["image_base"]
    rows = [[Cell(s["ordinal"], key=s["ordinal"]), visible(s["name"]) or Cell("(by ordinal)", color="gray"),
             Cell(f"0x{s['rva']:x}", key=s["rva"], mono=True), Cell(f"0x{base + s['rva']:x}", key=s["rva"], mono=True),
             Cell(s["forwarder"], color=SEVERITY["medium"] if s["forwarder"] else None)]
            for s in ex["symbols"]]
    fwd = sum(1 for s in ex["symbols"] if s["forwarder"])
    t = make_table(["Ordinal", "Name", "RVA", "VA", "Forwarded to"], rows, right_cols=(0,),
                   targets=[None if s["forwarder"] else ("rva", s["rva"], 1) for s in ex["symbols"]],
                   on_activate=lambda tg: jump(report, *tg))
    return _page(title("Exports", f"DLL name {ex['name'] or '-'} · {len(ex['symbols'])} symbols · {fwd} forwarded · {HINT}"), t)


def resources(report: dict) -> QWidget:
    from .resview import ResourcePreview, load_file
    res = report["pe"]["resources"]
    dn = report.get("dotnet") or {}
    preview = ResourcePreview(report, load_file(report), on_hex=lambda tg: jump(report, *tg))
    widgets = [title("Resources", f"{len(res)} PE resources · {HINT}" + (f" · {len(dn.get('resources', []))} .NET manifest resources"
                                                                 if dn.get("resources") else ""))]
    if res:
        rows = []
        for r in res:
            e = r["entropy"]
            rows.append([r["type"], visible(str(r["name"])), Cell(r["lang"], key=r["lang"]),
                         Cell(f"0x{r['offset']:x}", key=r["offset"], mono=True), Cell(f"{r['size']:,}", key=r["size"]),
                         Cell(f"{e:.3f}", key=e, color=SEVERITY["high"] if e >= 7.5 else None),
                         Cell(r["magic"], mono=True),
                         Cell("PE file!" if r["embedded_pe"] else "", color=SEVERITY["high"])])
        tbl = make_table(["Type", "Name", "Lang", "Offset", "Size", "Entropy", "First bytes", "Note"],
                         rows, right_cols=(2, 4, 5),
                         targets=[("offset", r["offset"], r["size"]) for r in res],
                         on_activate=lambda tg: jump(report, *tg))
        by_off = {(r["offset"], r["size"]): r for r in res}

        def _sel(row, _c, _pr, _pc):
            it = tbl.item(row, 0)
            tg = it.data(Qt.UserRole + 2) if it else None
            if tg and (tg[1], tg[2]) in by_off:
                preview.show_pe_resource(by_off[(tg[1], tg[2])], res)

        tbl.currentCellChanged.connect(_sel)
        widgets.append(tbl)
    hp = report.get("hidden_pe") or []
    if hp:
        widgets.append(_section_label("Executables hidden in the file (double-click to open in the hex view)"))
        rows = [[Cell(f"0x{h['offset']:x}", key=h["offset"], mono=True), h["region"],
                 " ".join(x for x in (h.get("machine"), ".NET" if h.get("dotnet") else "", h.get("kind")) if x),
                 Cell(f"{h['size']:,}" if h.get("size") else "?", key=h.get("size") or 0),
                 Cell(f"XOR, {h['key_length']}-byte key {h['key']}" if h["encrypted"] else "none",
                      color=SEVERITY["high"] if h["encrypted"] else None, mono=h["encrypted"])]
                for h in hp]
        widgets.append(make_table(["Offset", "Where", "Type", "Size (from headers)", "Encryption"], rows,
                                  right_cols=(3,), targets=[("offset", h["offset"], h.get("size") or 0x400) for h in hp],
                                  on_activate=lambda tg: jump(report, *tg)))
    if dn.get("resources"):
        widgets.append(_section_label(".NET manifest resources (double-click an entry to open it in the hex view)"))
        widgets.append(_dn_resources(dn, report, on_select=preview.show_blob))
    if len(widgets) == 1:
        widgets.append(_empty("No resources."))
        return _page(*widgets)
    left = QWidget()
    ll = QVBoxLayout(left)
    ll.setContentsMargins(0, 0, 0, 0)
    for i, x in enumerate(widgets[1:]):
        ll.addWidget(x, 0 if isinstance(x, QLabel) else 1)
    split = QSplitter(Qt.Horizontal)
    split.addWidget(left)
    split.addWidget(preview)
    split.setStretchFactor(0, 1)
    split.setStretchFactor(1, 1)
    return _page(widgets[0], split)


def _dn_resources(dn: dict, report: dict | None = None, on_select=None):
    """.NET manifest resources as a tree: .resources container -> elements (images, byte[], strings)."""
    tree = make_tree(["Name", "Type", "Size", "Entropy", "Image", "Note"])

    def note(r):
        img = r.get("image") or {}
        hp = img.get("hidden_pe") or r.get("hidden_pe")
        if hp:
            how = f"XOR key {hp['key']} ({hp['key_length']} bytes)" if hp["encrypted"] else "unencrypted"
            where = f", pixels read by {hp['layout']}" if img.get("hidden_pe") else ""
            ln = f", length {hp['length_header']:,}" if hp.get("length_header") else ""
            return f"PE file hidden, {how}{where}{ln}", SEVERITY["high"]
        if img.get("noise"):
            return (f"pixels are random noise (residual entropy {img['residual_entropy']:.2f}): encrypted data",
                    SEVERITY["high"])
        if r.get("embedded_pe"):
            return "PE file", SEVERITY["high"]
        if not img and r["size"] >= 16384 and r["entropy"] >= 7.5 and r.get("format") != ".resources":
            return "near-random data: encrypted?", SEVERITY["medium"]
        if r.get("text"):
            return visible(r["text"], 120), None
        return "", None

    def add(parent, r, typ):
        img = r.get("image") or {}
        imtxt = f"{img['format']} {img['width']}x{img['height']}, {img['bits']} bit" if img.get("width") else \
            (img.get("format") or "")
        n, col = note(r)
        it = QTreeWidgetItem([visible(r["name"]), typ, f"{r['size']:,}", f"{r['entropy']:.3f}", imtxt, n])
        it.setTextAlignment(2, Qt.AlignRight | Qt.AlignVCenter)
        it.setTextAlignment(3, Qt.AlignRight | Qt.AlignVCenter)
        if col:
            it.setForeground(5, QBrush(QColor(col)))
            it.setForeground(0, QBrush(QColor(col)))
        if r.get("offset") is not None:
            it.setData(0, Qt.UserRole, (r["offset"], r["size"]))
            # for the preview: the actual image if there is one (skips the length prefix)
            if img.get("offset") is not None and img.get("size"):
                it.setData(1, Qt.UserRole, (img["offset"], img["size"]))
            it.setToolTip(0, f"file offset 0x{r['offset']:x} · double-click to open in the hex view")
        (tree.addTopLevelItem(it) if parent is None else parent.addChild(it))
        return it

    for r in dn.get("resources", []):
        top = add(None, r, r.get("format") or "raw")
        f = top.font(0)
        f.setBold(True)
        top.setFont(0, f)
        for e in r.get("entries", []):
            add(top, e, e["type"])
    tree.expandAll()
    for c in (0, 1, 2, 3, 4):
        tree.resizeColumnToContents(c)
    tree.setColumnWidth(0, min(tree.columnWidth(0), 380))
    tree.setColumnWidth(1, min(tree.columnWidth(1), 220))

    def on_dbl(item, _col):
        tg = item.data(0, Qt.UserRole)
        if tg and report is not None:
            jump(report, "offset", tg[0], tg[1])

    tree.itemDoubleClicked.connect(on_dbl)
    if on_select is not None:
        def on_cur(item, _prev):
            if item is None:
                return
            tg = item.data(1, Qt.UserRole) or item.data(0, Qt.UserRole)
            if tg:
                on_select(item.text(0), tg[0], tg[1])

        tree.currentItemChanged.connect(on_cur)
    return tree


# --- Strings ----------------------------------------------------------------------------------------

class StringsModel(QAbstractTableModel):
    COLS = ["Address", "Section", "Length", "Type", "Source", "String", "Tags"]

    def __init__(self, strings: list[dict]):
        super().__init__()
        self.rows = strings
        self.text = [visible(s["value"], 400) for s in strings]
        self.mono = mono_font()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        s = self.rows[index.row()]
        c = index.column()
        if role == Qt.DisplayRole:
            if c == 0:
                return hx(s["va"]) if s["va"] is not None else (f"off 0x{s['offset']:x}" if s["offset"] is not None else "")
            return (s["section"], s["length"], s["type"], s["source"], self.text[index.row()], ", ".join(s["tags"]))[c - 1]
        if role == Qt.UserRole:  # sort key
            if c == 0:
                return s["va"] if s["va"] is not None else (s["offset"] if s["offset"] is not None else -1)
            if c == 2:
                return s["length"]
            return str(self.data(index, Qt.DisplayRole)).lower()
        if role == Qt.UserRole + 1:
            return s["value"] if c == 5 else None
        if role == Qt.FontRole and c in (0, 5):
            return self.mono
        if role == Qt.ForegroundRole:
            if SUSPICIOUS_TAGS & set(s["tags"]):
                return QBrush(QColor(SEVERITY["medium"]))
            if s["source"] == "stack":
                return QBrush(QColor(STACK))
        if role == Qt.TextAlignmentRole and c == 2:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None


class StringsFilter(QSortFilterProxyModel):
    def __init__(self, model: StringsModel):
        super().__init__()
        self.setSourceModel(model)
        self.setSortRole(Qt.UserRole)
        self.mode = "interesting"
        self.needle = ""
        self.rx: re.Pattern | None = None

    def set(self, mode: str, needle: str, regex: bool, case: bool):
        self.mode = mode
        self.needle = needle if case else needle.lower()
        self.case = case
        self.rx = None
        self.bad_regex = False
        if regex and needle:
            try:
                self.rx = re.compile(needle, 0 if case else re.I)
            except re.error:
                self.bad_regex = True
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        m: StringsModel = self.sourceModel()
        s = m.rows[row]
        mode = self.mode
        if mode == "interesting":
            if not (s["source"] == "stack" or SUSPICIOUS_TAGS & set(s["tags"])):
                return False
        elif mode == "stack":
            if s["source"] != "stack":
                return False
        elif mode == "us":
            if s["section"] != "#US":
                return False
        elif mode.startswith("tag:"):
            if mode[4:] not in s["tags"]:
                return False
        if self.rx is not None:
            return bool(self.rx.search(s["value"]))
        if self.needle and not getattr(self, "bad_regex", False):
            v = s["value"] if getattr(self, "case", False) else s["value"].lower()
            return self.needle in v
        return True


def strings(report: dict) -> QWidget:
    data = report.get("strings") or []
    model = StringsModel(data)
    proxy = StringsFilter(model)
    view = QTableView()
    view.setModel(proxy)
    view.setSortingEnabled(True)
    view.sortByColumn(0, Qt.AscendingOrder)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setAlternatingRowColors(True)
    view.setWordWrap(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(22)
    view.horizontalHeader().setStretchLastSection(False)
    install_copy(view)
    for c, w in enumerate((110, 70, 60, 46, 56, 560, 160)):
        view.setColumnWidth(c, w)
    view.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)

    mode = QComboBox()
    mode.addItem("Interesting (tagged + stack)", "interesting")
    mode.addItem("All strings", "all")
    if any(s["source"] == "stack" for s in data):
        mode.addItem("Stack strings", "stack")
    if any(s["section"] == "#US" for s in data):
        mode.addItem(".NET user strings (#US)", "us")
    tags = sorted({t for s in data for t in s["tags"]})
    for t in tags:
        n = sum(1 for s in data if t in s["tags"])
        mode.addItem(f"Tag: {t} ({n})", f"tag:{t}")
    search = QLineEdit()
    search.setPlaceholderText("Search strings…")
    rx = QCheckBox("Regex")
    case = QCheckBox("Case")
    count = QLabel()
    count.setObjectName("muted")
    detail = QPlainTextEdit()
    detail.setReadOnly(True)
    detail.setFont(mono_font())
    detail.setMaximumHeight(90)
    detail.setPlaceholderText("Select a string to see it in full.")

    def apply():
        proxy.set(mode.currentData(), search.text(), rx.isChecked(), case.isChecked())
        bad = getattr(proxy, "bad_regex", False)
        search.setStyleSheet(f"border: 1px solid {SEVERITY['high']};" if bad else "")
        count.setText(f"{proxy.rowCount():,} of {len(data):,} strings")

    def on_sel(cur, _prev):
        if cur.isValid():
            s = model.rows[proxy.mapToSource(cur).row()]
            where = hx(s["va"]) if s["va"] is not None else (f"offset 0x{s['offset']:x}" if s["offset"] is not None else "")
            detail.setPlainText(f"{where}  {s['section']}  {s['type']}  {s['source']}  len {s['length']}"
                                f"{'  [' + ', '.join(s['tags']) + ']' if s['tags'] else ''}\n{visible(s['value'])}")

    # no interesting strings: start from all of them, otherwise the table would be empty
    if not any(s["source"] == "stack" or SUSPICIOUS_TAGS & set(s["tags"]) for s in data):
        mode.setCurrentIndex(1)
    for sig in (mode.currentIndexChanged, search.textChanged, rx.toggled, case.toggled):
        sig.connect(lambda *_: apply())
    view.selectionModel().currentRowChanged.connect(on_sel)

    def on_dbl(idx):
        s = model.rows[proxy.mapToSource(idx).row()]
        size = s["length"] * (2 if s["type"] == "C16" else 1)
        if s["offset"] is not None:
            jump(report, "offset", s["offset"], size)
        elif s["va"] is not None:
            jump(report, "va", s["va"], 1)

    view.doubleClicked.connect(on_dbl)
    apply()
    bar = QHBoxLayout()
    bar.addWidget(mode)
    bar.addWidget(search, 1)
    bar.addWidget(rx)
    bar.addWidget(case)
    bar.addWidget(count)
    bw = QWidget()
    bw.setLayout(bar)
    sub = ("IDA-style view · type C = ASCII, C16 = UTF-16LE · amber: suspicious tags · cyan: reconstructed stack strings"
           " · double-click to open in the hex view (stack strings: the code that builds them)")
    w = _page(title("Strings", sub), bw, view, stretch_last=False)
    w.layout().setStretch(2, 1)
    w.layout().addWidget(detail)
    return w


# --- Crypto / code ----------------------------------------------------------------------------------

def crypto(report: dict) -> QWidget:
    hits = report.get("crypto") or []
    if not hits:
        return _page(title("Cryptography"), _empty("No cryptographic algorithms or obfuscation routines detected."))
    rows = []
    for h in hits:
        col = CONFIDENCE[h["confidence"]]
        where = _addr(h.get("va"), h.get("offset"))
        rows.append([Cell(h["algorithm"], bold=h["confidence"] == "high"), CAT_LABEL.get(h["category"], h["category"]),
                     Cell(visible(h["signature"], 300), tip=visible(h["signature"])),
                     Cell(h["count"], key=h["count"]), where, h.get("section") or "",
                     Cell(h["confidence"], color=col)])
    t = make_table(["Algorithm", "Type", "Evidence", "Count", "Address", "Section", "Confidence"], rows,
                   stretch=2, right_cols=(3,),
                   targets=[("va", h["va"], 1) if h.get("va") is not None else
                            ("offset", h["offset"], 1) if h.get("offset") is not None else None for h in hits],
                   on_activate=lambda tg: jump(report, *tg))
    detail = QPlainTextEdit()
    detail.setReadOnly(True)
    detail.setFont(mono_font())
    detail.setPlaceholderText("Select a row to see the details (implementations, callers, variant features).")

    def on_sel():
        r = t.currentRow()
        if r < 0:
            return
        # the table can be re-sorted: the hit is found again through algorithm + signature
        alg, sig = t.item(r, 0).text(), t.item(r, 2).toolTip() or t.item(r, 2).text()
        h = next((x for x in hits if x["algorithm"] == alg and visible(x["signature"]) == sig), None)
        if h:
            detail.setPlainText(json.dumps(_hexify(_ordered(h)), indent=2, ensure_ascii=False, default=str))

    t.itemSelectionChanged.connect(on_sel)
    t.selectRow(0)
    split = QSplitter(Qt.Vertical)
    split.addWidget(t)
    split.addWidget(detail)
    split.setSizes([360, 180])
    return _page(title("Cryptography", "Algorithms recognized from constants, instructions and code structure. "
                                       f"Nothing is decrypted. {HINT}"), split)


def _ordered(h: dict) -> dict:
    """First the evidence and the summary (e.g. the RC4 variants), then the full list."""
    keys = ["algorithm", "signature", "confidence", "category", "count", "va", "offset", "section"]
    out = {k: h[k] for k in keys if k in h}
    d = h.get("details")
    if isinstance(d, dict):
        d = {**{k: d[k] for k in ("variants",) if k in d}, **{k: v for k, v in d.items() if k != "variants"}}
    if d:
        out["details"] = d
    out.update({k: v for k, v in h.items() if k not in out and k != "details"})
    return out


_ADDR_KEYS = {"va", "function", "offset", "rva", "address", "first_va"}


def _hexify(o, key: str = ""):
    """Addresses in hex, as in the rest of the interface."""
    if isinstance(o, dict):
        return {k: _hexify(v, k) for k, v in o.items()}
    if isinstance(o, list):
        return [_hexify(v, key) for v in o]
    if isinstance(o, int) and not isinstance(o, bool) and key in _ADDR_KEYS:
        return f"0x{o:x}"
    return o


def code(report: dict) -> QWidget:
    ct = report.get("code_traits") or {}
    labels = [("peb_access", "PEB access (gs:[0x60] / fs:[0x30])"),
              ("export_parsing", "Manual export-table parsing"),
              ("hash_loops", "Name-hashing loops"), ("api_hashes", "Known API hashes"),
              ("syscalls", "Direct syscall stubs"), ("rwx_alloc", "RWX memory allocations"),
              ("rdtsc", "rdtsc timing checks")]
    tree = make_tree(["Technique / address", "Detail"])
    total = 0
    for k, label in labels:
        items = ct.get(k) or []
        if not items:
            continue
        total += len(items)
        top = QTreeWidgetItem([label, f"{len(items)}"])
        f = top.font(0)
        f.setBold(True)
        top.setFont(0, f)
        for x in items[:500]:
            if isinstance(x, dict):
                va = x.get("va")
                det = x.get("api") or x.get("op") or ""
                if "value" in x:
                    det = f"0x{x['value']:08x} = {det}"
            else:
                va, det = x, ""
            ch = QTreeWidgetItem([hx(va), det])
            ch.setFont(0, mono_font())
            top.addChild(ch)
        tree.addTopLevelItem(top)
    tree.expandAll()
    tree.setColumnWidth(0, 340)

    def on_dbl(item, _col):
        t = item.text(0)
        if t.startswith("0x"):
            jump(report, "va", int(t, 16), 1)

    tree.itemDoubleClicked.connect(on_dbl)
    notes = report.get("notes") or []
    if report["pe"]["is_dotnet"]:
        body = _empty("Code analysis is not done on .NET assemblies (IL bytecode). See the .NET page.")
    elif not total:
        body = _empty("No loader techniques found in the code." + ("\n" + "\n".join(notes) if notes else ""))
    else:
        body = tree
    return _page(title("Code techniques", "Loader and evasion techniques recognized in the disassembled code. "
                                          "Double-click an address to open it in the hex view."), body)


# --- .NET -------------------------------------------------------------------------------------------

def dotnet(report: dict) -> QWidget:
    dn = report.get("dotnet") or {}
    if "error" in dn:
        return _page(title(".NET"), _empty(f"Could not read the .NET metadata: {dn['error']}"))
    c = dn.get("counts", {})
    info = QFormLayout()
    info.setHorizontalSpacing(14)
    for k, v in [("Assembly", f"{dn.get('assembly', '')} {dn.get('version', '')}"), ("Module", dn.get("module", "")),
                 ("Parser", dn.get("parser", "")),
                 ("Counts", ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in c.items())),
                 ("References", ", ".join(dn.get("assembly_refs", [])) or "-")]:
        lab = QLabel(k)
        lab.setObjectName("muted")
        info.addRow(lab, _sel_label(visible(str(v))))
    on = dn.get("obfuscated_names") or {}
    if on.get("total"):
        lab = QLabel("Obfuscated names")
        lab.setObjectName("muted")
        info.addRow(lab, _sel_label(f"{on['ratio'] * 100:.0f}% of {on['total']}"
                                    + (f" — e.g. {', '.join(on['examples'][:3])}" if on.get("examples") else "")))
    iw = QWidget()
    iw.setLayout(info)

    tree = make_tree(["Item", "Detail"])

    def group(name, color=None):
        g = QTreeWidgetItem([name, ""])
        f = g.font(0)
        f.setBold(True)
        g.setFont(0, f)
        if color:
            g.setForeground(0, QBrush(QColor(color)))
        tree.addTopLevelItem(g)
        return g

    if dn.get("metadata_anomalies"):
        g = group("Metadata anomalies", SEVERITY["high"])
        for a in dn["metadata_anomalies"]:
            g.addChild(QTreeWidgetItem([visible(a), ""]))
    if dn.get("obfuscators"):
        g = group("Obfuscators / protectors", SEVERITY["medium"])
        for o in dn["obfuscators"]:
            g.addChild(QTreeWidgetItem([o["name"], f"{o['type']} · {visible(o['evidence'])}"]))
    for cid, cat in (dn.get("api_categories") or {}).items():
        g = group(cat["title"])
        g.setText(1, f"{len(cat['hits'])} APIs")
        for h in cat["hits"]:
            ch = QTreeWidgetItem([h, ""])
            ch.setFont(0, mono_font())
            g.addChild(ch)
    il = dn.get("il") or {}
    if il.get("string_decryptors"):
        g = group("String decryption methods (IL)", SEVERITY["high"])
        for d in il["string_decryptors"]:
            ch = QTreeWidgetItem([visible(d["method"]), f"→ {d['returns']}, {d['calls']} calls from {d['callers']} "
                                  f"methods, {d['constant_args']:.0%} constant args"
                                  + (", XOR loop" if d.get("xor_loop") else "") + f" · token {d['token']}"])
            g.addChild(ch)
    if il.get("xor_loops"):
        g = group("XOR loops in IL", SEVERITY["medium"])
        g.setText(1, f"{len(il['xor_loops'])} methods")
        for x in il["xor_loops"]:
            g.addChild(QTreeWidgetItem([visible(x["method"]), f"called from {x['callers']} methods · token {x['token']}"]))
    if dn.get("pinvoke"):
        g = group("P/Invoke (native imports)")
        g.setText(1, f"{len(dn['pinvoke'])}")
        for p in dn["pinvoke"]:
            ch = QTreeWidgetItem([p["name"], p.get("dll", "")])
            ch.setFont(0, mono_font())
            g.addChild(ch)
    tree.expandAll()
    tree.setColumnWidth(0, 420)
    widgets = [title(".NET", "Read from the CLR metadata: referenced APIs, obfuscators, resources."), iw, tree]
    if dn.get("resources"):
        widgets += [_section_label("Manifest resources"), _dn_resources(dn, report)]
        w = _page(*widgets, stretch_last=False)
        w.layout().setStretch(2, 1)
        return w
    return _page(*widgets)


# --- YARA -------------------------------------------------------------------------------------------

CHOOSE_YARA = None   # set by the window: opens the rules folder chooser


def yara(report: dict) -> QWidget:
    from PySide6.QtWidgets import QPushButton
    ya = report.get("yara")
    if not ya:
        lab = _empty("No YARA rules were used for this file.\n\nPut .yar files in a folder named 'yara' next to "
                     "pelens-gui.exe, or choose a folder below, then re-analyze the file (F5).")
        b = QPushButton("Choose YARA rules folder…")
        b.setMaximumWidth(240)
        b.clicked.connect(lambda: CHOOSE_YARA and CHOOSE_YARA())
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.addStretch(1)
        bl.addWidget(lab)
        bl.addWidget(b, 0, Qt.AlignHCenter)
        bl.addStretch(2)
        return _page(title("YARA"), box)

    from .hexview import AddressMap
    amap = AddressMap(report)
    matches = ya.get("matches") or []
    src = ", ".join(ya.get("sources") or []) or "?"
    sub = (f"{ya.get('rules', '?')} rules in {ya.get('rule_files', 0)} files ({src}) · {len(matches)} matched"
           + (" · double-click a string to open it in the hex view" if matches else ""))
    widgets = [title("YARA", sub)]
    errors = ya.get("errors") or []
    if errors:
        e = QLabel(f"<b style='color:{SEVERITY['medium']}'>{len(errors)} rule file(s) skipped:</b> "
                   + "; ".join(_h(x) for x in errors[:6]) + (" …" if len(errors) > 6 else ""))
        e.setWordWrap(True)
        e.setTextInteractionFlags(Qt.TextSelectableByMouse)
        widgets.append(e)
    if not matches:
        widgets.append(_empty("No rule matched this file."))
        return _page(*widgets)

    rows = [[Cell(m["rule"], bold=True, tip=m["namespace"]), Cell(SEV_LABEL[m["severity"]], color=SEVERITY[m["severity"]]),
             Cell(f"+{m['weight']}", key=m["weight"]), ", ".join(m["tags"]), Cell(m["description"], tip=m["description"]),
             m["file"], m["author"], Cell(len(m["strings"]), key=len(m["strings"]))]
            for m in matches]
    t = make_table(["Rule", "Severity", "Weight", "Tags", "Description", "Rule file", "Author", "Strings"], rows,
                   stretch=4, right_cols=(2, 7), targets=list(range(len(matches))), on_activate=lambda i: None)

    hits = make_table(["String", "Offset", "VA", "Where", "Length", "Matched data"], [], stretch=5)
    hits.setSortingEnabled(False)

    def show(idx: int):
        m = matches[idx]
        hits.setSortingEnabled(False)
        hits.setRowCount(0)
        mf = mono_font()
        for h in m["strings"]:
            r = hits.rowCount()
            hits.insertRow(r)
            rva, where = amap.describe(h["offset"])
            vals = [h["id"], f"0x{h['offset']:x}", f"0x{amap.base + rva:x}" if rva is not None else "", where,
                    str(h.get("length", "")), h["data"]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c in (1, 2, 5):
                    it.setFont(mf)
                if c == 0:
                    it.setData(Qt.UserRole + 2, ("offset", h["offset"], h.get("length") or max(1, len(h["data"]))))
                hits.setItem(r, c, it)
        hits.resizeColumnsToContents()
        hits.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        if not m["strings"]:
            hits.insertRow(0)
            hits.setItem(0, 0, QTableWidgetItem("(the rule matched on its condition only, no strings)"))

    def on_sel():
        r = t.currentRow()
        if r >= 0:
            show(t.item(r, 0).data(Qt.UserRole + 2))

    def on_hit(row, _col):
        it = hits.item(row, 0)
        tg = it.data(Qt.UserRole + 2) if it else None
        if tg:
            jump(report, *tg)

    t.itemSelectionChanged.connect(on_sel)
    hits.cellDoubleClicked.connect(on_hit)
    t.sortItems(2, Qt.DescendingOrder)
    t.selectRow(0)
    split = QSplitter(Qt.Vertical)
    split.addWidget(t)
    box = QWidget()
    bl = QVBoxLayout(box)
    bl.setContentsMargins(0, 0, 0, 0)
    bl.addWidget(_section_label("Matched strings of the selected rule"))
    bl.addWidget(hits)
    split.addWidget(box)
    split.setSizes([280, 260])
    widgets.append(split)
    return _page(*widgets)


# --- ATT&CK -----------------------------------------------------------------------------------------

def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def attack(report: dict) -> QWidget:
    techs = report["score"].get("attack") or []
    if not techs:
        return _page(title("MITRE ATT&CK"), _empty("No findings mapped to ATT&CK techniques."))
    titles = {f["id"]: f for f in report["score"]["findings"]}
    rows = []
    for t in techs:
        fs = [titles[i] for i in t["findings"] if i in titles]
        worst = max((f["weight"] for f in fs), default=0)
        sev = next((f["severity"] for f in fs if f["weight"] == worst), "low")
        rows.append([Cell(t["id"], mono=True, bold=True, tip=attack_url(t["id"])), t["name"],
                     Cell(", ".join(f["title"] for f in fs), tip="\n".join(f"+{f['weight']} {f['title']}" for f in fs)),
                     Cell(SEV_LABEL[sev], color=SEVERITY[sev])])
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QDesktopServices
    t = make_table(["Technique", "Name", "Evidence (findings)", "Severity"], rows, stretch=2,
                   targets=[x["id"] for x in techs],
                   on_activate=lambda tid: QDesktopServices.openUrl(QUrl(attack_url(tid))))
    return _page(title("MITRE ATT&CK", f"{len(techs)} techniques suggested by the findings. Static analysis: they "
                                       "are what the code is built to do, not observed behaviour. Double-click to "
                                       "open the technique on attack.mitre.org."), t)


# --- Headers ----------------------------------------------------------------------------------------

_PROT_COLOR = {"on": "#3fb950", "off": "#8b949e", "weak": "#d29922", "n/a": "#6e7681"}


def _muted_label(text):
    lab = QLabel(text)
    lab.setObjectName("muted")
    return lab


def protections_row(prots: list) -> QLabel:
    """Protections as colored 'chips': green enabled, grey missing, yellow weak."""
    parts = []
    for p in prots:
        col = _PROT_COLOR.get(p["state"], "#8b949e")
        mark = {"on": "✓", "off": "✗", "weak": "!", "n/a": "–"}.get(p["state"], "")
        parts.append(f"<span title='{p['detail']}' style='color:{col}'>{mark}&nbsp;{p['name']}</span>")
    lab = QLabel("&nbsp;&nbsp; ".join(parts))
    lab.setTextFormat(Qt.RichText)
    lab.setWordWrap(True)
    lab.setToolTip("\n".join(f"{p['name']}: {p['state']} · {p['detail']}" for p in prots))
    return lab


def headers(report: dict) -> QWidget:
    pe = report["pe"]
    tree = make_tree(["Field", "Value"])

    def fmt(v):
        if isinstance(v, bool):
            return str(v)
        if isinstance(v, int):
            return f"0x{v:x}  ({v})" if v >= 10 else str(v)
        return visible(str(v))

    def add(parent, key, val):
        if isinstance(val, dict):
            it = QTreeWidgetItem([str(key), ""])
            for k, v in val.items():
                add(it, k, v)
        elif isinstance(val, list):
            simple = all(not isinstance(x, (dict, list)) for x in val)
            if simple and len(val) <= 2 and not (val and isinstance(val[0], int)):
                it = QTreeWidgetItem([str(key), ", ".join(fmt(x) for x in val) or "-"])
            else:
                it = QTreeWidgetItem([str(key), f"{len(val)} items"])
                for i, x in enumerate(val):
                    add(it, f"[{i}]", x)
        else:
            it = QTreeWidgetItem([str(key), "-" if val is None else fmt(val)])
            it.setFont(1, mono_font())
        if parent is None:
            tree.addTopLevelItem(it)
            f = it.font(0)
            f.setBold(True)
            it.setFont(0, f)
        else:
            parent.addChild(it)
        return it

    h = pe.get("headers") or {}
    add(None, "DOS header", h.get("dos", {}))
    add(None, "File header", h.get("file", {}))
    add(None, "Optional header", h.get("optional", {}))
    add(None, "Characteristics", h.get("characteristics", []))
    add(None, "DLL characteristics", h.get("dll_characteristics", []))
    cs = pe.get("checksum") or {}
    it = add(None, "Checksum", {"stored": cs.get("stored"), "computed": cs.get("computed")})
    if cs.get("stored") and cs.get("computed") is not None and cs["stored"] != cs["computed"]:
        it.setText(1, "mismatch")
        it.setForeground(1, QBrush(QColor(SEVERITY["medium"])))
    cons = pe.get("consistency") or []
    it = add(None, "Dates and versions", "consistent" if not cons else f"{len(cons)} mismatches")
    if cons:
        it.setForeground(1, QBrush(QColor(SEVERITY["medium"])))
        for c in cons:
            it.addChild(QTreeWidgetItem([c["what"], c["detail"]]))
    prots = pe.get("protections") or []
    if prots:
        it = add(None, "Protections", f"{sum(p['state'] == 'on' for p in prots)} of {len(prots)} enabled")
        for p in prots:
            ch = QTreeWidgetItem([p["name"], f"{p['state']}  ·  {p['detail']}"])
            ch.setForeground(1, QBrush(QColor(_PROT_COLOR.get(p["state"], "#8b949e"))))
            it.addChild(ch)
    if pe.get("rich"):
        r = pe["rich"]
        it = add(None, "Rich header", r.get("summary") or "")
        if r.get("checksum_ok") is False:
            it.setText(1, (r.get("summary") or "") + "  ·  checksum mismatch: forged")
            it.setForeground(1, QBrush(QColor(SEVERITY["medium"])))
        it.addChild(QTreeWidgetItem(["hash", r.get("hash", "")]))
        for e in r["entries"]:
            ch = QTreeWidgetItem([e.get("tool") or f"product {e['product_id']}",
                                  f"{e.get('version') or '-'}  ·  build {e['build']}  ·  {e['count']} objects  "
                                  f"(id 0x{e['product_id']:x})"])
            it.addChild(ch)
    else:
        it = add(None, "Rich header", "removed (zeroed after linking)" if pe.get("rich_removed") else "not present")
        if pe.get("rich_removed"):
            it.setForeground(1, QBrush(QColor(SEVERITY["medium"])))
    base = pe["image_base"]
    tls = pe.get("tls_callbacks") or []
    it = add(None, "TLS callbacks", f"{len(tls)}" if tls else "none")
    for cb in tls:
        ch = QTreeWidgetItem([hx(cb), f"RVA 0x{cb - base:x}" if cb >= base else ""])
        ch.setFont(0, mono_font())
        it.addChild(ch)
    add(None, "Debug directory", pe.get("debug") or "none")
    add(None, "Version info", pe.get("version_info") or "none")
    add(None, "Authenticode signature", pe.get("signature") or "not present")
    add(None, "Overlay", pe.get("overlay") or "none")
    pw = pe.get("parser_warnings") or []
    it = add(None, "Parser warnings", pw or "none")
    if pw:
        it.setForeground(0, QBrush(QColor(SEVERITY["medium"])))
    for i in range(tree.topLevelItemCount()):
        x = tree.topLevelItem(i)
        if x.text(0) in ("File header", "Optional header", "Checksum", "Version info", "TLS callbacks"):
            x.setExpanded(True)
    tree.setColumnWidth(0, 300)
    return _page(title("Headers", "PE headers and directories."), tree)


# --- JSON -------------------------------------------------------------------------------------------

def raw_json(report: dict) -> QWidget:
    ed = QPlainTextEdit()
    ed.setReadOnly(True)
    ed.setFont(mono_font())
    ed.setLineWrapMode(QPlainTextEdit.NoWrap)
    slim = dict(report)
    if "entropy" in slim:
        slim["entropy"] = {**slim["entropy"], "points": f"[{len(slim['entropy'].get('points', []))} points]"}
    ed.setPlainText(json.dumps(slim, indent=2, ensure_ascii=False, default=str))
    return _page(title("JSON report", "The full report (entropy points omitted here; File → Export JSON saves everything)."), ed)


def _ai_notes(report: dict) -> QWidget:
    from .ai_page import ai_notes
    return ai_notes(report)


# --- page registry ---------------------------------------------------------------------------

def _count_label(report: dict, key: str) -> str:
    pe = report["pe"]
    if key == "findings":
        return f"Findings ({len(report['score']['findings'])})"
    if key == "attack":
        return f"ATT&CK ({len(report['score'].get('attack') or [])})"
    if key == "yara":
        ya = report.get("yara")
        return f"YARA ({len(ya['matches'])})" if ya else "YARA"
    if key == "sections":
        return f"Sections ({len(pe['sections'])})"
    if key == "imports":
        return f"Imports ({sum(len(i['functions']) for i in pe['imports'])})"
    if key == "exports":
        return f"Exports ({len(pe['exports']['symbols']) if pe['exports'] else 0})"
    if key == "resources":
        dn_res = (report.get("dotnet") or {}).get("resources", [])
        n_dn = sum(len(r.get("entries") or []) or 1 for r in dn_res)
        n_hidden = len(report.get("hidden_pe") or [])
        return f"Resources ({len(pe['resources']) + n_dn})" + (f" · {n_hidden} hidden PE" if n_hidden else "")
    if key == "strings":
        return f"Strings ({len(report.get('strings') or [])})"
    if key == "crypto":
        return f"Cryptography ({len(report.get('crypto') or [])})"
    if key == "code":
        ct = report.get("code_traits") or {}
        return f"Code techniques ({sum(len(v) for v in ct.values() if isinstance(v, list))})"
    return key


PAGES: list[tuple[str, str | None, Callable[[dict], QWidget], Callable[[dict], bool]]] = [
    ("overview", "Overview", overview, lambda r: True),
    ("findings", None, findings, lambda r: True),
    ("attack", None, attack, lambda r: True),
    ("ai_notes", None, _ai_notes, lambda r: True),
    ("dotnet", ".NET", dotnet, lambda r: bool(r.get("dotnet"))),
    ("crypto", None, crypto, lambda r: True),
    ("yara", None, yara, lambda r: True),
    ("code", None, code, lambda r: not r["pe"]["is_dotnet"]),
    ("strings", None, strings, lambda r: True),
    ("sections", None, sections, lambda r: True),
    ("imports", None, imports, lambda r: True),
    ("exports", None, exports, lambda r: True),
    ("resources", None, resources, lambda r: True),
    ("hex", "Hex", hex_page, lambda r: True),
    ("headers", "Headers", headers, lambda r: True),
    ("json", "JSON", raw_json, lambda r: True),
]


def page_label(report: dict, key: str, label: str | None) -> str:
    if key == "ai_notes":
        from .ai_page import notes_label
        return notes_label(report)
    return label or _count_label(report, key)


def page_color(report: dict, key: str) -> str | None:
    """Color of the side menu entry when the page contains something suspicious."""
    if key == "findings" and report["score"]["findings"]:
        return score_color(report["score"]["score"])
    if key == "yara" and (report.get("yara") or {}).get("matches"):
        return SEVERITY["high"] if any(m["severity"] == "high" for m in report["yara"]["matches"]) else SEVERITY["medium"]
    if key == "crypto" and any(h["confidence"] == "high" and h["category"] not in ("compression", "checksum", "hash")
                               for h in report.get("crypto") or []):
        return SEVERITY["medium"]
    if key == "dotnet" and (report.get("dotnet") or {}).get("metadata_anomalies"):
        return SEVERITY["high"]
    if key == "resources" and any(f["id"] in ("hidden_encrypted_pe", "embedded_pe_in_section", "dotnet_stego_payload", "dotnet_resource_payload", "embedded_pe",
                                              "high_entropy_resource") for f in report["score"]["findings"]):
        return SEVERITY["high"]
    return None
