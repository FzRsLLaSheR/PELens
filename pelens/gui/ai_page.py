"""AI Notes page, and the dialogs of the AI bridge (start, client configuration)."""
from __future__ import annotations

import json
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget)

from ..notes import STORE
from .theme import SEVERITY
from .widgets import mono_font, title


def _sha(report: dict) -> str:
    return report["pe"]["hashes"]["sha256"]


def notes_label(report: dict) -> str:
    n = len(STORE.get(_sha(report)))
    return f"AI Notes ({n})" if n else "AI Notes"


def ai_notes(report: dict) -> QWidget:
    sha = _sha(report)
    notes = STORE.get(sha)
    lst = QListWidget()
    view = QTextBrowser()
    view.setOpenExternalLinks(False)
    for n in notes:
        it = QListWidgetItem(f"{n['title']}\n{n['author']} · {n['time'].replace('T', ' ')} · {n['severity']}")
        it.setData(Qt.UserRole, n["id"])
        col = SEVERITY.get(n["severity"])
        if col and n["severity"] not in ("info", "low"):
            it.setForeground(QBrush(QColor(col)))
        lst.addItem(it)

    def show(row: int):
        if 0 <= row < len(notes):
            n = notes[row]
            view.setMarkdown(f"## {n['title']}\n\n*{n['author']} · {n['time'].replace('T', ' ')} · "
                             f"severity: {n['severity']}*\n\n{n['text']}")
        else:
            view.setMarkdown("No notes yet.\n\nStart the **AI bridge** (AI menu) and ask the assistant to explain or "
                             "validate what PELens found: its conclusions appear here. You can also add your own.")
    lst.currentRowChanged.connect(show)

    def add():
        text, ok = QInputDialog.getMultiLineText(view, "Add note", "Note (Markdown):")
        if ok and text.strip():
            first, _, rest = text.strip().partition("\n")
            STORE.add(sha, first[:120], rest.strip() or first, "info", author="analyst")

    def delete():
        it = lst.currentItem()
        if it is not None:
            STORE.delete(sha, int(it.data(Qt.UserRole)))

    def copy_all():
        QGuiApplication.clipboard().setText("\n\n".join(f"## {n['title']} ({n['author']}, {n['severity']})\n\n{n['text']}"
                                                        for n in notes))
    btns = QHBoxLayout()
    for label, fn in (("Add note…", add), ("Delete", delete), ("Copy all", copy_all)):
        b = QPushButton(label)
        b.clicked.connect(fn)
        btns.addWidget(b)
    btns.addStretch(1)
    split = QSplitter()
    split.addWidget(lst)
    split.addWidget(view)
    split.setSizes([280, 720])
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.addWidget(title("AI Notes", "What the AI assistant (through the AI bridge) or you wrote about this file. "
                                    "Kept by SHA-256: they come back when the file is opened again."))
    lay.addLayout(btns)
    lay.addWidget(split, 1)
    if notes:
        lst.setCurrentRow(len(notes) - 1)
    else:
        show(-1)
    return w


# --- AI bridge dialogs -------------------------------------------------------------------------------

class BridgeDialog(QDialog):
    def __init__(self, parent, settings, addresses: list[str]):
        super().__init__(parent)
        self.setWindowTitle("Start AI bridge")
        self.settings = settings
        lay = QVBoxLayout(self)
        info = QLabel("The AI bridge lets an AI assistant on <b>another machine</b> (where your AI accounts and API "
                      "keys are) read what PELens found and write AI notes. It is <b>read-only</b>: it cannot run, "
                      "write or upload anything. Listen only on the network shared with the AI machine (Host-only).")
        info.setWordWrap(True)
        lay.addWidget(info)
        form = QFormLayout()
        self.host = QComboBox()
        self.host.setEditable(True)
        self.host.addItems(addresses)
        last = settings.value("ai/host", "")
        if last:
            self.host.setCurrentText(last)
        self.port = QSpinBox()
        self.port.setRange(1024, 65535)
        self.port.setValue(int(settings.value("ai/port", 47011)))
        self.client = QLineEdit(settings.value("ai/client", ""))
        self.client.setPlaceholderText("optional: only this address may connect (the AI machine)")
        self.token = QLineEdit(settings.value("ai/token", "") or "")
        self.token.setFont(mono_font())
        if not self.token.text():
            from ..bridge import new_token
            self.token.setText(new_token())
        regen = QPushButton("New token")
        regen.clicked.connect(self._regen)
        row = QHBoxLayout()
        row.addWidget(self.token, 1)
        row.addWidget(regen)
        form.addRow("Listen on", self.host)
        form.addRow("Port", self.port)
        form.addRow("Allowed client", self.client)
        form.addRow("Token", row)
        lay.addLayout(form)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Start")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.setMinimumWidth(620)
        self.adjustSize()

    def _regen(self):
        from ..bridge import new_token
        self.token.setText(new_token())

    def accept(self):
        if self.host.currentText().strip() in ("0.0.0.0", ""):
            QMessageBox.warning(self, "PELens", "Choose the address of the network shared with the AI machine, "
                                                "not all interfaces.")
            return
        s = self.settings
        s.setValue("ai/host", self.host.currentText().strip())
        s.setValue("ai/port", self.port.value())
        s.setValue("ai/client", self.client.text().strip())
        s.setValue("ai/token", self.token.text().strip())
        super().accept()


class ClientConfigDialog(QDialog):
    """What to configure on the AI machine."""

    def __init__(self, parent, url: str, token: str):
        super().__init__(parent)
        self.setWindowTitle("AI bridge: configure the AI machine")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"AI bridge running on <b>{url}</b>. On the AI machine, next to <code>pelens_mcp.py</code>, "
                             f"create <code>pelens-mcp.json</code> with this content, then add the MCP server to "
                             f"Claude Desktop or Claude Code:"))
        cfg = json.dumps({"url": url, "token": token}, indent=2)
        tabs = QTabWidget()
        mcp_path = r"C:\PELens-MCP\pelens_mcp.py"
        desktop = json.dumps({"mcpServers": {"pelens": {"command": "python", "args": [mcp_path]}}}, indent=2)
        code = f'claude mcp add --scope user --transport stdio pelens -- python "{mcp_path}"'
        for name, text, hint in (
                ("pelens-mcp.json", cfg, "Next to pelens_mcp.py on the AI machine. The token is a password: do not "
                                         "share it."),
                ("Claude Desktop", desktop, "Settings → Developer → Edit config (claude_desktop_config.json), then "
                                            "restart Claude Desktop. Adjust the path to pelens_mcp.py."),
                ("Claude Code", code, "Run once in a terminal on the AI machine, then /mcp in Claude Code to check "
                                      "it is connected. Adjust the path to pelens_mcp.py.")):
            page = QWidget()
            pl = QVBoxLayout(page)
            h = QLabel(hint)
            h.setWordWrap(True)
            pl.addWidget(h)
            ed = QPlainTextEdit(text)
            ed.setReadOnly(True)
            ed.setFont(mono_font())
            pl.addWidget(ed, 1)
            b = QPushButton("Copy")
            b.clicked.connect(lambda _=False, t=text: QGuiApplication.clipboard().setText(t))
            pl.addWidget(b, 0, Qt.AlignLeft)
            tabs.addTab(page, name)
        lay.addWidget(tabs, 1)
        fw = QLabel("If the AI machine cannot connect: allow PELens through the Windows firewall for this network "
                    "(Windows asks the first time), and check that both machines are on the same Host-only network.")
        fw.setWordWrap(True)
        fw.setObjectName("muted")
        lay.addWidget(fw)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        bb.accepted.connect(self.accept)
        lay.addWidget(bb)
        self.resize(680, 420)


def mcp_script_path() -> str:
    """pelens_mcp.py shipped with PELens (for "Save MCP server script")."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "mcp_server", "pelens_mcp.py")

