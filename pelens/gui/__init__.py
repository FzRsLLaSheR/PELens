"""PELens graphical interface (PySide6)."""
from __future__ import annotations

import sys
import traceback


def main(argv: list[str] | None = None) -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from .theme import apply_theme
    from .window import MainWindow, app_icon

    argv = sys.argv if argv is None else argv
    app = QApplication.instance() or QApplication(argv)
    app.setApplicationName("PELens")
    app.setOrganizationName("PELens")
    app.setWindowIcon(app_icon())
    win = MainWindow()
    apply_theme(app, win.a_dark.isChecked())

    # in the exe without a console an unhandled exception would vanish: show it
    def hook(t, e, tb):
        msg = "".join(traceback.format_exception(t, e, tb))
        sys.stderr.write(msg) if sys.stderr else None
        box = QMessageBox(QMessageBox.Critical, "PELens", f"Unexpected error: {e}", parent=win)
        box.setDetailedText(msg)
        box.exec()

    sys.excepthook = hook
    win.show()
    files = [a for a in argv[1:] if not a.startswith("-")]
    if files:
        win.open_paths(files)
    return app.exec()
