"""AI notes: what an AI assistant (through the AI bridge) or the analyst wrote about a file.

Notes are kept per file (by SHA-256) in the user's application data folder, so they come back when the same file
is opened again, on any path.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _folder() -> str:
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "PELens", "notes")


class NotesStore:
    def __init__(self, folder: str | None = None):
        self.folder = folder or _folder()
        self.lock = threading.Lock()
        self.cache: dict[str, list[dict]] = {}
        self.listeners: list = []                     # called with the sha256 of a file whose notes changed

    def _path(self, sha256: str) -> str:
        return os.path.join(self.folder, f"{sha256.lower()}.json")

    def get(self, sha256: str) -> list[dict]:
        with self.lock:
            if sha256 not in self.cache:
                try:
                    with open(self._path(sha256), encoding="utf-8") as fh:
                        self.cache[sha256] = json.load(fh)
                except (OSError, ValueError):
                    self.cache[sha256] = []
            return [dict(n) for n in self.cache[sha256]]

    def add(self, sha256: str, title: str, text: str, severity: str = "info", author: str = "AI") -> dict:
        severity = severity if severity in SEVERITIES else "info"
        note = {"id": 0, "time": dt.datetime.now().isoformat(timespec="seconds"), "author": author[:40],
                "title": title.strip()[:200] or "Note", "severity": severity, "text": text.strip()[:20000]}
        self.get(sha256)
        with self.lock:
            notes = self.cache[sha256]
            note["id"] = max((n["id"] for n in notes), default=0) + 1
            notes.append(note)
            self._save(sha256)
        self._changed(sha256)
        return dict(note)

    def delete(self, sha256: str, note_id: int) -> bool:
        self.get(sha256)
        with self.lock:
            notes = self.cache[sha256]
            keep = [n for n in notes if n["id"] != note_id]
            if len(keep) == len(notes):
                return False
            self.cache[sha256] = keep
            self._save(sha256)
        self._changed(sha256)
        return True

    def clear(self, sha256: str) -> None:
        with self.lock:
            self.cache[sha256] = []
            self._save(sha256)
        self._changed(sha256)

    def _save(self, sha256: str) -> None:
        try:
            os.makedirs(self.folder, exist_ok=True)
            tmp = self._path(sha256) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.cache[sha256], fh, indent=1, ensure_ascii=False)
            os.replace(tmp, self._path(sha256))
        except OSError:
            pass

    def _changed(self, sha256: str) -> None:
        for cb in list(self.listeners):
            try:
                cb(sha256)
            except Exception:
                pass


STORE = NotesStore()
