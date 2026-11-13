"""Analysis of several files: list of PE files, a summary row for each, CSV export."""
from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Iterable

COLUMNS = ["file", "score", "verdict", "type", "identified", "top_findings", "crypto", "hidden_pe", "yara",
           "attack", "imphash", "sha256", "path"]


def is_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(0x400)
        if head[:2] != b"MZ" or len(head) < 0x40:
            return False
        lf = int.from_bytes(head[0x3C:0x40], "little")
        if lf + 4 <= len(head):
            return head[lf:lf + 4] == b"PE\0\0"
        with open(path, "rb") as f:
            f.seek(lf)
            return f.read(4) == b"PE\0\0"
    except OSError:
        return False


def collect(paths: Iterable[str], recursive: bool = False) -> list[str]:
    """The given PE files, also inside folders (only those starting with a valid PE header)."""
    import glob as _glob
    out = []
    expanded = []
    for p in paths:
        # Windows cmd does not expand wildcards: it is done here (*.exe, sample_??.dll, **\*.dll with -r)
        if any(c in str(p) for c in "*?["):
            expanded += sorted(_glob.glob(str(p), recursive=recursive)) or [str(p)]
        else:
            expanded.append(str(p))
    for p in expanded:
        p = Path(p)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            out += sorted(str(f) for f in it if f.is_file() and is_pe(f))
        elif p.is_file() and any(c in str(paths) for c in "*?[") and not is_pe(p):
            continue   # with wildcards, files that are not PEs are skipped
        else:
            out.append(str(p))
    return list(dict.fromkeys(out))


def summary(report: dict) -> dict:
    pe = report["pe"]
    sc = report["score"]
    crypto = sorted({h["algorithm"] for h in report.get("crypto") or [] if h["confidence"] != "low"})
    hidden = [f"0x{h['offset']:x}" + (f" xor {h['key']}" if h["encrypted"] else "")
              for h in report.get("hidden_pe") or []]
    for r in (report.get("dotnet") or {}).get("resources", []):
        for e in r.get("entries", []):
            hp = (e.get("image") or {}).get("hidden_pe")
            if hp:
                hidden.append(f"{e['name']} (pixels" + (f", xor {hp['key']})" if hp["encrypted"] else ")"))
    return {
        "file": report["file"]["name"],
        "score": sc["score"],
        "verdict": sc["verdict"],
        "type": f"{pe['format']} {pe['kind']} {pe['machine']}" + (" .NET" if pe["is_dotnet"] else ""),
        "identified": ", ".join(i["name"] for i in report.get("identification") or []),
        "top_findings": "; ".join(f["title"] for f in sc["findings"][:4]),
        "crypto": ", ".join(crypto),
        "hidden_pe": ", ".join(hidden),
        "yara": ", ".join(m["rule"] for m in (report.get("yara") or {}).get("matches", [])),
        "attack": ", ".join(t["id"] for t in sc.get("attack") or []),
        "imphash": pe.get("imphash") or "",
        "sha256": pe["hashes"]["sha256"],
        "path": report["file"].get("path", ""),
    }


def write_csv(rows: list[dict], out: str) -> None:
    with open(out, "w", newline="", encoding="utf-8-sig") as f:   # utf-8-sig: Excel opens it correctly
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def error_row(path: str, msg: str) -> dict:
    return {"file": os.path.basename(path), "score": "", "verdict": f"error: {msg}", "path": path}
