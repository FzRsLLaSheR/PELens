"""User YARA rules: matches become findings with a weight.

Rules are looked for in: paths passed explicitly (--yara, GUI setting), the PELENS_YARA environment
variable (several paths separated by os.pathsep), a "yara" folder next to the executable.
Each file is compiled on its own: a rule with errors does not block the others.
Weight: meta "weight" if present, otherwise meta "score" (0-100, as in signature-base) halved, otherwise 25.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

EXTS = {".yar", ".yara", ".rule", ".rules"}
DEFAULT_WEIGHT = 25
_cache: dict[tuple, tuple[list, list[str]]] = {}

# external variables used by many public collections (e.g. signature-base)
_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


def default_paths() -> list[str]:
    out = [p for p in os.environ.get("PELENS_YARA", "").split(os.pathsep) if p]
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()
    if (base / "yara").is_dir():
        out.append(str(base / "yara"))
    return out


def rule_files(paths: list[str]) -> list[Path]:
    files = []
    for p in paths:
        p = Path(p).expanduser()
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in EXTS)
    return list(dict.fromkeys(files))


def _compile(files: list[Path]) -> tuple[list, list[str]]:
    import yara
    key = tuple((str(f), f.stat().st_mtime) for f in files)
    if key in _cache:
        return _cache[key]
    compiled, errors = [], []
    for f in files:
        try:
            compiled.append((f, yara.compile(filepath=str(f), externals=_EXTERNALS)))
        except yara.Error as e:
            errors.append(f"{f.name}: {e}")
    _cache.clear()
    _cache[key] = (compiled, errors)
    return compiled, errors


def _weight(meta: dict) -> int:
    for k in ("weight", "pelens_weight"):
        if k in meta:
            try:
                return max(0, min(100, int(meta[k])))
            except (TypeError, ValueError):
                pass
    if "score" in meta:
        try:
            return max(5, min(40, int(meta["score"]) // 2))
        except (TypeError, ValueError):
            pass
    return DEFAULT_WEIGHT


def scan(data: bytes, path: str, kind: str, paths: list[str] | None) -> dict:
    """Runs the rules on the file. Returns {rules_files, matches, errors} (empty if there are no rules)."""
    paths = default_paths() if paths is None else paths
    files = rule_files(paths)
    if not files:
        return {}
    if not available():
        return {"rule_files": len(files), "rules": 0, "sources": [str(Path(p)) for p in paths], "matches": [],
                "errors": ["yara-python is not installed: YARA rules were not run"]}
    compiled, errors = _compile(files)
    p = Path(path)
    ext = {"filename": p.name, "filepath": str(p.parent), "extension": p.suffix.lower(),
           "filetype": kind.upper(), "owner": ""}
    matches = []
    for f, rules in compiled:
        try:
            res = rules.match(data=data, externals=ext, timeout=60)
        except Exception as e:  # timeout or error of a rule
            errors.append(f"{f.name}: {e}")
            continue
        for m in res:
            meta = dict(m.meta)
            hits = []
            for s in m.strings[:10]:
                for inst in s.instances[:3]:
                    data_ = bytes(inst.matched_data[:48])
                    shown = data_.decode("latin-1") if all(32 <= b < 127 for b in data_) else data_.hex(" ")
                    hits.append({"id": s.identifier, "offset": inst.offset, "length": inst.matched_length,
                                 "data": shown})
            w = _weight(meta)
            matches.append({
                "rule": m.rule, "namespace": m.namespace, "file": f.name, "tags": list(m.tags),
                "description": str(meta.get("description", "")), "author": str(meta.get("author", "")),
                "weight": w, "severity": "high" if w >= 25 else "medium" if w >= 10 else "low",
                "attack": [t.strip() for t in str(meta.get("mitre_att", meta.get("attack", ""))).replace(";", ",")
                           .split(",") if t.strip().startswith("T")],
                "strings": hits,
            })
    n_rules = 0
    for _f, rules in compiled:
        try:
            n_rules += sum(1 for _ in rules)
        except TypeError:
            pass
    return {"rule_files": len(files), "rules": n_rules, "sources": [str(Path(p)) for p in paths],
            "matches": matches, "errors": errors}
