"""Identification of packers, protectors, installers and compilers/languages (signatures in rules/identify.yaml)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SIGNATURES = Path(__file__).parent / "rules" / "identify.yaml"
MAX_SCAN = 16 * 1024 * 1024


def load_signatures(path: str | Path | None = None) -> list[dict]:
    with open(path or DEFAULT_SIGNATURES, encoding="utf-8") as f:
        return yaml.safe_load(f)["signatures"]


def _ep_regex(pattern: str) -> re.Pattern:
    parts = [b"." if p == "??" else re.escape(bytes([int(p, 16)])) for p in pattern.split()]
    return re.compile(b"".join(parts), re.S)


def _str_regex(s: str) -> re.Pattern:
    if s.startswith("re:"):
        return re.compile(s[3:].encode("latin-1"), re.S)
    return re.compile(re.escape(s.encode("latin-1")))


_GO_FUNC = re.compile(rb"\x00([A-Za-z0-9_./\-]{1,80})\.[A-Za-z0-9_.*()\[\]{},\-]{1,120}(?=\x00)")


def go_obfuscation(data: bytes) -> dict | None:
    """Obfuscated Go binary (garble and similar): Go package names are always lowercase; if many functions
    are in packages with random uppercase letters and digits (e.g. "im1oaIiU3.Xyz"), the names were scrambled."""
    total = weird = 0
    pkgs: set[str] = set()
    for m in _GO_FUNC.finditer(data[:64 * 1024 * 1024]):
        name = m.group(0)[1:].decode("latin-1")
        last = name.rsplit("/", 1)[-1].split(".", 1)[0]     # package name: last segment, before the dot
        if not last or last in ("go", "type", "main"):
            continue
        total += 1
        if any(c.isupper() for c in last) and any(c.isdigit() or c == "_" for c in last) and len(last) >= 5:
            weird += 1
            pkgs.add(last)
    if total >= 500 and weird / total >= 0.15 and len(pkgs) >= 10:
        return {"name": "garble (Go obfuscator)", "type": "obfuscator",
                "evidence": f"{weird} of {total} functions in packages with random names, e.g. "
                            + ", ".join(sorted(pkgs)[:4])}
    return None


def go_user_functions(data: bytes) -> set[str]:
    """Function names of the program itself in a Go binary: package main and third-party modules
    (first path segment with a dot, e.g. github.com/...), without the runtime and the standard library."""
    out = set()
    for m in _GO_FUNC.finditer(data[:64 * 1024 * 1024]):
        name = m.group(0)[1:].decode("latin-1")
        if name.startswith(("type:", "go:", "type.", "go.")):
            continue
        slash = name.rfind("/")
        dot = name.find(".", slash + 1)
        pkg = name[:dot]
        first = pkg.split("/", 1)[0]
        if pkg == "main" or ("." in first and not pkg.startswith(("golang.org/x/", "vendor/"))):
            out.add(name)
    return out


def detect(data: bytes, info: dict[str, Any], ep_bytes: bytes, path: str | None = None) -> list[dict]:
    sections = {s["name"].lower() for s in info["sections"]}
    dlls = {imp["dll"].lower() for imp in info["imports"]}
    body = data[:MAX_SCAN]
    sig_dir = info.get("signature")
    if sig_dir:   # the signature's certificates contain strings of other products: exclude them
        lo, hi = sig_dir["offset"], sig_dir["offset"] + sig_dir["size"]
        body = body[:lo] + body[hi:]
    ov = info.get("overlay")
    overlay = data[ov["offset"]:ov["offset"] + 65536] if ov else b""

    found = []
    for sig in load_signatures(path):
        evidence = None
        for name in sig.get("sections", []):
            if name.lower() in sections:
                evidence = f"section {name}"
                break
        if evidence is None:
            for p in sig.get("ep", []):
                if _ep_regex(p).match(ep_bytes):
                    evidence = f"entry point bytes {p}"
                    break
        if evidence is None:
            for p in sig.get("overlay", []):
                if overlay and _str_regex(p).search(overlay):
                    evidence = "overlay signature"
                    break
        if evidence is None:
            for d in sig.get("imports", []):
                if d.lower() in dlls:
                    evidence = f"imports {d}"
                    break
        if evidence is None:
            for p in sig.get("strings", []):
                m = _str_regex(p).search(body)
                if m:
                    evidence = f"string {m.group()[:40]!r}"[:60]
                    break
        if evidence:
            found.append({"name": sig["name"], "type": sig["type"], "evidence": evidence})
    if any(f["name"] == "Go" for f in found):
        g = go_obfuscation(data)
        if g:
            found.append(g)
    if info.get("is_dotnet"):
        found.append({"name": ".NET", "type": "compiler", "evidence": "CLR header"})
    return found
