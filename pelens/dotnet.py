"""Analysis of .NET assemblies (metadata, not code): APIs used, P/Invoke, user strings, resources, obfuscators.

.NET code is IL bytecode: instead of disassembling it we read the metadata tables with dnfile.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from . import dotnet_il, dotnet_resources, entropy

DEFAULT_SIGNATURES = Path(__file__).parent / "rules" / "dotnet.yaml"
_PRINTABLE_NAME = re.compile(r"^[A-Za-z_<>`.$][A-Za-z0-9_<>`.$|@-]*$")


def _s(x) -> str:
    if x is None:
        return ""
    v = getattr(x, "value", x)
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)


def _readable(s: str, limit: int = 80) -> str:
    """Makes invisible characters (zero-width, directional, control) visible as \\uXXXX."""
    import unicodedata
    out = "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp") else c
                  for c in s)
    return out[:limit]


def _type_name(row) -> str:
    if row is None:
        return ""
    if hasattr(row, "TypeName"):
        ns = _s(getattr(row, "TypeNamespace", ""))
        return f"{ns}.{_s(row.TypeName)}" if ns else _s(row.TypeName)
    return ""


def _user_strings(pe) -> list[str]:
    """Strings of the #US heap (literals used by the code), read directly from the heap bytes."""
    us = getattr(pe.net, "user_strings", None)
    if us is None:
        return []
    raw = bytes(us.__data__) if hasattr(us, "__data__") else b""
    out, i = [], 1
    while i < len(raw):
        b0 = raw[i]
        if b0 & 0x80 == 0:
            n, i = b0, i + 1
        elif b0 & 0xC0 == 0x80 and i + 1 < len(raw):
            n, i = ((b0 & 0x3F) << 8) | raw[i + 1], i + 2
        elif i + 3 < len(raw):
            n, i = ((b0 & 0x1F) << 24) | (raw[i + 1] << 16) | (raw[i + 2] << 8) | raw[i + 3], i + 4
        else:
            break
        if n == 0:
            continue
        data = raw[i:i + n - 1] if n % 2 else raw[i:i + n]   # the last (odd) byte is a flag
        i += n
        try:
            s = data.decode("utf-16le")
        except UnicodeDecodeError:
            continue
        if s.strip():
            out.append(s)
        if len(out) >= 20000:
            break
    return out


# --- Direct reading of the metadata root (resists anti-analysis tricks) ----------------------

_STD_STREAMS = {"#~", "#-", "#Strings", "#US", "#GUID", "#Blob"}


def _metadata_streams(pe) -> tuple[list[dict], bytes]:
    """List of the metadata streams (duplicates too) read directly from the "BSJB" root."""
    import struct
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dd) <= 14 or not dd[14].VirtualAddress:
        return [], b""
    data = bytes(pe.__data__)   # pefile may use an mmap: we copy it into bytes
    cor = pe.get_offset_from_rva(dd[14].VirtualAddress)
    md_rva, md_size = struct.unpack_from("<II", data, cor + 8)
    root = pe.get_offset_from_rva(md_rva)
    if data[root:root + 4] != b"BSJB":
        return [], b""
    vlen = struct.unpack_from("<I", data, root + 12)[0]
    pos = root + 16 + vlen
    n_streams = struct.unpack_from("<H", data, pos + 2)[0]
    pos += 4
    streams = []
    for _ in range(min(n_streams, 64)):
        off, size = struct.unpack_from("<II", data, pos)
        end = data.index(b"\x00", pos + 8)
        name = data[pos + 8:end].decode("latin-1", errors="replace")
        pos = (end + 4) & ~3
        start = root + off
        streams.append({"name": name, "offset": start, "size": size, "data": bytes(data[start:start + size])})
    return streams, bytes(data[root:root + md_size])


def _strings_heap_names(raw: bytes) -> list[str]:
    return [x.decode("utf-8", errors="replace") for x in raw.split(b"\x00") if x]


def _plausibility_strings(raw: bytes) -> float:
    names = _strings_heap_names(raw[:200000])
    if not names or raw[:1] != b"\x00":
        return 0.0
    ok = sum(1 for n in names if _PRINTABLE_NAME.match(n) or n.startswith("<"))
    return ok / len(names)


def _parse_us_heap(raw: bytes) -> list[str]:
    out, i = [], 1
    while i < len(raw):
        b0 = raw[i]
        if b0 & 0x80 == 0:
            n, i = b0, i + 1
        elif b0 & 0xC0 == 0x80 and i + 1 < len(raw):
            n, i = ((b0 & 0x3F) << 8) | raw[i + 1], i + 2
        elif i + 3 < len(raw):
            n, i = ((b0 & 0x1F) << 24) | (raw[i + 1] << 16) | (raw[i + 2] << 8) | raw[i + 3], i + 4
        else:
            break
        if n == 0:
            continue
        if i + n > len(raw):
            break
        data = raw[i:i + n - 1] if n % 2 else raw[i:i + n]
        i += n
        try:
            text = data.decode("utf-16le")
        except UnicodeDecodeError:
            continue
        if text.strip():
            out.append(text)
        if len(out) >= 20000:
            break
    return out


def _plausibility_us(raw: bytes) -> float:
    if raw[:1] != b"\x00":
        return 0.0
    strings = _parse_us_heap(raw[:200000])
    if not strings:
        return 0.0
    ok = sum(1 for x in strings if sum(c.isprintable() for c in x) >= 0.9 * len(x))
    return ok / len(strings)


def _pick(streams: list[dict], name: str, score) -> dict | None:
    cands = [st for st in streams if st["name"] == name]
    if not cands:
        return None
    return max(cands, key=lambda st: (score(st["data"]), st["size"]))


def load_signatures(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_SIGNATURES, encoding="utf-8") as f:
        return yaml.safe_load(f)


def analyze(path: str, signatures: str | None = None) -> dict[str, Any]:
    import logging
    import warnings

    import dnfile   # imported here: only needed for .NET files

    # dnfile reports malformed metadata with thousands of warnings: we silence them and summarize them ourselves
    sigs = load_signatures(signatures)
    logging.disable(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                pe = dnfile.dnPE(path)
            except Exception as e:
                # metadata so broken that dnfile fails: read the heaps directly with pefile
                import pefile
                pe = pefile.PE(path)
                try:
                    streams, _ = _metadata_streams(pe)
                    anomalies = _stream_anomalies(streams) + [f"metadata could not be parsed ({type(e).__name__})"]
                    return _analyze_heaps(streams, sigs, anomalies)
                finally:
                    pe.close()
            try:
                return _analyze(pe, sigs)
            finally:
                pe.close()
    finally:
        logging.disable(logging.NOTSET)


def _stream_anomalies(streams: list[dict]) -> list[str]:
    names = [st["name"] for st in streams]
    out = [f"duplicate metadata stream {n} (x{names.count(n)})" for n in sorted({n for n in names if names.count(n) > 1})]
    out += [f"non-standard metadata stream {n!r}" for n in names if n not in _STD_STREAMS]
    return out


def _analyze(pe, sigs: dict) -> dict[str, Any]:
    streams, _ = _metadata_streams(pe)
    anomalies = _stream_anomalies(streams)

    net = pe.net
    md = getattr(net, "mdtables", None) if net else None
    tables_ok = md is not None and bool(getattr(md, "TypeDef", None))
    if not tables_ok:
        anomalies.append("metadata tables could not be parsed")
        return _analyze_heaps(streams, sigs, anomalies)

    def rows(name):
        t = getattr(md, name, None)
        return list(t) if t else []

    asm = rows("Assembly")
    module = rows("Module")
    typedefs = [_type_name(t) for t in rows("TypeDef")]
    typerefs = [_type_name(t) for t in rows("TypeRef")]
    methods = [_s(m.Name) for m in rows("MethodDef")]
    memberrefs = []
    for r in rows("MemberRef"):
        cls = r.Class.row if r.Class is not None else None
        memberrefs.append(f"{_type_name(cls)}::{_s(r.Name)}" if _type_name(cls) else f"?::{_s(r.Name)}")
    # type that contains each method (from the TypeDef MethodList lists) and IL code analysis
    type_of = [""] * len(methods)
    for t in rows("TypeDef"):
        for ref in getattr(t, "MethodList", None) or []:
            i = getattr(ref, "row_index", 0)
            if 0 < i <= len(type_of):
                type_of[i - 1] = _type_name(t)
    try:
        il = dotnet_il.analyze(pe, bytes(pe.__data__), methods, type_of, memberrefs)
    except Exception as e:
        il = {"error": str(e)}
    pinvoke = []
    for r in rows("ImplMap"):
        scope = r.ImportScope.row if r.ImportScope is not None else None
        pinvoke.append({"name": _s(r.ImportName), "dll": _s(getattr(scope, "Name", ""))})
    asm_refs = [_s(r.Name) for r in rows("AssemblyRef")]

    resources = []
    raw_file = bytes(pe.__data__)
    for res in getattr(net, "resources", None) or []:
        # the raw bytes: dnfile replaces res.data with the already parsed ResourceSet when it is a .resources
        data, off = b"", None
        rva, size = getattr(res, "rva", None), getattr(res, "size", None)
        if rva and size:
            try:
                off = pe.get_offset_from_rva(rva)
                data = raw_file[off:off + size]
            except Exception:
                off = None
        if not data and isinstance(res.data, (bytes, bytearray)):
            data = bytes(res.data)
        if not data and getattr(res.data, "_data", None):
            data = bytes(res.data._data)
        resources.append({"name": _s(res.name), **dotnet_resources.analyze_resource(data, off)})
    us = _pick(streams, "#US", _plausibility_us)
    user_strings = _parse_us_heap(us["data"]) if us else _user_strings(pe)

    # --- API categories ---------------------------------------------------------------------
    ref_set = set(memberrefs)
    pinv_set = {p["name"].lower() for p in pinvoke}
    categories = {}
    for cid, cat in (sigs.get("api_categories") or {}).items():
        hits = [m for m in cat.get("methods", []) if m in ref_set]
        hits += [f"P/Invoke {p}" for p in cat.get("pinvoke", []) if p.lower() in pinv_set]
        if len(hits) >= cat.get("min", 1):
            categories[cid] = {"title": cat["title"], "hits": hits}

    # --- obfuscators / packers ------------------------------------------------------------------
    names_pool = typedefs + typerefs + methods + [r["name"] for r in resources] + asm_refs + \
        [_s(m.Name) for m in module] + user_strings[:2000]
    obfuscators = []
    for ob in sigs.get("obfuscators") or []:
        for pat in ob["patterns"]:
            rx = re.compile(pat)
            hit = next((n for n in names_pool if rx.search(n)), None)
            if hit is not None:
                obfuscators.append({"name": ob["name"], "type": ob["type"], "evidence": _readable(hit)})
                break

    # unreadable names: non-printable/non-ASCII characters or random names in types and methods defined by the assembly
    own = [n for n in typedefs + methods if n and n not in ("<Module>", ".ctor", ".cctor")]
    weird = [n for n in own if not _PRINTABLE_NAME.match(n.split(".")[-1])]
    obf_ratio = round(len(weird) / len(own), 3) if own else 0.0

    return {
        "assembly": _s(asm[0].Name) if asm else "",
        "version": f"{asm[0].MajorVersion}.{asm[0].MinorVersion}.{asm[0].BuildNumber}.{asm[0].RevisionNumber}" if asm else "",
        "module": _s(module[0].Name) if module else "",
        "counts": {"types": len(typedefs), "methods": len(methods), "member_refs": len(memberrefs),
                   "pinvoke": len(pinvoke), "resources": len(resources), "user_strings": len(user_strings)},
        "assembly_refs": asm_refs,
        "pinvoke": pinvoke[:200],
        "api_categories": categories,
        "resources": resources[:100],
        "obfuscators": obfuscators,
        "obfuscated_names": {"ratio": obf_ratio, "examples": [repr(n)[:40] for n in weird[:5]], "total": len(own)},
        "metadata_anomalies": anomalies,
        "parser": "metadata tables",
        "il": il,
        "user_strings": user_strings,
    }


def _analyze_heaps(streams: list[dict], sigs: dict, anomalies: list[str]) -> dict[str, Any]:
    """Unreadable tables (often on purpose): we get names and strings directly from the heaps.

    Without tables we do not know which type each method belongs to: an API counts if both the type name and
    the method name appear in the #Strings heap. Less precise, but it resists tampered metadata.
    """
    st = _pick(streams, "#Strings", _plausibility_strings)
    us = _pick(streams, "#US", _plausibility_us)
    names = set(_strings_heap_names(st["data"])) if st else set()
    user_strings = _parse_us_heap(us["data"]) if us else []

    categories = {}
    for cid, cat in (sigs.get("api_categories") or {}).items():
        hits = []
        for m in cat.get("methods", []):
            typ, meth = m.split("::")
            tname = typ.split(".")[-1]
            if tname in names and (meth in (".ctor",) or meth in names):
                hits.append(m)
        hits += [f"P/Invoke {p}" for p in cat.get("pinvoke", []) if p in names]
        if len(hits) >= cat.get("min", 1):
            categories[cid] = {"title": cat["title"], "hits": hits}

    pool = list(names) + user_strings[:2000]
    obfuscators = []
    for ob in sigs.get("obfuscators") or []:
        for pat in ob["patterns"]:
            rx = re.compile(pat)
            hit = next((n for n in pool if rx.search(n)), None)
            if hit is not None:
                obfuscators.append({"name": ob["name"], "type": ob["type"], "evidence": _readable(hit)})
                break
    weird = [n for n in names if not _PRINTABLE_NAME.match(n) and not n.startswith("<")]
    return {
        "assembly": "", "version": "", "module": "",
        "counts": {"types": 0, "methods": 0, "member_refs": 0, "pinvoke": 0, "resources": 0,
                   "user_strings": len(user_strings), "heap_names": len(names)},
        "assembly_refs": [], "pinvoke": [], "api_categories": categories, "resources": [],
        "obfuscators": obfuscators,
        "obfuscated_names": {"ratio": round(len(weird) / len(names), 3) if names else 0.0,
                             "examples": [repr(n)[:40] for n in list(weird)[:5]], "total": len(names)},
        "metadata_anomalies": anomalies,
        "parser": "heaps (tables unreadable)",
        "user_strings": user_strings,
    }
