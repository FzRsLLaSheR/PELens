"""Extraction of structural information from a PE file (based on pefile)."""
from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from pathlib import Path

import pefile
from pefile import ordlookup

from . import entropy

SCN_CNT_CODE = 0x00000020
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

DIR_SECURITY = 4
DIR_CLR = 14


def _s(b) -> str:
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    if isinstance(b, (bytes, bytearray)):
        return bytes(b).decode("latin-1", errors="replace").rstrip("\x00")
    # pefile objects (e.g. UnicodeStringWrapperPostProcessor for resource names)
    raw = getattr(b, "string", None)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", errors="replace").rstrip("\x00")
    try:
        return str(b).rstrip("\x00")
    except Exception:
        return ""


def _struct_to_dict(struct) -> dict[str, Any]:
    out = {}
    for key, val in struct.dump_dict().items():
        if key == "Structure":
            continue
        v = val.get("Value") if isinstance(val, dict) else val
        if isinstance(v, bytes):
            v = v.hex()
        out[key] = v
    return out


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _flags(ch: int) -> str:
    return ("R" if ch & SCN_MEM_READ else "-") + ("W" if ch & SCN_MEM_WRITE else "-") + (
        "X" if ch & SCN_MEM_EXECUTE else "-")


_DIRS = [pefile.DIRECTORY_ENTRY[d] for d in (
    "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_DEBUG", "IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")]


def load(data: bytes) -> pefile.PE:
    """Loads the PE reading only the directories we use (the x64 exception table is slow and useless here)."""
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=_DIRS)
    return pe


def parse(data: bytes, pe: pefile.PE | None = None) -> dict[str, Any]:
    """Parses the bytes of a PE and returns a JSON-serializable dictionary."""
    if pe is not None:
        return _parse(pe, data)
    pe = load(data)
    try:
        return _parse(pe, data)
    finally:
        pe.close()


def _parse(pe: pefile.PE, data: bytes) -> dict[str, Any]:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is64 = oh.Magic == 0x20B
    ts = fh.TimeDateStamp

    info: dict[str, Any] = {
        "size": len(data),
        "hashes": _hashes(data),
        "imphash": _safe(pe.get_imphash) or "",
        "entropy": round(entropy.shannon(data), 4),
        "format": "PE32+" if is64 else "PE32",
        "kind": "driver" if _safe(pe.is_driver) else ("dll" if pe.is_dll() else "exe"),
        "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)).replace("IMAGE_FILE_MACHINE_", ""),
        "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)).replace("IMAGE_SUBSYSTEM_", ""),
        "timestamp": ts,
        "timestamp_utc": _ts_to_str(ts),
        "is_dotnet": oh.DATA_DIRECTORY[DIR_CLR].VirtualAddress != 0 if len(oh.DATA_DIRECTORY) > DIR_CLR else False,
        "image_base": oh.ImageBase,
        "entry_point_rva": oh.AddressOfEntryPoint,
        # computing the checksum is slow (pure Python): only needed if the header has one to compare
        "checksum": {"stored": oh.CheckSum, "computed": _safe(pe.generate_checksum) if oh.CheckSum else None},
        "headers": {
            "dos": _struct_to_dict(pe.DOS_HEADER),
            "file": _struct_to_dict(fh),
            "optional": _struct_to_dict(oh),
            "characteristics": [n for n, v in pefile.image_characteristics if fh.Characteristics & v],
            "dll_characteristics": [n for n, v in pefile.dll_characteristics if oh.DllCharacteristics & v],
        },
        "parser_warnings": list(pe.get_warnings())[:50],
    }

    # each part is read on its own: an error on a weird PE leaves only that part empty
    def part(name, fn, default):
        try:
            info[name] = fn()
        except Exception as e:
            info[name] = default
            info["parser_warnings"].append(f"PELens could not read {name.replace('_', ' ')}: {type(e).__name__}: {e}")

    part("rich", lambda: _rich(pe), None)
    info["rich_removed"] = not info["rich"] and _rich_removed(data)
    part("sections", lambda: _sections(pe), [])
    info["entry_point_section"] = _section_of_rva(info["sections"], oh.AddressOfEntryPoint)
    part("imports", lambda: _imports(pe), [])
    part("exports", lambda: _exports(pe), None)
    part("resources", lambda: _resources(pe, data), [])
    part("tls_callbacks", lambda: _tls_callbacks(pe, is64), [])
    part("debug", lambda: _debug(pe), [])
    part("version_info", lambda: _version_info(pe), {})
    part("signature", lambda: _signature(pe), None)
    part("protections", lambda: _protections(pe, data, is64), [])
    part("consistency", lambda: consistency(info), [])
    part("overlay", lambda: _overlay(pe, data, info["signature"]), None)
    return info


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _ts_to_str(ts: int) -> str:
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "invalid"


def _rich(pe: pefile.PE) -> dict[str, Any] | None:
    rh = getattr(pe, "RICH_HEADER", None)
    parsed = pe.parse_rich_header()   # with fast_load pefile does not parse it by itself
    if rh is None and parsed:
        rh = type("Rich", (), {"values": parsed["values"]})()
    if not rh:
        return None
    valid = _rich_checksum_ok(pe.__data__, parsed) if parsed else None
    vals = rh.values
    entries = []
    for i in range(0, len(vals) - 1, 2):
        compid, count = vals[i], vals[i + 1]
        pid, build = compid >> 16, compid & 0xFFFF
        tool, version = _rich_tool(pid, build)
        entries.append({"product_id": pid, "build": build, "count": count, "tool": tool, "version": version})
    # summary: what it was linked and compiled with
    linker = next((e for e in entries if e["tool"] == "Linker"), None)
    comp = sorted((e for e in entries if "compiler" in e["tool"]), key=lambda e: -e["count"])
    parts = []
    if linker:
        parts.append(f"linker {linker['version'] or 'build ' + str(linker['build'])}")
    if comp:
        parts.append(f"{comp[0]['tool']} {comp[0]['version'] or 'build ' + str(comp[0]['build'])}")
    return {"entries": entries, "hash": hashlib.md5(parsed["clear_data"]).hexdigest() if parsed and parsed.get("clear_data") else "", "summary": ", ".join(parts),
            "checksum_ok": valid}


def _rich_removed(data: bytes) -> bool:
    """Microsoft DOS header with a zeroed gap between the stub (0x80) and the PE header: the Rich header was there.

    The other linkers (GCC, Go, Delphi, lld) put the PE header right after the stub or use a different stub;
    the Microsoft linker without a Rich header (/emittoolversioninfo:no) leaves no gap either."""
    lf = int.from_bytes(data[0x3C:0x40], "little")
    if not 0x80 + 16 <= lf <= 0x400 or len(data) < lf:
        return False
    if not data[0x4E:0x80].startswith(b"This program cannot be run in DOS mode"):
        return False
    return not any(data[0x80:lf])


def _rich_checksum_ok(data, parsed) -> bool | None:
    """The linker encrypts the Rich header with a checksum of the DOS header and of the entries:
    if it does not match, the Rich header was copied from another file or edited by hand."""
    raw = parsed.get("raw_data") or b""
    start = bytes(data[:0x1000]).find(raw[:8]) if raw else -1
    if start <= 0:
        return None
    key = parsed["key"]
    key = int.from_bytes(key, "little") if isinstance(key, (bytes, bytearray)) else key
    rol = lambda v, n: ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF if n else v
    c = start
    for i in range(start):
        if 0x3C <= i < 0x40:            # e_lfanew excluded
            continue
        c = (c + rol(data[i], i % 32)) & 0xFFFFFFFF
    v = parsed["values"]
    for i in range(0, len(v) - 1, 2):
        c = (c + rol(v[i], v[i + 1] % 32)) & 0xFFFFFFFF
    return c == key


_RICH: dict | None = None


def _rich_tool(pid: int, build: int) -> tuple[str, str]:
    """Tool and Visual Studio version of a Rich header entry (rules/rich.yaml)."""
    global _RICH
    if _RICH is None:
        import yaml
        try:
            with open(Path(__file__).parent / "rules" / "rich.yaml", encoding="utf-8") as f:
                _RICH = yaml.safe_load(f) or {}
        except OSError:
            _RICH = {}
    prod = (_RICH.get("products") or {}).get(pid)
    if not prod:
        return f"unknown tool 0x{pid:x}", ""
    version = prod.get("version", "")
    if not version and pid >= 0xFD and build:
        for row in _RICH.get("builds") or []:
            if build >= row["from"]:
                version = row["version"]
    return prod["tool"], version


def _sections(pe: pefile.PE) -> list[dict[str, Any]]:
    out = []
    for s in pe.sections:
        raw = s.get_data()
        ch = s.Characteristics
        out.append({
            "name": _s(s.Name),
            "virtual_address": s.VirtualAddress,
            "virtual_size": s.Misc_VirtualSize,
            "raw_offset": s.PointerToRawData,
            "raw_size": s.SizeOfRawData,
            "characteristics": ch,
            "flags": _flags(ch),
            "executable": bool(ch & SCN_MEM_EXECUTE),
            "writable": bool(ch & SCN_MEM_WRITE),
            "contains_code": bool(ch & SCN_CNT_CODE),
            "entropy": round(entropy.shannon(raw), 4),
            "md5": hashlib.md5(raw).hexdigest(),
        })
    return out


def _section_of_rva(sections: list[dict], rva: int) -> str | None:
    for s in sections:
        size = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= rva < s["virtual_address"] + size:
            return s["name"]
    return None


def _imports(pe: pefile.PE) -> list[dict[str, Any]]:
    out = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            funcs, ords = [], {}
            for imp in entry.imports:
                if imp.name:
                    funcs.append(_s(imp.name))
                    continue
                # import by number: for ws2_32/wsock32/oleaut32 the name is known (pefile's table)
                name = _safe(lambda: ordlookup.ordLookup(entry.dll.lower(), imp.ordinal))
                name = _s(name) if name else f"ordinal_{imp.ordinal}"
                funcs.append(name)
                ords[name] = imp.ordinal
            item = {"dll": _s(entry.dll), "delayed": delayed, "functions": funcs}
            if ords:
                item["by_ordinal"] = ords
            out.append(item)
    return out


def _exports(pe: pefile.PE) -> dict[str, Any] | None:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exp:
        return None
    return {
        "name": _s(pe.get_string_at_rva(exp.struct.Name)) if exp.struct.Name else "",
        "timestamp": exp.struct.TimeDateStamp,
        "symbols": [
            {"ordinal": sym.ordinal, "name": _s(sym.name), "rva": sym.address,
             "forwarder": _s(sym.forwarder)}
            for sym in exp.symbols[:5000]
        ],
    }


def _resources(pe: pefile.PE, data: bytes) -> list[dict[str, Any]]:
    out = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return out
    for rtype in root.entries:
        tname = _s(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(rtype.id, str(rtype.id))
        for rname in getattr(getattr(rtype, "directory", None), "entries", []):
            name = _s(rname.name) if rname.name else str(rname.id)
            for rlang in getattr(getattr(rname, "directory", None), "entries", []):
                d = getattr(rlang, "data", None)
                if d is None:
                    continue
                rva, size = d.struct.OffsetToData, d.struct.Size
                off = _safe(lambda: pe.get_offset_from_rva(rva))
                blob = data[off:off + size] if off is not None else b""
                out.append({
                    "type": tname, "name": name, "lang": d.lang, "rva": rva, "offset": off,
                    "size": size, "entropy": round(entropy.shannon(blob), 4),
                    "magic": blob[:4].hex(), "embedded_pe": blob[:2] == b"MZ",
                })
                if len(out) >= 2000:
                    return out
    return out


def _tls_callbacks(pe: pefile.PE, is64: bool) -> list[int]:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls or not tls.struct.AddressOfCallBacks:
        return []
    callbacks = []
    rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
    read = pe.get_qword_at_rva if is64 else pe.get_dword_at_rva
    for i in range(64):
        va = _safe(lambda: read(rva + i * (8 if is64 else 4)))
        if not va:
            break
        callbacks.append(va)
    return callbacks


def _protections(pe: pefile.PE, data: bytes, is64: bool) -> list[dict[str, str]]:
    """Protections of the binary (mitigations): ASLR, DEP, CFG, SafeSEH, /GS, CET..."""
    oh = pe.OPTIONAL_HEADER
    dc = oh.DllCharacteristics
    dd = oh.DATA_DIRECTORY
    has_reloc = len(dd) > 5 and dd[5].Size > 0
    lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    lcs = lc.struct if lc else None
    dotnet = len(dd) > 14 and dd[14].VirtualAddress != 0
    out = []

    def add(name, state, detail=""):
        out.append({"name": name, "state": state, "detail": detail})

    if dc & 0x40:
        if has_reloc or pe.is_dll():
            add("ASLR", "on", "DYNAMIC_BASE")
        else:
            add("ASLR", "weak", "DYNAMIC_BASE set but relocations stripped: the image cannot move")
    else:
        add("ASLR", "off", "no DYNAMIC_BASE: always loaded at the same address")
    if is64:
        add("High-entropy ASLR", "on" if dc & 0x20 else "off", "HIGH_ENTROPY_VA")
    add("DEP", "on" if dc & 0x100 else "off", "NX_COMPAT")
    guard = getattr(lcs, "GuardFlags", 0) if lcs else 0
    if dotnet:
        add("CFG", "n/a", ".NET assembly")
    elif dc & 0x4000 and guard & 0x100:
        add("CFG", "on", "GUARD_CF + instrumented code")
    else:
        add("CFG", "off", "Control Flow Guard not used")
    if not is64:
        if dc & 0x400:
            add("SafeSEH", "n/a", "NO_SEH: the image uses no structured exception handlers")
        elif lcs is not None and getattr(lcs, "SEHandlerCount", 0):
            add("SafeSEH", "on", f"{lcs.SEHandlerCount} registered handlers")
        elif not dotnet:
            add("SafeSEH", "off", "no table of safe exception handlers")
    if not dotnet:
        add("Stack cookies (/GS)", "on" if lcs is not None and getattr(lcs, "SecurityCookie", 0) else "off",
            "security cookie in the load configuration")
    cet = False
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        if d.struct.Type == 20 and d.struct.SizeOfData >= 4:    # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
            off = d.struct.PointerToRawData
            cet = bool(int.from_bytes(data[off:off + 4], "little") & 0x1)
    if is64:
        add("CET shadow stack", "on" if cet else "off", "CET_COMPAT")
    if dc & 0x80:
        add("Force integrity", "on", "FORCE_INTEGRITY: Windows requires a valid signature")
    if dc & 0x1000:
        add("AppContainer", "on", "APPCONTAINER")
    return out


# release of the first version of each Visual Studio (previews come out a few months earlier)
_VS_RELEASE = {"VS2015": "2015-07-20", "VS2017": "2017-03-07", "VS2019": "2019-04-02",
               "VS2022": "2021-11-08", "VS2026": "2025-11-11"}
# linker version (optional header) of each Visual Studio
_VS_LINKER = {"VS6": (6, None), "VS2002": (7, None), "VS2003": (7, None), "VS2005": (8, None), "VS2008": (9, None),
              "VS2010": (10, None), "VS2012": (11, None), "VS2013": (12, None), "VS2015": (14, range(0, 10)),
              "VS2017": (14, range(10, 20)), "VS2019": (14, range(20, 30)), "VS2022": (14, range(30, 50)),
              "VS2026": (14, range(50, 60))}


def consistency(info: dict[str, Any]) -> list[dict[str, str]]:
    """Dates and versions that should agree: if they do not, someone edited them."""
    out = []
    ts = info.get("timestamp") or 0
    debug = info.get("debug") or []
    # reproducible builds (/Brepro, recent .NET): a hash instead of the date
    repro = any(d["type"] == "IMAGE_DEBUG_TYPE_REPRO" for d in debug) or info.get("is_dotnet")
    fmt = lambda t: _ts_to_str(t) + " UTC"
    if ts and not repro:
        other = sorted({d["timestamp"] for d in debug if d.get("timestamp") and d["timestamp"] != ts})
        if other:
            out.append({"what": "debug directory date",
                        "detail": f"header says {fmt(ts)}, debug directory says {fmt(other[0])}"})
        ets = (info.get("exports") or {}).get("timestamp") or 0
        if ets and ets != 0xFFFFFFFF and abs(ets - ts) > 86400:
            out.append({"what": "export directory date",
                        "detail": f"header says {fmt(ts)}, export directory says {fmt(ets)}"})
    rich = info.get("rich") or {}
    linker = next((e for e in rich.get("entries", []) if e.get("tool") == "Linker" and e.get("version")), None)
    if linker:
        vs = linker["version"].split()[0]
        opt = (info.get("headers") or {}).get("optional") or {}
        major, minor = opt.get("MajorLinkerVersion"), opt.get("MinorLinkerVersion")
        want = _VS_LINKER.get(vs)
        if want and major is not None and (major != want[0] or (want[1] is not None and minor not in want[1])):
            out.append({"what": "linker version",
                        "detail": f"Rich header says {linker['version']} linker, optional header says {major}.{minor}"})
        rel = _VS_RELEASE.get(vs)
        if rel and ts and not repro:
            released = dt.datetime.fromisoformat(rel).replace(tzinfo=dt.timezone.utc).timestamp()
            if ts < released - 240 * 86400:
                out.append({"what": "compile date",
                            "detail": f"compiled {fmt(ts)}, but linked with {vs} (released {rel})"})
    sig = (info.get("signature") or {}).get("verification") or {}
    if sig.get("signing_time") and ts and not repro:
        try:
            st = dt.datetime.fromisoformat(sig["signing_time"]).timestamp()
        except ValueError:
            st = None
        if st and st < ts - 86400:
            out.append({"what": "signing date",
                        "detail": f"signed {sig['signing_time'][:19].replace('T', ' ')} UTC, before it was compiled "
                                  f"({fmt(ts)})"})
    return out


def _debug(pe: pefile.PE) -> list[dict[str, Any]]:
    out = []
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        item = {"type": pefile.DEBUG_TYPE.get(d.struct.Type, str(d.struct.Type)), "timestamp": d.struct.TimeDateStamp}
        pdb = getattr(d.entry, "PdbFileName", None) if d.entry else None
        if pdb:
            item["pdb"] = _s(pdb)
        out.append(item)
    return out


def _version_info(pe: pefile.PE) -> dict[str, str]:
    out: dict[str, str] = {}
    for fi_list in getattr(pe, "FileInfo", []) or []:
        for fi in fi_list:
            for st in getattr(fi, "StringTable", []) or []:
                for k, v in st.entries.items():
                    out[_s(k)] = _s(v)
    return out


def _signature(pe: pefile.PE) -> dict[str, Any] | None:
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dd) <= DIR_SECURITY or not dd[DIR_SECURITY].VirtualAddress:
        return None
    # in the security directory VirtualAddress is a file offset, not an RVA
    return {"offset": dd[DIR_SECURITY].VirtualAddress, "size": dd[DIR_SECURITY].Size}


def _overlay(pe: pefile.PE, data: bytes, sig: dict | None) -> dict[str, Any] | None:
    start = _safe(pe.get_overlay_data_start_offset)
    if start is None or start >= len(data):
        return None
    end = len(data)
    # the Authenticode signature is at the end of the file: it must not be considered "suspicious" overlay
    if sig and sig["offset"] >= start:
        if sig["offset"] == start:
            start = sig["offset"] + sig["size"]
        else:
            end = sig["offset"]
    if start >= end:
        return None
    blob = data[start:end]
    return {
        "offset": start, "size": len(blob), "entropy": round(entropy.shannon(blob), 4),
        "magic": blob[:4].hex(), "embedded_pe": blob[:2] == b"MZ",
        "ratio": round(len(blob) / len(data), 4),
    }


def locate(info: dict[str, Any], offset: int) -> tuple[int | None, str]:
    """Converts a file offset into (VA, section). For headers and overlay the section is empty."""
    base = info["image_base"]
    for s in info["sections"]:
        if s["raw_size"] and s["raw_offset"] <= offset < s["raw_offset"] + s["raw_size"]:
            return base + s["virtual_address"] + offset - s["raw_offset"], s["name"]
    if offset < info["headers"]["optional"].get("SizeOfHeaders", 0x400):
        return base + offset, "HEADER"
    if info.get("overlay") and offset >= info["overlay"]["offset"]:
        return None, "OVERLAY"
    return None, ""
