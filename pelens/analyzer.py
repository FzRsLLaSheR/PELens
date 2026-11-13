"""Analysis entry point: PE structure, entropy, strings, code, cryptography and score.

It is independent of the interface: both the CLI and the GUI use it.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import time
from typing import Any, Callable

from .compare import SSDEEP_MAX, ssdeep
from . import authenticode, hidden, yara_scan, __version__, codescan, crypto, dotnet, entropy, identify, pe_info, scoring
from . import strings as strmod

Progress = Callable[[str], None]


def _guard(report: dict, what: str, fn, default):
    """Runs one analysis phase: if it fails on a weird file, the error is recorded and the analysis goes on."""
    try:
        return fn()
    except Exception as e:
        report["errors"].append(f"{what}: {type(e).__name__}: {e}")
        return default


def _region_of(info: dict, off: int) -> str:
    """Where an offset is: resource, overlay, section or header."""
    for r in info.get("resources") or []:
        if r["offset"] <= off < r["offset"] + r["size"]:
            return f"resource {r['type']}/{r['name']}"
    ov = info.get("overlay")
    if ov and off >= ov["offset"]:
        return "overlay"
    _va, sec = pe_info.locate(info, off)
    return f"section {sec}" if sec else "headers"


def analyze(path: str, *, code_analysis: bool = True, rules_path: str | None = None,
            crypto_signatures: str | None = None, progress: Progress | None = None,
            yara_paths: list[str] | None = None) -> dict[str, Any]:
    """yara_paths: files or folders of YARA rules; None = the default ones (PELENS_YARA, yara/ folder)."""
    say = progress or (lambda msg: None)
    with open(path, "rb") as f:
        data = f.read()

    report: dict[str, Any] = {
        "tool": {"name": "PELens", "version": __version__},
        "file": {"name": os.path.basename(path), "path": os.path.abspath(path)},
        "analyzed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "errors": [],
        "timings": {},
    }
    t0 = time.perf_counter()

    def lap(name: str):
        nonlocal t0
        now = time.perf_counter()
        report["timings"][name] = round(now - t0, 3)
        t0 = now

    say("Parsing PE structure…")
    pe = pe_info.load(data)
    try:
        info = pe_info.parse(data, pe)
        report["pe"] = info
        if len(data) <= SSDEEP_MAX:
            info["hashes"]["ssdeep"] = _guard(report, "ssdeep", lambda: ssdeep(data), "")
        lap("pe")

        say("Identifying packers and compilers…")
        try:
            ep_off = pe.get_offset_from_rva(info["entry_point_rva"]) if info["entry_point_rva"] else None
            ep_bytes = data[ep_off:ep_off + 64] if ep_off is not None else b""
        except Exception:
            ep_bytes = b""
        report["identification"] = _guard(report, "identification", lambda: identify.detect(data, info, ep_bytes), [])
        lap("identify")

        say("Computing entropy…")
        report["entropy"] = {"window": 256, "points": entropy.sliding(data, 256)}
        lap("entropy")

        # a memory dump (mapped layout) read as a file gives wrong results: it is reported
        try:
            from . import unmapper
            d = unmapper.Dump(data)
            if any(s["va"] != s["raw_ptr"] and s["raw_size"] for s in d.sections):
                lay, why = unmapper.detect_layout(d)
                if lay == "mapped":
                    info["memory_dump"] = why
                    report.setdefault("notes", []).append("This file looks like a memory dump (sections at their virtual "
                                           f"addresses: {why}). Rebuild it with the Unmapper (Ctrl+U) before "
                                           "trusting the results.")
        except Exception:
            pass

        sig = info.get("signature")
        if sig:
            say("Verifying the signature…")
            sig["verification"] = authenticode.verify(data, sig["offset"], sig["size"])
            # with the signing date we also check that it is not earlier than the compilation
            info["consistency"] = _guard(report, "date consistency", lambda: pe_info.consistency(info), [])
            lap("signature")

        say("Looking for hidden executables…")
        hidden_pes = _guard(report, "hidden PE scan",
                            lambda: hidden.scan(data, [(sig["offset"], sig["offset"] + sig["size"])] if sig else []), [])
        for h in hidden_pes:
            h["va"], h["section"] = pe_info.locate(info, h["offset"])
            h["region"] = _region_of(info, h["offset"])
        report["hidden_pe"] = hidden_pes
        lap("hidden_pe")

        say("Extracting strings…")
        found = strmod.extract_static(data)
        # the strings inside the Authenticode signature (certificates, OCSP URLs...) do not belong to the program
        sig = info.get("signature")
        if sig:
            found = [s for s in found if not (sig["offset"] <= s.offset < sig["offset"] + sig["size"])]
        for s in found:
            s.va, s.section = pe_info.locate(info, s.offset)
        # version numbers (e.g. "1.2.0.3" in the version info) are not IP addresses
        versions = set(info["version_info"].values())
        for s in found:
            if "ip" in s.tags and (s.value.strip() in versions or s.value.strip().startswith("0.")
                               or re.search(r"version\s*=\s*[\"']?\d+\.\d+\.\d+\.\d+", s.value, re.I)):
                s.tags.remove("ip")
        lap("strings")

        if info["is_dotnet"]:
            say("Reading .NET metadata…")
            try:
                report["dotnet"] = dotnet.analyze(path)
                # user strings (#US) go through the same rules as the other strings
                already = {x.value for x in found}
                # PEs hidden in the manifest resources belong to the resource, not to the .text section
                for h in report.get("hidden_pe", []):
                    for r in report["dotnet"].get("resources", []):
                        if r.get("offset") is not None and r["offset"] <= h["offset"] < r["offset"] + r["size"]:
                            h["region"] = f".NET resource {r['name']}"
                for us in report["dotnet"].pop("user_strings", []):
                    if us not in already:
                        already.add(us)
                        found.append(strmod.FoundString(us, "static", "utf-16le", section="#US",
                                                        tags=strmod.classify(us)))
            except Exception as e:
                report["errors"].append(f".NET metadata: {e}")
            lap("dotnet")

        code = codescan.CodeScanResult()
        if info["is_dotnet"]:
            # .NET assembly: the code is IL bytecode, not x86. Disassembling it would only give noise.
            report.setdefault("notes", []).append("code analysis skipped: .NET assembly (IL bytecode, not native code)")
        elif code_analysis:
            say("Analyzing code (stack strings, RC4, AES/SHA instructions)…")
            try:
                # high-entropy areas (large data sections): candidate encrypted payloads
                hot = [(info["image_base"] + sc["virtual_address"],
                        info["image_base"] + sc["virtual_address"] + max(sc["virtual_size"], sc["raw_size"]))
                       for sc in info["sections"]
                       if not sc["executable"] and sc["raw_size"] >= 16384 and sc["entropy"] >= 7.5]
                code = codescan.scan(pe, hot)
                found.extend(code.stack_strings)
            except Exception as e:  # a problem in the disassembly must not stop the analysis
                report["errors"].append(f"code analysis: {e}")
            lap("code")
    finally:
        pe.close()

    say("Running YARA rules…")
    try:
        ya = yara_scan.scan(data, path, info.get("kind", "exe"), yara_paths)
    except Exception as e:
        ya = {"matches": [], "errors": [f"YARA: {e}"]}
    if ya:
        report["yara"] = ya
    lap("yara")

    report["code_traits"] = code.loader.to_dict()
    say("Looking for cryptographic algorithms…")
    # Base64 hiding suspicious text (also in .NET strings and stack strings)
    found += _guard(report, "base64 strings", lambda: strmod.decode_base64_strings(found), [])
    report["crypto"] = _guard(report, "crypto detection",
                              lambda: crypto.detect(data, info, code, found, crypto_signatures), [])
    lap("crypto")
    report["strings"] = [s.to_dict() for s in found]

    say("Computing score…")
    rules = scoring.load_rules(rules_path)
    result = scoring.evaluate({**info, "crypto": report["crypto"], "code_traits": report["code_traits"],
                               "file_name": report["file"]["name"], "dotnet": report.get("dotnet"),
                               "hidden_pe": report.get("hidden_pe", []),
                               "yara_matches": (report.get("yara") or {}).get("matches", []),
                               "identification": report.get("identification", [])},
                              report["strings"], rules)
    report["score"] = result.to_dict()
    report["errors"].extend(result.errors)
    lap("score")
    return report
