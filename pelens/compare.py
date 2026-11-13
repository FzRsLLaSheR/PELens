"""Comparison of two analyzed files: fuzzy hash (ssdeep), imphash, Rich header, sections, imports, resources, strings.

Useful to see whether two samples are variants of the same program or come out of the same builder/crypter.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

import ppdeep

# beyond this size ssdeep is not computed during the analysis (pure Python: ~0.5 s per MB)
SSDEEP_MAX = 4 << 20


def ssdeep(data: bytes) -> str:
    return ppdeep.hash(bytes(data)) if data else ""


def similarity(h1: str, h2: str) -> int | None:
    """ssdeep similarity 0-100 (None if a hash is missing)."""
    if not h1 or not h2:
        return None
    try:
        return int(ppdeep.compare(h1, h2))
    except Exception:
        return None


def _file_ssdeep(report: dict, data: bytes) -> str:
    return report["pe"]["hashes"].get("ssdeep") or ssdeep(data)


def _jaccard(a: set, b: set) -> int | None:
    if not a and not b:
        return None
    return round(100 * len(a & b) / len(a | b))


def _keyed(items, key):
    """Pairs elements with the same key; repeated keys are told apart by their order (e.g. two '.text')."""
    seen = Counter()
    out = {}
    for it in items:
        k = key(it)
        out[(k, seen[k])] = it
        seen[k] += 1
    return out


def _pair_sections(la: list, lb: list) -> list[tuple[int | None, int | None]]:
    """Pairs the sections of A and B: by name when the name is unique in both files, the rest by position.

    Packers often use empty or random names (Themida, VMProtect...): there the order is what counts."""
    name = lambda s: s["name"].strip()
    ca, cb = Counter(name(s) for s in la), Counter(name(s) for s in lb)
    unique = {n for n in ca if n and ca[n] == 1 and cb.get(n) == 1}
    pairs, used_b = {}, set()
    for i, s in enumerate(la):
        if name(s) in unique:
            j = next(j for j, t in enumerate(lb) if name(t) == name(s))
            pairs[i] = j
            used_b.add(j)
    rest_a = [i for i in range(len(la)) if i not in pairs]
    rest_b = [j for j in range(len(lb)) if j not in used_b]
    for i, j in zip(rest_a, rest_b):
        pairs[i] = j
        used_b.add(j)
    out = [(i, pairs.get(i)) for i in range(len(la))]
    out += [(None, j) for j in range(len(lb)) if j not in used_b]
    return out


def _sections(ra, rb, da, db) -> list[dict[str, Any]]:
    la, lb = ra["pe"]["sections"], rb["pe"]["sections"]
    rows = []
    for i, j in _pair_sections(la, lb):
        a = la[i] if i is not None else None
        b = lb[j] if j is not None else None
        label = lambda s, k: s["name"].strip() or f"#{k + 1} (no name)"
        na, nb = (label(a, i) if a else ""), (label(b, j) if b else "")
        row = {"name": na if not b or na == nb else (f"{na} / {nb}" if a else nb),
               "a": None, "b": None, "identical": False, "similarity": None}
        blobs = []
        for side, sec, d in (("a", a, da), ("b", b, db)):
            if sec:
                row[side] = {"raw_size": sec["raw_size"], "virtual_size": sec["virtual_size"],
                             "entropy": sec["entropy"], "flags": sec["flags"]}
                blobs.append(d[sec["raw_offset"]:sec["raw_offset"] + sec["raw_size"]])
        if a and b:
            row["identical"] = bool(a.get("md5")) and a.get("md5") == b.get("md5")
            if row["identical"]:
                row["similarity"] = 100
            elif blobs[0] and blobs[1]:
                row["similarity"] = similarity(ssdeep(blobs[0]), ssdeep(blobs[1]))
        rows.append(row)
    return rows


def _imports(report) -> set[str]:
    out = set()
    for imp in report["pe"]["imports"]:
        dll = imp["dll"].lower()
        for fn in imp["functions"]:
            out.add(f"{dll}!{fn}")
    # .NET: the framework APIs it uses (all import only mscoree!_CorExeMain)
    for cat in ((report.get("dotnet") or {}).get("api_categories") or {}).values():
        out.update(cat.get("hits") or [])
    for p in (report.get("dotnet") or {}).get("pinvoke") or []:
        out.add(f"{str(p.get('dll', '')).lower()}!{p.get('name', '')}" if isinstance(p, dict) else str(p))
    return out


def _resources(ra, rb, da, db) -> list[dict[str, Any]]:
    def key(r):                       # the language is not part of the key: a rebuilt file may change it
        return (str(r["type"]), str(r["name"]))

    def digest(r, d):
        return hashlib.md5(d[r["offset"]:r["offset"] + r["size"]]).hexdigest() if r.get("offset") is not None else ""

    sa = _keyed(ra["pe"]["resources"], key)
    sb = _keyed(rb["pe"]["resources"], key)
    rows = []
    for k in list(sa) + [k for k in sb if k not in sa]:
        a, b = sa.get(k), sb.get(k)
        if a and b:
            state = "identical" if digest(a, da) == digest(b, db) else "different"
        else:
            state = "only in A" if a else "only in B"
        rows.append({"type": k[0][0], "name": k[0][1], "lang": (a or b).get("lang"), "state": state,
                     "size_a": a["size"] if a else None, "size_b": b["size"] if b else None})
    return rows


def _strings(report) -> tuple[set[str], set[str]]:
    """(all string values, interesting strings) of a report."""
    all_s, tagged = set(), set()
    for s in report.get("strings") or []:
        v = s.get("value", "")
        if len(v) < 5:
            continue
        all_s.add(v)
        if [t for t in s.get("tags", []) if t != "pe_header"]:
            tagged.add(v)
    return all_s, tagged


def _go_functions(da: bytes, db: bytes) -> dict[str, Any] | None:
    from .identify import go_user_functions
    fa, fb = go_user_functions(da), go_user_functions(db)
    if not fa and not fb:
        return None
    return {"count_a": len(fa), "count_b": len(fb), "common": len(fa & fb), "similarity": _jaccard(fa, fb),
            "only_a": sorted(fa - fb), "only_b": sorted(fb - fa)}


def _is_go(report) -> bool:
    return any(i.get("name", "").split()[0] == "Go" for i in report.get("identification") or [] if i.get("name"))


def _packed(report) -> bool:
    """Packed or protected: a packer/protector was identified, or most of the file is near-random."""
    if any(i.get("type") in ("packer", "protector") for i in report.get("identification") or []):
        return True
    secs = report["pe"]["sections"]
    raw = sum(s["raw_size"] for s in secs) or 1
    return sum(s["raw_size"] for s in secs if s["entropy"] >= 7.2) / raw > 0.6


def _ident(report) -> str:
    return ", ".join(i.get("name", "") for i in report.get("identification") or [])


def compare(ra: dict, da: bytes, rb: dict, db: bytes) -> dict[str, Any]:
    """Compares two reports (with the bytes of their files)."""
    pa, pb = ra["pe"], rb["pe"]
    ha, hb = _file_ssdeep(ra, da), _file_ssdeep(rb, db)
    rich_a, rich_b = (pa.get("rich") or {}).get("hash", ""), (pb.get("rich") or {}).get("hash", "")
    sig = lambda p: ((p.get("signature") or {}).get("verification") or {}).get("signer", "") or \
        ("signed" if p.get("signature") else "")

    def field(label, a, b, same=None):
        if a in ("", None) and b in ("", None):
            same = None                      # missing in both: nothing to compare
        elif same is None:
            same = a == b
        return {"field": label, "a": a, "b": b, "same": same}

    overview = [
        field("Name", ra["file"]["name"], rb["file"]["name"]),
        field("Size", pa["size"], pb["size"]),
        field("SHA-256", pa["hashes"]["sha256"], pb["hashes"]["sha256"]),
        field("ssdeep", ha, hb),
        field("imphash", pa.get("imphash", ""), pb.get("imphash", "")),
        field("Rich header hash", rich_a, rich_b),
        field("Toolchain", (pa.get("rich") or {}).get("summary", ""), (pb.get("rich") or {}).get("summary", "")),
        field("Identified", _ident(ra), _ident(rb)),
        field("Type", f"{pa.get('machine', '')} {pa.get('kind', '')}", f"{pb.get('machine', '')} {pb.get('kind', '')}"),
        field("Compiled", pa.get("timestamp_utc", ""), pb.get("timestamp_utc", "")),
        field("Entry point (RVA)", f"0x{pa.get('entry_point_rva', 0):x}", f"0x{pb.get('entry_point_rva', 0):x}"),
        field("Signature", sig(pa), sig(pb)),
        field("Overlay", (pa.get("overlay") or {}).get("size", 0), (pb.get("overlay") or {}).get("size", 0)),
        field("Score", ra["score"]["score"], rb["score"]["score"]),
    ]
    ia, ib = _imports(ra), _imports(rb)
    sa_all, sa_tag = _strings(ra)
    sb_all, sb_tag = _strings(rb)
    sections = _sections(ra, rb, da, db)
    resources = _resources(ra, rb, da, db)
    go = _is_go(ra) and _is_go(rb)
    fa = {f["id"] for f in ra["score"]["findings"]}
    fb = {f["id"] for f in rb["score"]["findings"]}
    title = {f["id"]: f["title"] for f in ra["score"]["findings"] + rb["score"]["findings"]}
    return {
        "a": ra["file"]["name"], "b": rb["file"]["name"],
        "dotnet": bool(pa.get("is_dotnet") and pb.get("is_dotnet")),
        "packed": _packed(ra) and _packed(rb),
        "go": go,
        "go_functions": _go_functions(da, db) if go else None,
        "ssdeep_similarity": 100 if pa["hashes"]["sha256"] == pb["hashes"]["sha256"] else similarity(ha, hb),
        "overview": overview,
        "sections": sections,
        "imports": {"common": len(ia & ib), "only_a": sorted(ia - ib), "only_b": sorted(ib - ia),
                    "similarity": _jaccard(ia, ib)},
        "resources": resources,
        "strings": {"similarity": _jaccard(sa_all, sb_all), "common": len(sa_all & sb_all),
                    "only_a": sorted(sa_tag - sb_tag), "only_b": sorted(sb_tag - sa_tag)},
        "findings": {"common": sorted(title[i] for i in fa & fb), "only_a": sorted(title[i] for i in fa - fb),
                     "only_b": sorted(title[i] for i in fb - fa)},
    }


def summary_lines(c: dict) -> list[str]:
    """A few lines in plain words: how similar the two files are."""
    out = []
    s = c["ssdeep_similarity"]
    if s is not None:
        out.append(f"ssdeep similarity of the whole file: {s}/100")
    same = {f["field"]: f["same"] for f in c["overview"]}
    if same.get("SHA-256"):
        out.append("The two files are identical.")
        return out
    if c.get("dotnet"):
        out.append("Both .NET: the imphash says nothing (every assembly imports only mscoree!_CorExeMain)")
    elif c.get("go"):
        out.append("Both Go: the imphash says little (the Go runtime always imports the same APIs), and any code "
                   "change moves the whole .text, so its ssdeep is low even between builds of the same program")
    elif same.get("imphash") is not None:
        out.append("Same imphash (same imports in the same order)" if same["imphash"] else "Different imphash")
    if same.get("Rich header hash"):
        out.append("Same Rich header: built with the same toolchain and the same object files")
    secs = [r for r in c["sections"] if r["a"] and r["b"]]
    if secs:
        ident = sum(r["identical"] for r in secs)
        sims = [r["similarity"] for r in secs if r["similarity"] is not None and not r["identical"]]
        txt = f"Sections: {ident} of {len(secs)} in common are identical"
        if sims:
            txt += (f", the others {min(sims)}-{max(sims)}/100 similar" if min(sims) != max(sims)
                    else f", the others {min(sims)}/100 similar")
        out.append(txt)
    im = c["imports"]
    if im["similarity"] is not None:
        out.append(f"Imports: {im['common']} in common, {len(im['only_a'])} only in A, {len(im['only_b'])} only in B "
                   f"({im['similarity']}% overlap)")
    res = Counter(r["state"] for r in c["resources"])
    if res:
        out.append("Resources: " + ", ".join(f"{n} {k}" for k, n in res.most_common()))
    st = c["strings"]
    if st["similarity"] is not None:
        out.append(f"Strings: {st['common']} in common ({st['similarity']}% overlap)")
    gf = c.get("go_functions")
    if gf:
        out.append(f"Go functions of the program (package main and modules, no runtime/stdlib): {gf['common']} in "
                   f"common, {len(gf['only_a'])} only in A, {len(gf['only_b'])} only in B ({gf['similarity']}% overlap)")
    elif c.get("go"):
        out.append("Go function names not found (stripped or obfuscated)")
    if c.get("packed"):
        out.append("Both files are packed or encrypted: ssdeep, sections and strings compare the packer's random-looking "
                   "output, so low values do not mean different programs. Compare the unpacked files.")
    return out
