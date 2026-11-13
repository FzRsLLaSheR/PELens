"""PELens command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys

import pefile
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .analyzer import analyze
from .batch import collect, error_row, summary, write_csv
from .strings import SUSPICIOUS_TAGS

CONF_STYLE = {"high": "bold", "medium": "", "low": "dim"}
CONF_LABEL = {"high": "high", "medium": "medium", "low": "low"}
CAT_LABEL = {"stream_cipher": "stream cipher", "block_cipher": "block cipher", "asymmetric": "asymmetric",
             "hash": "hash", "checksum": "checksum", "encoding": "encoding", "xor": "XOR obfuscation",
             "payload": "loader", "compression": "compression"}

SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan"}
SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _score_style(score: int) -> str:
    return "bold red" if score >= 60 else "bold yellow" if score >= 30 else "bold green"


def signature_text(sig: dict) -> str:
    """Summary of the signature verification, shared by CLI and GUI."""
    v = sig.get("verification") or {}
    if not v:
        return f"present ({sig['size']:,} bytes, not verified)"
    who = f"{v.get('signer', '?')} (issued by {v.get('issuer', '?')})" if v.get("signer") else ""
    when = f", signed {v['signing_time'][:10]}" if v.get("signing_time") else ""
    if v.get("verified"):
        return f"valid — {who}{when}"
    return f"NOT valid — {who}{when}: " + "; ".join(v.get("problems") or ["unknown problem"])


def _res_note(r: dict) -> str:
    """Note on a .NET resource: image (size, PE hidden in the pixels, noise) or encrypted data."""
    img = r.get("image")
    parts = []
    if img:
        if img.get("width"):
            parts.append(f"{img['format']} {img['width']}x{img['height']}")
        hp = img.get("hidden_pe")
        if hp:
            how = f"XOR key {hp['key']}" if hp["encrypted"] else "unencrypted"
            parts.append(f"[red]PE hidden in the pixels ({how}, {hp['layout']})[/]")
        elif img.get("noise"):
            parts.append("[red]pixels are random noise (encrypted data)[/]")
    else:
        hp = r.get("hidden_pe")
        if hp:
            parts.append(f"[red]PE ({'XOR key ' + hp['key'] if hp['encrypted'] else 'unencrypted'})[/]")
        elif r.get("embedded_pe"):
            parts.append("[red]PE![/]")
        elif r["size"] >= 16384 and r["entropy"] >= 7.5:
            parts.append(f"[yellow]entropy {r['entropy']:.2f}, encrypted?[/]")
    return (" — " + ", ".join(parts)) if parts else ""


def render(report: dict, console: Console, all_strings: bool = False) -> None:
    pe, sc = report["pe"], report["score"]

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold")
    meta.add_column()
    meta.add_row("File", report["file"]["name"])
    meta.add_row("Type", f"{pe['format']} {pe['kind']}  {pe['machine']}  {pe['subsystem']}"
                 + ("  [.NET]" if pe["is_dotnet"] else ""))
    meta.add_row("Size", f"{pe['size']:,} bytes")
    meta.add_row("Compiled", pe["timestamp_utc"])
    for k in ("md5", "sha1", "sha256"):
        meta.add_row(k.upper(), pe["hashes"][k])
    meta.add_row("Imphash", pe["imphash"] or "-")
    if pe["hashes"].get("ssdeep"):
        meta.add_row("ssdeep", pe["hashes"]["ssdeep"])
    meta.add_row("Entropy", f"{pe['entropy']:.3f}")
    ident = report.get("identification") or []
    if ident:
        meta.add_row("Identified", escape(", ".join(f"{i['name']} ({i['type']})" for i in ident)))
    meta.add_row("Entry point", f"0x{pe['entry_point_rva']:x} in {pe['entry_point_section'] or 'no section'}")
    if pe["debug"]:
        pdb = [d["pdb"] for d in pe["debug"] if "pdb" in d]
        if pdb:
            meta.add_row("PDB", escape(pdb[0]))
    t = report.get("timings", {})
    meta.add_row("Time", f"{sum(t.values()):.2f} s")
    console.print(Panel(meta, title=f"PELens {__version__}", border_style="blue"))

    style = _score_style(sc["score"])
    console.print(Panel(f"[{style}]{sc['score']}/100 — {sc['verdict']}[/]", title="Score", border_style=style.split()[-1]))

    if sc["findings"]:
        t = Table(title="Findings", show_lines=True, expand=True)
        t.add_column("Weight", justify="right", width=6)
        t.add_column("Severity", width=8)
        t.add_column("Indicator", ratio=1)
        t.add_column("Details", ratio=2)
        for f in sc["findings"]:
            ev = "\n".join(escape(e) for e in f["evidence"][:6]) + (f"\n… {len(f['evidence']) - 6} more" if len(f["evidence"]) > 6 else "")
            t.add_row(f"+{f['weight']}", f"[{SEV_STYLE[f['severity']]}]{SEV_LABEL[f['severity']]}[/]",
                      f"[bold]{escape(f['title'])}[/]\n[dim]{escape(f['description'])}[/]", ev)
        console.print(t)

    t = Table(title="Sections")
    for col in ("Name", "VA", "Virtual size", "Offset", "Raw size", "Flags", "Entropy"):
        t.add_column(col, justify="left" if col in ("Name", "Flags") else "right")
    for s in pe["sections"]:
        e = s["entropy"]
        es = f"[red]{e:.2f}[/]" if e >= 7.2 else f"[yellow]{e:.2f}[/]" if e >= 6.5 else f"{e:.2f}"
        perm = f"[red]{s['flags']}[/]" if s["executable"] and s["writable"] else s["flags"]
        t.add_row(escape(s["name"]), f"0x{s['virtual_address']:x}", f"{s['virtual_size']:,}", f"0x{s['raw_offset']:x}",
                  f"{s['raw_size']:,}", perm, es)
    console.print(t)

    n_funcs = sum(len(i["functions"]) for i in pe["imports"])
    console.print(f"[bold]Imports:[/] {n_funcs} functions from {len(pe['imports'])} DLLs: "
                  + ", ".join(i["dll"] for i in pe["imports"][:15]))
    n_ord = sum(len(i.get("by_ordinal") or {}) for i in pe["imports"])
    if n_ord:
        named = [f"{n} (#{o})" for i in pe["imports"] for n, o in (i.get("by_ordinal") or {}).items()
                 if not n.startswith("ordinal_")]
        console.print(f"  {n_ord} imported by ordinal" + (": " + escape(", ".join(named[:12])) if named else "")
                      + (f" (+{len(named) - 12})" if len(named) > 12 else ""))
    if pe["exports"]:
        console.print(f"[bold]Exports:[/] {len(pe['exports']['symbols'])} symbols ({pe['exports']['name']})")
    for h in report.get("hidden_pe") or []:
        what = " ".join(x for x in (h.get("machine"), ".NET" if h.get("dotnet") else "", h.get("kind")) if x)
        how = f"[red]XOR key {h['key']} ({h['key_length']} bytes)[/]" if h["encrypted"] else "unencrypted"
        size = f", {h['size']:,} bytes" if h.get("size") else ""
        console.print(f"[bold]Hidden PE:[/] {what} at offset 0x{h['offset']:x} in {escape(h['region'])}{size}, {how}")
    if pe["resources"]:
        console.print(f"[bold]Resources:[/] {len(pe['resources'])}")
    if pe["overlay"]:
        ov = pe["overlay"]
        console.print(f"[bold]Overlay:[/] {ov['size']:,} bytes at offset 0x{ov['offset']:x}, entropy {ov['entropy']:.2f}")
    if pe["signature"]:
        console.print(f"[bold]Authenticode signature:[/] {escape(signature_text(pe['signature']))}")
    if (pe.get("rich") or {}).get("summary"):
        forged = "  [red](Rich header forged: checksum mismatch)[/]" if pe["rich"].get("checksum_ok") is False else ""
        console.print(f"[bold]Toolchain (Rich header):[/] {escape(pe['rich']['summary'])}{forged}")
    for c in pe.get("consistency") or []:
        console.print(f"[bold]Inconsistent {escape(c['what'])}:[/] [yellow]{escape(c['detail'])}[/]")
    if pe.get("protections"):
        st = {"on": "green", "off": "dim", "weak": "yellow", "n/a": "dim"}
        console.print("[bold]Protections:[/] " + "  ".join(
            f"[{st[p['state']]}]{'+' if p['state'] == 'on' else '-' if p['state'] == 'off' else '!' if p['state'] == 'weak' else '·'}"
            f"{escape(p['name'])}[/]" for p in pe["protections"]))

    dn = report.get("dotnet")
    if dn and "error" not in dn:
        console.print(f"[bold].NET:[/] assembly {escape(dn['assembly'])} {dn['version']}  "
                      f"({dn['counts']['types']} types, {dn['counts']['methods']} methods, "
                      f"{dn['counts']['pinvoke']} P/Invoke, {dn['counts']['resources']} resources)")
        if dn.get("parser", "").startswith("heaps"):
            console.print(f"  [yellow]metadata tables unreadable: names and strings read directly from the heaps "
                          f"({dn['counts'].get('heap_names', 0)} names, {dn['counts']['user_strings']} user strings)[/]")
        for a in dn.get("metadata_anomalies", []):
            console.print(f"  [red]anomaly:[/] {escape(a)}")
        for o in dn.get("obfuscators", []):
            console.print(f"  [yellow]{escape(o['name'])}[/] ({o['type']}): {escape(o['evidence'])}")
        if dn.get("api_categories"):
            t = Table(title=".NET capabilities (from referenced APIs)")
            t.add_column("Capability")
            t.add_column("APIs")
            for c in dn["api_categories"].values():
                short = [h.split("::")[0].split(".")[-1] + "::" + h.split("::")[1] if "::" in h else h
                         for h in c["hits"][:6]]
                t.add_row(escape(c["title"]), escape(", ".join(short)))
            console.print(t)
        il = dn.get("il") or {}
        for d in il.get("string_decryptors") or []:
            console.print(f"  [bold]string decryptor:[/] {escape(d['method'])} → {d['returns']}, {d['calls']} calls "
                          f"from {d['callers']} methods" + (", XOR loop" if d.get("xor_loop") else ""))
        if il.get("xor_loops"):
            console.print(f"  XOR loops in IL: " + ", ".join(escape(x["method"]) for x in il["xor_loops"][:6])
                          + (f" (+{len(il['xor_loops']) - 6})" if len(il["xor_loops"]) > 6 else ""))
        for r in dn.get("resources", [])[:10]:
            if r.get("format") == ".resources":
                console.print(f"  resource {escape(r['name'])}: {r['size']:,} bytes, {len(r['entries'])} entries")
                for e in r["entries"][:20]:
                    console.print(f"    {escape(e['name'])} ({escape(e['type'])}): {e['size']:,} bytes"
                                  f"{_res_note(e)}")
            else:
                console.print(f"  resource {escape(r['name'])}: {r['size']:,} bytes, entropy {r['entropy']:.2f}"
                              f"{_res_note(r)}")

    ya = report.get("yara")
    if ya:
        console.print(f"[bold]YARA:[/] {ya.get('rule_files', 0)} rule files, {len(ya['matches'])} matches"
                      + (": " + ", ".join(escape(m["rule"]) for m in ya["matches"]) if ya["matches"] else ""))
        for e in ya.get("errors", [])[:5]:
            console.print(f"  [yellow]{escape(e)}[/]")
    techs = report["score"].get("attack") or []
    if techs:
        console.print("[bold]MITRE ATT&CK:[/] " + ", ".join(f"{t['id']} {escape(t['name'].split(': ')[-1])}"
                                                          for t in techs))

    ct = report.get("code_traits") or {}
    labels = [("peb_access", "PEB access"), ("export_parsing", "manual export parsing"),
              ("hash_loops", "name-hashing loops"), ("api_hashes", "known API hashes"),
              ("syscalls", "direct syscalls"), ("rwx_alloc", "RWX allocations"), ("rdtsc", "rdtsc")]
    found = [f"{label} ×{len(ct[k])}" for k, label in labels if ct.get(k)]
    if found:
        console.print(f"[bold]Code techniques:[/] " + ", ".join(found))
        hashes = ct.get("api_hashes") or []
        if hashes:
            console.print("  API hashes: " + ", ".join(f"0x{h['value']:08x}={escape(h['api'])}" for h in hashes[:8]))

    if report.get("crypto"):
        t = Table(title="Cryptography detected")
        t.add_column("Algorithm")
        t.add_column("Type")
        t.add_column("Evidence")
        t.add_column("Address", justify="right")
        t.add_column("Section")
        t.add_column("Confidence")
        for h in report["crypto"]:
            st = CONF_STYLE[h["confidence"]]
            where = f"0x{h['va']:x}" if h.get("va") else (f"off 0x{h['offset']:x}" if h.get("offset") is not None else "")
            count = f" (×{h['count']})" if h["count"] > 1 and not any(w in h["signature"] for w in (" places", "copies", "loops", "implementation")) else ""
            t.add_row(f"[{st}]{escape(h['algorithm'])}[/]" if st else escape(h["algorithm"]), CAT_LABEL.get(h["category"], h["category"]),
                      escape(h["signature"][:140]) + count, where, escape(h["section"]), CONF_LABEL[h["confidence"]])
        console.print(t)

    strings = report["strings"]
    stack = [s for s in strings if s["source"] == "stack"]
    if stack:
        t = Table(title=f"Reconstructed stack strings ({len(stack)})")
        t.add_column("Address", justify="right")
        t.add_column("Section")
        t.add_column("Length", justify="right")
        t.add_column("Type")
        t.add_column("String")
        t.add_column("Tags")
        for s in stack[:100]:
            t.add_row(f"0x{s['va']:x}", escape(s["section"]), str(s["length"]), s["type"], escape(s["value"][:100]),
                      ", ".join(s["tags"]))
        console.print(t)

    shown = [s for s in strings if s["source"] == "static" and (all_strings or SUSPICIOUS_TAGS & set(s["tags"]))]
    if shown:
        t = Table(title=f"Strings ({len(shown)})" if all_strings else "Interesting strings")
        t.add_column("Address", justify="right")
        t.add_column("Section")
        t.add_column("Length", justify="right")
        t.add_column("Type")
        t.add_column("String")
        t.add_column("Tags")
        for s in shown[: (None if all_strings else 60)]:
            addr = f"0x{s['va']:x}" if s["va"] is not None else (f"off 0x{s['offset']:x}" if s["offset"] is not None else "")
            t.add_row(addr, escape(s["section"]), str(s["length"]), s["type"], escape(s["value"][:120]), ", ".join(s["tags"]))
        console.print(t)

    for note in report.get("notes", []):
        console.print(f"[dim]Note: {escape(note)}[/]")
    for err in report["errors"]:
        console.print(f"[red]Error:[/] {err}")


def _yara_paths(args) -> list[str] | None:
    if args.no_yara:
        return []
    return args.yara or None    # None = default paths (PELENS_YARA, yara/ folder next to the exe)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pelens", description="PE file analyzer for malware triage.")
    ap.add_argument("files", nargs="+", metavar="FILE",
                    help="file(s) to analyze (exe, dll, sys...), or folders: with more than one file a summary "
                         "table is printed")
    ap.add_argument("--json", metavar="FILE", help="save the full report as JSON ('-' to print it to stdout); "
                                                   "with more files: a JSON list")
    ap.add_argument("--csv", metavar="FILE", help="save the summary table of all files as CSV")
    ap.add_argument("-r", "--recursive", action="store_true", help="look for PE files in subfolders too")
    ap.add_argument("--no-code", action="store_true",
                    help="skip disassembly (no stack strings, RC4, AES/SHA instructions)")
    ap.add_argument("--yara", metavar="PATH", action="append",
                    help="YARA rule file or folder (repeatable). Default: PELENS_YARA and the 'yara' folder "
                         "next to the executable")
    ap.add_argument("--no-yara", action="store_true", help="do not run YARA rules")
    ap.add_argument("--rules", metavar="YAML", help="custom rules file")
    un = ap.add_argument_group("rebuild a PE dumped from memory")
    un.add_argument("--unmap", metavar="OUT", help="rebuild the dump FILE into OUT")
    un.add_argument("--mode", choices=["auto", "unmap", "realign"], default="auto",
                    help="unmap: sections at the raw offsets of the headers; realign: raw = virtual (default: auto)")
    un.add_argument("--layout", choices=["auto", "mapped", "raw"], default="auto", help="layout of the dump")
    un.add_argument("--load-base", metavar="HEX", help="base the module was loaded at (default: detected)")
    un.add_argument("--base", metavar="HEX", help="ImageBase of the rebuilt file (default: the load base)")
    un.add_argument("--headers-from", metavar="FILE", help="take the PE headers from this file (wiped headers)")
    un.add_argument("--no-iat", action="store_true", help="do not restore the IAT from the import name table")
    ap.add_argument("--compare", action="store_true",
                    help="compare two files: ssdeep, imphash, Rich header, sections, imports, resources, strings")
    ap.add_argument("--all-strings", action="store_true", help="show all strings, not only the interesting ones")
    ap.add_argument("--version", action="version", version=f"PELens {__version__}")
    args = ap.parse_args(argv)

    err = Console(stderr=True)
    if args.unmap:
        return _unmap(args, err)
    files = collect(args.files, args.recursive)
    if not files:
        err.print("[red]No PE files found.[/]")
        return 2
    if args.compare:
        if len(files) != 2:
            err.print(f"[red]--compare needs exactly two PE files ({len(files)} given).[/]")
            return 2
        return _compare(files, args, err)
    batch = len(files) > 1 or any(os.path.isdir(p) for p in args.files) or bool(args.csv)
    if not batch:
        return _single(files[0], args, err)

    rows, reports = [], []
    with err.status("Analyzing…") as status:
        for i, path in enumerate(files, 1):
            name = os.path.basename(path)
            try:
                rep = analyze(path, code_analysis=not args.no_code, rules_path=args.rules,
                              yara_paths=_yara_paths(args),
                              progress=lambda m, n=name, i=i: status.update(f"[{i}/{len(files)}] {n}: {m}"))
            except (OSError, pefile.PEFormatError) as e:
                rows.append(error_row(path, str(e)))
                continue
            except Exception as e:   # a problematic file must not stop the analysis of the others
                rows.append(error_row(path, f"{type(e).__name__}: {e}"))
                continue
            rows.append(summary(rep))
            if args.json:
                reports.append(rep)
    con = Console()
    t = Table(title=f"{len(files)} files", show_lines=False)
    for c, kw in (("File", {}), ("Score", {"justify": "right"}), ("Verdict", {}), ("Identified", {}),
                  ("Top findings", {"overflow": "fold"}), ("Hidden PE / YARA", {"overflow": "fold"})):
        t.add_column(c, **kw)
    for r in sorted(rows, key=lambda r: -(r["score"] if isinstance(r["score"], int) else -1)):
        sc = r["score"]
        col = "red" if isinstance(sc, int) and sc >= 60 else "yellow" if isinstance(sc, int) and sc >= 30 else "green"
        extra = ", ".join(x for x in (r.get("hidden_pe"), r.get("yara")) if x)
        t.add_row(escape(r["file"]), f"[{col}]{sc}[/]", escape(r["verdict"]), escape(r.get("identified", "")),
                  escape(r.get("top_findings", "")), escape(extra))
    con.print(t)
    if args.csv:
        write_csv(rows, args.csv)
        err.print(f"Summary saved to {args.csv}")
    if args.json:
        if args.json == "-":
            json.dump(reports, sys.stdout, indent=2, ensure_ascii=False)
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(reports, f, indent=2, ensure_ascii=False)
            err.print(f"Reports saved to {args.json}")
    return 0


def _unmap(args, err: Console) -> int:
    from . import unmapper
    if len(args.files) != 1:
        err.print("[red]--unmap takes exactly one dump file[/]")
        return 2
    hx = lambda v: int(v, 16) if v else None
    try:
        data = open(args.files[0], "rb").read()
        ref = open(args.headers_from, "rb").read() if args.headers_from else None
        r = unmapper.unmap(data, mode=args.mode, layout=args.layout, load_base=hx(args.load_base),
                           new_base=hx(args.base), restore_imports=not args.no_iat, headers_from=ref)
    except (OSError, ValueError) as e:
        err.print(f"[red]Cannot rebuild the dump:[/] {e}")
        return 2
    with open(args.unmap, "wb") as f:
        f.write(r.data)
    con = Console()
    for line in r.log:
        con.print(f"  {escape(line)}")
    for w in r.warnings:
        con.print(f"  [yellow]{escape(w)}[/]")
    con.print(f"[green]Rebuilt PE saved to {escape(args.unmap)}[/] — analyze it with: pelens {escape(args.unmap)}")
    return 0


def _compare(files: list[str], args, err: Console) -> int:
    from .compare import compare, summary_lines
    reports, datas = [], []
    with err.status("Analyzing…") as status:
        for i, path in enumerate(files, 1):
            name = os.path.basename(path)
            try:
                reports.append(analyze(path, code_analysis=not args.no_code, rules_path=args.rules,
                                       yara_paths=_yara_paths(args),
                                       progress=lambda m, n=name: status.update(f"[{i}/2] {n}: {m}")))
                with open(path, "rb") as f:
                    datas.append(f.read())
            except (OSError, pefile.PEFormatError) as e:
                err.print(f"[red]{escape(path)}:[/] {e}")
                return 2
        status.update("Comparing…")
        c = compare(reports[0], datas[0], reports[1], datas[1])
    if args.json:
        if args.json == "-":
            json.dump(c, sys.stdout, indent=2, ensure_ascii=False)
            print()
            return 0
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(c, f, indent=2, ensure_ascii=False)
        err.print(f"Comparison saved to {args.json}")
    render_compare(c, Console())
    return 0


def render_compare(c: dict, console: Console) -> None:
    from .compare import summary_lines
    sim = c["ssdeep_similarity"]
    col = "green" if sim is None or sim < 30 else "yellow" if sim < 70 else "red"
    console.print(Panel("\n".join(escape(x) for x in summary_lines(c)),
                        title=f"A = {escape(c['a'])}   B = {escape(c['b'])}",
                        subtitle=f"[{col}]ssdeep {sim if sim is not None else '-'}/100[/]"))
    t = Table(show_lines=False, expand=True)
    t.add_column("", style="bold", no_wrap=True)
    t.add_column("A", overflow="fold")
    t.add_column("B", overflow="fold")
    t.add_column("", no_wrap=True)
    for f in c["overview"]:
        t.add_row(f["field"], escape(str(f["a"])), escape(str(f["b"])), "" if f["same"] is None else "[green]=[/]" if f["same"] else "[dim]≠[/]")
    console.print(t)
    t = Table(title="Sections", expand=True)
    for h in ("Name", "Size A", "Size B", "Entropy A", "Entropy B", "Similarity"):
        t.add_column(h, justify="right" if h != "Name" else "left")
    for r in c["sections"]:
        a, b = r["a"] or {}, r["b"] or {}
        simv = "identical" if r["identical"] else ("-" if r["similarity"] is None else f"{r['similarity']}/100")
        t.add_row(escape(r["name"]), f"{a['raw_size']:,}" if a else "-", f"{b['raw_size']:,}" if b else "-",
                  f"{a['entropy']:.2f}" if a else "-", f"{b['entropy']:.2f}" if b else "-", simv)
    console.print(t)
    for key, title in (("go_functions", "Go functions"), ("imports", "Imports"), ("strings", "Interesting strings"),
                       ("findings", "Findings")):
        d = c.get(key)
        if not d:
            continue
        for side in ("a", "b"):
            items = d[f"only_{side}"]
            if items:
                more = f" (+{len(items) - 25})" if len(items) > 25 else ""
                console.print(f"[bold]{title} only in {side.upper()}:[/] " + escape(", ".join(items[:25])) + more)


def _single(path: str, args, err: Console) -> int:
    try:
        with err.status("Analyzing…") as status:
            report = analyze(path, code_analysis=not args.no_code, rules_path=args.rules,
                             yara_paths=_yara_paths(args), progress=lambda m: status.update(m))
    except FileNotFoundError:
        err.print(f"[red]File not found:[/] {path}")
        return 2
    except pefile.PEFormatError as e:
        err.print(f"[red]Not a valid PE file:[/] {e}")
        return 2

    if args.json == "-":
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        err.print(f"Report saved to {args.json}")
    render(report, Console(), all_strings=args.all_strings)
    return 0
