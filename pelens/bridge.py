"""AI bridge: a small read-only HTTP API over the files open in PELens, for an AI assistant on ANOTHER machine.

The assistant's MCP server (pelens_mcp.py, on the AI machine) calls this API; API keys and AI accounts never
reach the analysis VM. The API only reads what PELens already computed, plus bytes and disassembly of the open
files. The only thing it writes is AI notes. It listens on one address only and every request needs the token.

GET  /api/files                              open files
GET  /api/files/<id>/<part>                  summary, findings, attack, sections, imports, exports, resources,
                                             strings, crypto, yara, code, dotnet, hidden, identification, headers,
                                             version, signature, overlay, notes
GET  /api/files/<id>/bytes?offset=|rva=&size=
GET  /api/files/<id>/disasm?rva=|offset=&count=
GET  /api/files/<id>/compare?with=<id>
POST /api/files/<id>/notes                   {"title", "text", "severity"}
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from . import __version__
from .notes import STORE

MAX_BYTES = 4096
MAX_INSTR = 300
MAX_LIST = 2000
MAX_STR = 400


def new_token() -> str:
    return secrets.token_urlsafe(24)


def file_id(report: dict) -> str:
    return (report.get("pe", {}).get("hashes", {}).get("sha256") or "")[:12] or "unknown"


def _cut(s, n: int = MAX_STR):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"… [{len(s) - n} more chars]"


def _page(items: list, q: dict, default: int = 200) -> dict:
    off = max(0, _int(q, "offset", 0))
    lim = max(1, min(MAX_LIST, _int(q, "limit", default)))
    return {"total": len(items), "offset": off, "returned": len(items[off:off + lim]), "items": items[off:off + lim]}


def _int(q: dict, key: str, default: int | None = None) -> int | None:
    v = (q.get(key) or [None])[0]
    if v is None or v == "":
        return default
    return int(str(v), 0)


def _rva_to_offset(pe: dict, rva: int) -> int | None:
    if rva < ((pe.get("headers") or {}).get("optional") or {}).get("SizeOfHeaders", 0x400):
        return rva
    for s in pe.get("sections") or []:
        size = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= rva < s["virtual_address"] + size:
            delta = rva - s["virtual_address"]
            return s["raw_offset"] + delta if delta < s["raw_size"] else None
    return None


def _offset_to_rva(pe: dict, off: int) -> int | None:
    for s in pe.get("sections") or []:
        if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
            return s["virtual_address"] + off - s["raw_offset"]
    return off if off < 0x400 else None


class Api:
    """What the HTTP handler answers, independent of the transport (easy to test)."""

    def __init__(self, reports: Callable[[], dict[str, dict]], notes=STORE):
        self.reports = reports
        self.notes = notes

    def _files(self) -> dict[str, tuple[str, dict]]:
        return {file_id(r): (p, r) for p, r in list(self.reports().items())}

    def list_files(self) -> dict:
        out = []
        for fid, (path, r) in self._files().items():
            pe, sc = r.get("pe", {}), r.get("score", {})
            out.append({"id": fid, "name": r["file"]["name"], "path": path, "sha256": pe.get("hashes", {}).get("sha256"),
                        "size": pe.get("size"), "kind": pe.get("kind"), "machine": pe.get("machine"),
                        "is_dotnet": pe.get("is_dotnet"), "score": sc.get("score"), "verdict": sc.get("verdict"),
                        "notes": len(self.notes.get(pe.get("hashes", {}).get("sha256", "")))})
        return {"pelens": __version__, "files": out}

    def part(self, fid: str, part: str, q: dict) -> dict:
        files = self._files()
        if fid not in files:
            raise KeyError(f"no open file with id {fid}")
        path, r = files[fid]
        pe = r.get("pe", {})
        sha = pe.get("hashes", {}).get("sha256", "")
        if part == "summary":
            sc = r.get("score", {})
            return {"name": r["file"]["name"], "path": path, "hashes": pe.get("hashes"), "imphash": pe.get("imphash"),
                    "size": pe.get("size"), "kind": pe.get("kind"), "machine": pe.get("machine"),
                    "subsystem": pe.get("subsystem"), "compiled": pe.get("timestamp_utc"), "is_dotnet": pe.get("is_dotnet"),
                    "image_base": pe.get("image_base"), "entry_point_rva": pe.get("entry_point_rva"),
                    "entry_point_section": pe.get("entry_point_section"), "entropy": pe.get("entropy"),
                    "protections": pe.get("protections"), "identification": r.get("identification"),
                    "score": sc.get("score"), "verdict": sc.get("verdict"),
                    "findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"], "weight": f.get("weight"),
                                  "evidence": [_cut(e) for e in (f.get("evidence") or [])[:8]]}
                                 for f in sc.get("findings") or []],
                    "signed": bool(pe.get("signature")), "overlay": bool(pe.get("overlay")),
                    "hidden_pe": len(r.get("hidden_pe") or []), "yara_matches": len((r.get("yara") or {}).get("matches") or []),
                    "notes": r.get("notes"), "analysis_errors": r.get("errors")}
        if part == "findings":
            return {"score": r["score"]["score"], "verdict": r["score"]["verdict"], "findings": r["score"]["findings"]}
        if part == "attack":
            return {"attack": r["score"].get("attack")}
        if part == "sections":
            return {"sections": pe.get("sections"), "entry_point_section": pe.get("entry_point_section")}
        if part == "imports":
            dll = ((q.get("dll") or [""])[0]).lower()
            name = ((q.get("name") or [""])[0]).lower()
            imps = [{"dll": i["dll"], "delayed": i.get("delayed"),
                     "functions": [f for f in i["functions"] if name in str(f).lower()]}
                    for i in pe.get("imports") or [] if dll in i["dll"].lower()]
            return {"imphash": pe.get("imphash"), "imports": [i for i in imps if i["functions"] or not name]}
        if part == "exports":
            return {"exports": pe.get("exports")}
        if part == "resources":
            return {"resources": pe.get("resources")}
        if part == "strings":
            items = r.get("strings") or []
            flt = ((q.get("filter") or [""])[0])
            tag = ((q.get("tag") or [""])[0]).lower()
            minlen = _int(q, "min_length", 0) or 0
            rx = re.compile(flt, re.I) if flt else None
            sel = [{"value": _cut(s["value"]), "offset": s.get("offset"), "va": s.get("va"), "section": s.get("section"),
                    "encoding": s.get("encoding"), "source": s.get("source"), "tags": s.get("tags")}
                   for s in items if (not rx or rx.search(s["value"])) and (not tag or tag in [t.lower() for t in s.get("tags") or []])
                   and len(s["value"]) >= minlen]
            tags: dict[str, int] = {}
            for s in items:
                for t in s.get("tags") or []:
                    tags[t] = tags.get(t, 0) + 1
            return {"tags": tags, **_page(sel, q)}
        if part == "crypto":
            return {"crypto": r.get("crypto")}
        if part == "yara":
            return {"yara": r.get("yara")}
        if part == "code":
            return {"code_traits": r.get("code_traits")}
        if part == "dotnet":
            return {"dotnet": r.get("dotnet")}
        if part == "hidden":
            return {"hidden_pe": r.get("hidden_pe")}
        if part == "identification":
            return {"identification": r.get("identification")}
        if part == "headers":
            return {"headers": pe.get("headers"), "rich": pe.get("rich"), "rich_removed": pe.get("rich_removed"),
                    "debug": pe.get("debug"), "tls_callbacks": pe.get("tls_callbacks"),
                    "parser_warnings": pe.get("parser_warnings"), "consistency": pe.get("consistency")}
        if part == "version":
            return {"version_info": pe.get("version_info")}
        if part == "signature":
            return {"signature": pe.get("signature")}
        if part == "overlay":
            return {"overlay": pe.get("overlay")}
        if part == "notes":
            return {"notes": self.notes.get(sha)}
        if part == "bytes":
            return self._bytes(path, pe, q)
        if part == "disasm":
            return self._disasm(path, pe, q)
        if part == "compare":
            other = ((q.get("with") or [""])[0])
            if other not in files:
                raise KeyError(f"no open file with id {other}")
            from .compare import compare
            p2, r2 = files[other]
            with open(path, "rb") as fa, open(p2, "rb") as fb:
                return {"compare": compare(r, fa.read(), r2, fb.read())}
        raise KeyError(f"unknown part {part}")

    def _locate(self, pe: dict, q: dict) -> int:
        off = _int(q, "offset")
        if off is None:
            rva = _int(q, "rva")
            if rva is None and _int(q, "va") is not None:
                rva = _int(q, "va") - (pe.get("image_base") or 0)
            if rva is None:
                raise ValueError("give offset, rva or va")
            off = _rva_to_offset(pe, rva)
            if off is None:
                raise ValueError(f"rva 0x{rva:x} is not backed by the file (uninitialised data)")
        return off

    def _bytes(self, path: str, pe: dict, q: dict) -> dict:
        off = self._locate(pe, q)
        size = max(1, min(MAX_BYTES, _int(q, "size", 256) or 256))
        with open(path, "rb") as fh:
            fh.seek(off)
            data = fh.read(size)
        rows = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            rows.append(f"{off + i:08x}  {chunk.hex(' '):<47}  " + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
        rva = _offset_to_rva(pe, off)
        return {"offset": off, "rva": rva, "size": len(data), "hex": data.hex(), "dump": "\n".join(rows)}

    def _disasm(self, path: str, pe: dict, q: dict) -> dict:
        import capstone
        if pe.get("is_dotnet"):
            raise ValueError(".NET assembly: the code is IL, not x86 (use the dotnet part)")
        off = self._locate(pe, q)
        count = max(1, min(MAX_INSTR, _int(q, "count", 60) or 60))
        x64 = str(pe.get("machine", "")).upper() in ("AMD64", "X64", "IMAGE_FILE_MACHINE_AMD64")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if x64 else capstone.CS_MODE_32)
        with open(path, "rb") as fh:
            fh.seek(off)
            data = fh.read(count * 15)
        rva = _offset_to_rva(pe, off) or 0
        base = (pe.get("image_base") or 0) + rva
        out = []
        for ins in md.disasm(data, base):
            out.append(f"{ins.address:0{16 if x64 else 8}x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}".rstrip())
            if len(out) >= count:
                break
        return {"arch": "x64" if x64 else "x86", "offset": off, "rva": rva, "va": base, "instructions": out}

    def add_note(self, fid: str, body: dict) -> dict:
        files = self._files()
        if fid not in files:
            raise KeyError(f"no open file with id {fid}")
        sha = files[fid][1]["pe"]["hashes"]["sha256"]
        return {"note": self.notes.add(sha, str(body.get("title", "")), str(body.get("text", "")),
                                       str(body.get("severity", "info")), str(body.get("author", "AI")))}


class _Handler(BaseHTTPRequestHandler):
    server_version = "PELens-AI-bridge"
    bridge: "Bridge"

    def log_message(self, fmt, *args):            # requests go to the bridge log, not to stderr
        self.bridge.log(f"{self.client_address[0]} {fmt % args}")

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj, default=str, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        b = self.bridge
        if b.allowed_client and self.client_address[0] != b.allowed_client:
            self._send(403, {"error": "client address not allowed"})
            return False
        got = self.headers.get("Authorization", "")
        if not hmac.compare_digest(got.encode(), f"Bearer {b.token}".encode()):
            self._send(401, {"error": "missing or wrong token"})
            return False
        return True

    def _route(self):
        u = urllib.parse.urlsplit(self.path)
        parts = [p for p in u.path.split("/") if p]
        return parts, urllib.parse.parse_qs(u.query)

    def do_GET(self):
        if not self._auth():
            return
        parts, q = self._route()
        try:
            if parts == ["api", "files"]:
                return self._send(200, self.bridge.api.list_files())
            if len(parts) == 4 and parts[:2] == ["api", "files"]:
                return self._send(200, self.bridge.api.part(parts[2], parts[3], q))
            self._send(404, {"error": "unknown endpoint"})
        except KeyError as e:
            self._send(404, {"error": str(e).strip("'\"")})
        except (ValueError, re.error) as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        if not self._auth():
            return
        parts, _q = self._route()
        try:
            n = min(int(self.headers.get("Content-Length", "0")), 64 * 1024)
            body = json.loads(self.rfile.read(n) or b"{}")
            if len(parts) == 4 and parts[:2] == ["api", "files"] and parts[3] == "notes" and isinstance(body, dict):
                return self._send(200, self.bridge.api.add_note(parts[2], body))
            self._send(404, {"error": "unknown endpoint"})
        except KeyError as e:
            self._send(404, {"error": str(e).strip("'\"")})
        except ValueError as e:
            self._send(400, {"error": str(e)})


class Bridge:
    def __init__(self, reports: Callable[[], dict[str, dict]], host: str, port: int, token: str | None = None,
                 allowed_client: str = "", log: Callable[[str], None] | None = None):
        self.api = Api(reports)
        self.host, self.port = host, port
        self.token = token or new_token()
        self.allowed_client = allowed_client.strip()
        self.log = log or (lambda m: None)
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        handler = type("Handler", (_Handler,), {"bridge": self})
        self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="ai-bridge")
        self.thread.start()
        self.log(f"AI bridge listening on {self.url}")

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            self.log("AI bridge stopped")

    @property
    def running(self) -> bool:
        return self.httpd is not None

    def client_config(self) -> dict:
        """Content of pelens-mcp.json for the MCP server on the AI machine."""
        return {"url": self.url, "token": self.token}


def local_addresses() -> list[str]:
    """IPv4 addresses of this machine (the bridge must listen on the one the AI machine can reach)."""
    import socket
    out = []
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127.") and ip not in out:
                out.append(ip)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        s.close()
        if ip not in out and not ip.startswith("127."):
            out.append(ip)
    except OSError:
        pass
    return out or ["127.0.0.1"]


if __name__ == "__main__":                          # quick manual test: python -m pelens.bridge file.exe
    import sys
    from .analyzer import analyze
    reps = {os.path.abspath(p): analyze(p) for p in sys.argv[1:]}
    b = Bridge(lambda: reps, "127.0.0.1", 47011, log=print)
    b.start()
    print("token:", b.token)
    threading.Event().wait()
