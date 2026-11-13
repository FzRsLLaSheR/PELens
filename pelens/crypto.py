"""Static recognition of cryptographic algorithms (without decrypting anything).

Sources of evidence:
- characteristic constants and tables in data and code (signatures in rules/crypto.yaml);
- AES-NI / SHA hardware instructions (from codescan);
- the RC4 key scheduling pattern in the code (from codescan);
- custom Base64 alphabets among the strings.
"""
from __future__ import annotations

import bisect
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .codescan import CRYPTO_MNEMONICS, CodeScanResult
from .pe_info import locate
from .strings import FoundString

DEFAULT_SIGNATURES = Path(__file__).parent / "rules" / "crypto.yaml"
MAX_HITS = 2000   # maximum occurrences considered per single value
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
URL_B64 = STD_B64[:62] + "-_"
_B64_LIKE = set(STD_B64 + "-_.!$*~@#=:;,")


@dataclass
class CryptoHit:
    algorithm: str
    category: str
    signature: str
    confidence: str
    count: int = 1
    offset: int | None = None
    va: int | None = None
    section: str = ""
    details: list | dict = field(default_factory=list)   # additional information (e.g. RC4 variants), JSON only

    def to_dict(self):
        return asdict(self)


def load_signatures(path: str | Path | None = None) -> list[dict[str, Any]]:
    with open(path or DEFAULT_SIGNATURES, encoding="utf-8") as f:
        return yaml.safe_load(f)["algorithms"]


def _find_all(data: bytes, pattern: bytes, limit: int = MAX_HITS) -> list[int]:
    out, pos = [], data.find(pattern)
    while pos != -1 and len(out) < limit:
        out.append(pos)
        pos = data.find(pattern, pos + 1)
    return out


def _match(data: bytes, sig: dict) -> list[int]:
    kind = sig["type"]
    if kind == "bytes":
        return _find_all(data, bytes.fromhex(sig["hex"]))
    if kind == "string":
        return _find_all(data, sig["text"].encode("ascii"))
    if kind in ("dwords", "qwords"):
        size = 4 if kind == "dwords" else 8
        values = [int(v) for v in sig["values"]]
        if sig.get("contiguous", True):
            le = b"".join(v.to_bytes(size, "little") for v in values)
            be = b"".join(v.to_bytes(size, "big") for v in values)
            hits = _find_all(data, le) + (_find_all(data, be) if be != le else [])
            return sorted(hits)
        # non-contiguous: all values within "window" bytes of the first (typical of immediates in code)
        window = sig.get("window", 256)
        positions = [_find_all(data, v.to_bytes(size, "little")) for v in values]
        if not all(positions):
            return []
        hits = []
        for p in positions[0]:
            if all(_near(other, p, window) for other in positions[1:]):
                hits.append(p)
        return hits
    raise ValueError(f"unknown signature type: {kind}")


def _near(sorted_pos: list[int], p: int, window: int) -> bool:
    i = bisect.bisect_left(sorted_pos, p - window)
    return i < len(sorted_pos) and sorted_pos[i] <= p + window


def _custom_base64(strings: list[FoundString]) -> list[FoundString]:
    """Strings of 64-65 all-different characters that look like a Base64 alphabet but not the standard one."""
    out = []
    for s in strings:
        v = s.value
        if len(v) not in (64, 65) or len(set(v)) != len(v):
            continue
        if not set(v) <= _B64_LIKE or sum(c.isalnum() for c in v) < 58:
            continue
        core = v[:64]
        if core in (STD_B64, URL_B64):
            continue
        # a shuffled alphabet has many breaks in the order; "0-9A-Za-z._" or "a-zA-Z0-9_$" are just
        # ordered character sets (e.g. those valid in identifiers), not custom encodings
        breaks = sum(1 for a, b in zip(core, core[1:]) if ord(b) != ord(a) + 1)
        if breaks < 12:
            continue
        out.append(s)
    return out


def _payload_decryption_hits(code: CodeScanResult, sec_of) -> list[CryptoHit]:
    """A decryption loop (XOR or RC4) that reads a high-entropy blob: a loader decrypting its payload.

    Link loop -> blob: a reference to the blob inside the loop's function, or right before
    a call to that function (pointer to the blob passed as an argument).
    """
    if not code.blob_refs:
        return []
    ref_addrs = sorted(a for a, _ in code.blob_refs)
    targets = {a: t for a, t in code.blob_refs}

    def ref_near(lo: int, hi: int) -> int | None:
        i = bisect.bisect_left(ref_addrs, lo)
        return targets[ref_addrs[i]] if i < len(ref_addrs) and ref_addrs[i] <= hi else None

    loops = [("XOR", lp["va"], lp.get("function")) for lp in code.xor_loops]
    loops += [("RC4", va, code.rc4_variants.get(va, {}).get("function")) for va in code.rc4_candidates]
    found: dict[int, CryptoHit] = {}
    for kind, va, func in loops:
        start = func if func and va - func <= 0x400 else va - 0x200
        blob = ref_near(start, va + 0x200)
        via_arg = func is not None and code.blob_ref_calls.get(func, 0) > 0
        if blob is None and not via_arg:
            continue
        key = func or va
        if key in found:
            continue
        how = f"reads the high-entropy data at 0x{blob:x}" if blob is not None else \
            "its caller passes it a pointer to high-entropy data"
        found[key] = CryptoHit("Payload decryption", "payload", f"{kind} decryption loop that {how}", "high",
                               1, None, va, sec_of(va), [{"va": va, "kind": kind, "blob": blob}])
    hits = list(found.values())
    if len(hits) <= 2:
        return hits
    # many loops (e.g. encrypted strings in .data decrypted one by one): a single line, details in the JSON
    first = hits[0]
    return [CryptoHit("Payload decryption", "payload",
                      f"{len(hits)} decryption loops read high-entropy data stored in the file", "high",
                      len(hits), None, first.va, first.section, [d for h in hits for d in h.details])]


XOR_MIN_FAN_IN = 8        # routine called from at least N places...
XOR_PTR_RATIO_HIGH = 0.5  # ...and in at least half of the calls it receives 2+ pointers to data (key + ciphertext)
INLINE_MAX_DIST = 0x60    # XOR loop within 96 bytes of the end of a mov sequence with encrypted data
INLINE_MIN = 4            # at least 4 encrypted stack strings decrypted this way
BLOB_CALLS_MIN = 5        # decryptor called at least 5 times right after encrypted constants on the stack
CALL_PATTERN_MIN = 20     # fallback: function called from at least 20 places...
CALL_PATTERN_RATIO = 0.8  # ...almost always with 2+ pointers to data


def _xor_hits(code: CodeScanResult, sec_of, skip=lambda h: False) -> list[CryptoHit]:
    """XOR decryption routines.

    An XOR loop alone is not enough (hashes, character conversions... big programs are full of them).
    The usage pattern of a string decryptor is needed too: many calls, each with pointers
    to data in the file as arguments.
    """
    loops = code.xor_loops   # (RC4 PRGA loops are already excluded in codescan)
    if not loops:
        return []
    blobs = sorted(code.enc_blobs)

    def after_blob(va: int) -> bool:
        i = bisect.bisect_right(blobs, va) - 1
        return i >= 0 and 0 <= va - blobs[i] <= INLINE_MAX_DIST

    # the key must be in a register (state or immediate), not in memory: whoever encrypts strings "inline"
    # does it precisely to leave no references to data. Rules out, for example, HMAC (key ^ ipad after the SHA IVs).
    # and the loop must be a real loop, closed by a conditional jump (not a piece of flow closed by jmp)
    inline = [lp for lp in loops if after_blob(lp["va"]) and not lp["multibyte_key"] and lp.get("conditional", True)]
    hits: list[CryptoHit] = []
    if len(inline) >= INLINE_MIN:
        rolling = sum(lp.get("rolling") for lp in inline)
        kind = "rolling-key XOR (state += plaintext)" if rolling >= len(inline) / 2 else "XOR"
        hits.append(CryptoHit("XOR", "xor", f"{len(inline)} encrypted stack strings decrypted inline with {kind}",
                              "high" if len(inline) >= 2 * INLINE_MIN else "medium", len(inline), None,
                              inline[0]["va"], sec_of(inline[0]["va"])))
        inline_ids = {id(lp) for lp in inline}
        loops = [lp for lp in loops if id(lp) not in inline_ids]
    by_func: dict = {}
    for lp in loops:
        by_func.setdefault(lp["function"] or lp["va"], []).append(lp)

    for group in by_func.values():
        lp = group[0]
        multi = any(x["multibyte_key"] for x in group)
        key = "multi-byte key" if multi else ("rolling key" if any(x.get("rolling") for x in group)
                                              else "single-byte/register key")
        fan_in, ptr, ptr1 = lp["fan_in"], lp.get("ptr_sites", 0), lp.get("ptr1_sites", 0)
        if fan_in >= XOR_MIN_FAN_IN and ptr >= XOR_MIN_FAN_IN // 2:
            # like Vidar: key and ciphertext passed at every call
            conf = "high" if ptr / fan_in >= XOR_PTR_RATIO_HIGH else "medium"
            sig = (f"XOR decryption routine ({key}): called from {fan_in} places, "
                   f"{ptr} of them with pointers to key/ciphertext")
            va = lp["function"]
        elif fan_in >= XOR_MIN_FAN_IN and multi and ptr1 / fan_in >= 0.75:
            # key fixed inside the routine (e.g. optimized by the compiler): only the ciphertext at every call
            conf = "medium"
            sig = (f"XOR decryption routine (multi-byte key): called from {fan_in} places, "
                   f"{ptr1} of them with a pointer to data")
            va = lp["function"]
        else:
            conf = "low"
            sig = f"XOR loop ({key})" + (f", function called {fan_in}x" if fan_in else "")
            va = lp["va"]
        hits.append(CryptoHit("XOR", "xor", sig, conf, 1, None, va, sec_of(va)))
    # Fallback on the call pattern: function called from many places, almost always with 2+ pointers
    # to data (key + ciphertext), that contains an XOR loop even if attributed to another function.
    # (The call pattern alone is not enough: it is also that of log/error functions with file + message.)
    found = {h.va for h in hits if h.confidence != "low"}
    loop_vas = sorted(lp["va"] for lp in loops)
    for tgt, (n_calls, n_ptr) in code.call_patterns.items():
        if tgt in found or n_calls < CALL_PATTERN_MIN or n_ptr / n_calls < CALL_PATTERN_RATIO:
            continue
        i = bisect.bisect_left(loop_vas, tgt)
        if i < len(loop_vas) and loop_vas[i] < tgt + 0x400:
            hits.append(CryptoHit("XOR", "xor", f"string decryption function: called from {n_calls} places, "
                                  f"{n_ptr} of them with pointers to key/ciphertext, contains an XOR loop",
                                  "medium", 1, None, tgt, sec_of(tgt)))

    # Decryptor fed with encrypted data written to the stack (e.g. decode_string of the ClickFix payload:
    # constants -> stack -> call decode(buf, seed)): many calls preceded by a blob, and an XOR loop inside.
    found = {h.va for h in hits if h.confidence != "low"}
    for tgt, (n_calls, n_blob) in code.blob_calls.items():
        if tgt in found or n_blob < BLOB_CALLS_MIN:
            continue
        # key/state in a register (seed passed as an argument), not read from memory
        inside = [lp for lp in loops if tgt <= lp["va"] < tgt + 0x400 and not lp["multibyte_key"]]
        if not inside:
            continue
        kind = "rolling key" if any(lp.get("rolling") for lp in inside) else "single-byte/register key"
        hits.append(CryptoHit("XOR", "xor", f"string decryption function ({kind}): called {n_blob} times right after "
                              f"encrypted data is written to the stack", "high" if n_blob >= 2 * BLOB_CALLS_MIN
                              else "medium", 1, None, tgt, sec_of(tgt)))
        found.add(tgt)
    # low-confidence loops inside functions already recognized are not repeated
    hits = [h for h in hits if h.confidence != "low" or not any(f <= (h.va or -1) < f + 0x400 for f in found)]
    hits = [h for h in hits if not skip(h)]

    hits.sort(key=lambda h: (-CONFIDENCE_ORDER[h.confidence], h.va or 0))
    strong = [h for h in hits if h.confidence != "low"]
    weak = [h for h in hits if h.confidence == "low"]
    if len(weak) > 5:   # do not clutter the report: summarize the low-confidence loops
        weak = weak[:4] + [CryptoHit("XOR", "xor", f"{len(weak) - 4} more XOR loops", "low", len(weak) - 4)]
    return strong + weak


def _rc4_variants(details: list[dict]) -> list[dict]:
    """Groups RC4 implementations (often inlined copies of the same function) by variant.

    The initialization constant (S[i] = i ^ K) is read reliably in every copy; the drop and the
    extra XOR are not: with junk code in between or with the compiler splitting things up they are sometimes
    not visible. So: group by constant; inside the group, different drops are different variants and the copies
    without a readable drop go into the most common variant. The extra XOR counts if it is seen in at least half
    of the copies: nearby junk code can add XORs that are not part of the algorithm.
    """
    by_init: dict = {}
    for d in details:
        by_init.setdefault(d["ksa_init_xor"], []).append(d)
    variants = []
    for init, group in by_init.items():
        by_drop: dict = {}
        unknown = []
        for d in group:
            (by_drop.setdefault(d["drop"], []) if d["drop"] is not None else unknown).append(d)
        if by_drop:
            biggest = max(by_drop, key=lambda k: len(by_drop[k]))
            by_drop[biggest].extend(unknown)
        else:
            by_drop[None] = unknown
        for drop, g in by_drop.items():
            seen = [x for x in g if x["drop"] is not None]
            n_xor = sum(1 for x in g if x["extra_xor"])
            variants.append({"ksa_init_xor": init, "drop": drop, "extra_xor": n_xor * 2 >= len(g),
                             "copies": len(g), "called_from": sum(x["called_from"] for x in g),
                             "drop_seen_in": len(seen), "extra_xor_seen_in": sum(1 for x in g if x["extra_xor"]),
                             "first_va": min(x["va"] for x in g)})
    variants.sort(key=lambda v: (-v["copies"], -v["called_from"]))
    return variants


def detect(data: bytes, info: dict, code: CodeScanResult, strings: list[FoundString],
           signatures_path: str | None = None) -> list[dict[str, Any]]:
    # the Authenticode signature contains certificates (RSA/SHA OIDs...) that are not program code
    sig_dir = info.get("signature")
    if sig_dir:
        lo, hi = sig_dir["offset"], sig_dir["offset"] + sig_dir["size"]
        scan = data[:lo] + b"\x00" * max(0, min(hi, len(data)) - lo) + data[hi:]
    else:
        scan = data

    hits: list[CryptoHit] = []
    for algo in load_signatures(signatures_path):
        for sig in algo["signatures"]:
            positions = _match(scan, sig)
            if positions:
                va, section = locate(info, positions[0])
                hits.append(CryptoHit(algo["name"], algo["category"], sig["name"], sig["confidence"],
                                      len(positions), positions[0], va, section))

    def sec_of(va: int) -> str:
        rva = va - info["image_base"]
        return next((s["name"] for s in info["sections"]
                     if s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"])), "")

    # RC4: a single line. The traits of the single implementations (modified initialization,
    # dropped bytes, extra XOR on the output) go into the JSON details.
    if code.rc4_candidates:
        details, n_calls, modified = [], 0, False
        for va in code.rc4_candidates:
            v = code.rc4_variants.get(va, {})
            feats = {"ksa_init_xor": v.get("ksa_xor"), "drop": v.get("drop"), "extra_xor": v.get("extra_xor", False)}
            modified |= any(feats.values())
            n_calls += v.get("fan_in", 0)
            details.append({"va": va, "section": sec_of(va), "function": v.get("function"),
                            "called_from": v.get("fan_in", 0), **feats})
        n = len(details)
        variants = _rc4_variants(details)
        nv = len(variants)
        if nv < n:
            sig = f"RC4 key schedule + keystream loops: {nv} variant{'s' if nv > 1 else ''} ({n} copies)"
        else:
            sig = f"RC4 key schedule + keystream loops: {n} implementation{'s' if n > 1 else ''}"
        if modified:
            sig += ", non-standard variant" + ("s" if nv > 1 else "")
        if n_calls > 1:
            sig += f", called from {n_calls} places"
        if modified and nv <= 8:
            def _desc(v):
                parts = []
                if v["ksa_init_xor"] is not None:
                    parts.append(f"S[i]=i^0x{v['ksa_init_xor']:x}")
                if v["drop"]:
                    parts.append(f"drop {v['drop']}")
                if v["extra_xor"]:
                    parts.append("extra xor")
                elif v.get("extra_xor_seen_in"):
                    parts.append(f"(extra xor in {v['extra_xor_seen_in']}/{v['copies']})")
                return " ".join(parts) or "standard"
            sig += " — " + "; ".join(_desc(v) + (f" ×{v['copies']}" if v["copies"] > 1 else "") for v in variants)
        first = code.rc4_candidates[0]
        hits.append(CryptoHit("RC4", "stream_cipher", sig, "high" if modified else "medium", n, None,
                              first, sec_of(first), {"variants": variants, "implementations": details}
                              if nv < n else details))

    payload = _payload_decryption_hits(code, sec_of)
    hits.extend(payload)
    # XOR loops already reported as payload decryption are not repeated among the low-confidence ones
    covered = {d["va"] for h in payload for d in h.details}
    # the final RC4 XOR (data ^ keystream) is not a separate XOR routine: RC4 functions and loops
    # near inlined copies are not counted a second time as "XOR decryption"
    rc4_funcs = {v.get("function") for v in code.rc4_variants.values() if v.get("function")}
    rc4_vas = sorted(code.rc4_candidates)

    def _is_rc4(h: CryptoHit) -> bool:
        if h.va is None:
            return False
        if h.va in rc4_funcs:
            return True
        i = bisect.bisect_right(rc4_vas, h.va + 0x100) - 1
        return h.confidence == "low" and i >= 0 and h.va - rc4_vas[i] <= 0x400

    xor = [h for h in _xor_hits(code, sec_of, skip=_is_rc4)
           if not (h.confidence == "low" and h.va in covered)]
    hits.extend(xor)

    for mnem, (va, n) in sorted(code.crypto_instructions.items()):
        algo = CRYPTO_MNEMONICS[mnem]
        hits.append(CryptoHit(algo, "block_cipher" if algo == "AES" else "hash",
                              f"hardware instruction {mnem}", "high", n, None, va, sec_of(va)))

    for s in _custom_base64(strings):
        hits.append(CryptoHit("Custom Base64", "encoding", f"alphabet: {s.value}", "medium",
                              1, s.offset, s.va, s.section))

    hits += _compression_api_hits(info, strings)
    hits.sort(key=lambda h: (-CONFIDENCE_ORDER[h.confidence], h.algorithm))
    return [h.to_dict() for h in hits]


# Windows decompression APIs: LZNT1/Xpress (ntdll) and the Compression API (cabinet.dll)
_RTL_DECOMPRESS = {"RtlDecompressBuffer", "RtlDecompressBufferEx", "RtlDecompressBufferEx2", "RtlDecompressFragment",
                   "RtlGetCompressionWorkSpaceSize"}
_CABINET = {"CreateDecompressor", "Decompress"}


def _compression_api_hits(info: dict, strings: list[FoundString]) -> list[CryptoHit]:
    """Decompression through Windows: imported, or the name as a string (resolved at runtime with GetProcAddress)."""
    imported, cabinet = set(), set()
    for imp in info.get("imports") or []:
        funcs = set(imp["functions"])
        imported |= funcs & _RTL_DECOMPRESS
        if imp["dll"].lower().startswith("cabinet"):
            cabinet |= funcs & _CABINET
    runtime = {s.value for s in strings if s.value in _RTL_DECOMPRESS} - imported
    out = []
    for names, how, algo in ((imported, "imported", "LZNT1/Xpress (Windows)"),
                             (runtime, "resolved at runtime (name as a string)", "LZNT1/Xpress (Windows)"),
                             (cabinet, "imported from cabinet.dll", "Windows Compression API")):
        if names:
            out.append(CryptoHit(algo, "compression", f"{', '.join(sorted(names))} {how}", "high", len(names),
                                 None, None, ""))
    return out
