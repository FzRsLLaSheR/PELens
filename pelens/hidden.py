"""PEs hidden anywhere in the file: in clear or encrypted with a repeating-key XOR.

Known-plaintext attack on the DOS header: bytes 0x1C-0x3B of the header are almost always zero, so
in a PE encrypted with a key of period p that area contains the repeated key and data[i] == data[i+p].
XORing the file with itself shifted by p turns those areas into runs of zeros, which a regex finds
at once; only there is the full header tried and confirmed with the "PE\\0\\0" signature at e_lfanew.
Nothing is extracted or decrypted beyond the header needed to recognize it.
"""
from __future__ import annotations

import re
import struct

from .dotnet_resources import find_xor_pe

MAX_SCAN = 48 * 1024 * 1024   # beyond this only the first 48 MB are analyzed
ZERO_START, ZERO_END = 0x1C, 0x3C   # reserved bytes of the DOS header: zero in every PE
SCAN_MAX_KEY = 24                   # when scanning the whole file: keys up to 24 bytes
MAX_HITS = 50

_MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2"}


def _describe(head: bytes) -> dict:
    """Type and declared size of the PE, read from the (already decrypted) headers."""
    out: dict = {}
    try:
        lf = struct.unpack_from("<I", head, 0x3C)[0]
        machine, nsec = struct.unpack_from("<HH", head, lf + 4)
        sooh, chars = struct.unpack_from("<HH", head, lf + 20)
        magic = struct.unpack_from("<H", head, lf + 24)[0]
        out["machine"] = _MACHINES.get(machine, hex(machine))
        out["kind"] = "dll" if chars & 0x2000 else "exe"
        dd = lf + 24 + (112 if magic == 0x20B else 96)
        if sooh > (dd - lf - 24) + 14 * 8 + 4 and len(head) >= dd + 15 * 8:
            clr_rva, clr_size = struct.unpack_from("<II", head, dd + 14 * 8)
            out["dotnet"] = bool(clr_rva and clr_size)
        sec = lf + 24 + sooh
        end = 0
        for i in range(min(nsec, 96)):
            if sec + 40 * (i + 1) > len(head):
                break
            raw_size, raw_ptr = struct.unpack_from("<II", head, sec + 40 * i + 16)
            end = max(end, raw_ptr + raw_size)
        if end:
            out["size"] = end
    except struct.error:
        pass
    return out


def _decoded_head(data: bytes, off: int, key: bytes) -> bytes:
    head = data[off:off + 0x1000]
    if not any(key):
        return head
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(head))


def scan(data: bytes, skip_ranges: list[tuple[int, int]] | None = None) -> list[dict]:
    """PEs hidden in the file (excluding the file's own header, at offset 0)."""
    data = data[:MAX_SCAN]
    skip_ranges = skip_ranges or []
    found: dict[int, dict] = {}

    def skipped(off):
        return off == 0 or any(a <= off < b for a, b in skip_ranges)

    # 1) in clear: "MZ" with "PE\0\0" at e_lfanew
    for m in re.finditer(rb"MZ", data):
        off = m.start()
        if skipped(off) or len(found) >= MAX_HITS:
            continue
        hit = find_xor_pe(data[off:off + 0x1000], max_skip=0)
        if hit and not hit["encrypted"]:
            found[off] = {"offset": off, "encrypted": False, "key": "", "key_length": 0}

    # 2) XOR-encrypted: periodic areas where the zeros of the DOS header should be
    n = len(data)
    if n > 0x1000:
        whole = int.from_bytes(data, "big")
        for p in range(1, SCAN_MAX_KEY + 1):
            x = (whole >> (8 * p)) ^ (whole & ((1 << (8 * (n - p))) - 1))
            xb = x.to_bytes(n - p, "big")    # xb[i] == data[i] ^ data[i + p]
            need = max(8, (ZERO_END - ZERO_START) - p)
            for m in re.finditer(rb"\x00{%d,}" % need, xb):
                if len(found) >= MAX_HITS:
                    break
                r, e = m.start(), m.end()
                if e - r > 512:
                    continue   # constant padding, not a header
                if not any(data[r:r + p]):
                    continue   # real zeros: a PE in clear, already searched for above
                j0 = ZERO_START + (-ZERO_START) % p          # position in the zero area with the same key byte as
                j1 = ZERO_START + (1 - ZERO_START) % p       # "M" and "Z"
                for off in range(max(1, r - ZERO_START - 8), r - ZERO_START + 2 + p):
                    # quick filter: "MZ" decrypted with the key read in the zero area must come back
                    if off + 0x40 > n or data[off] ^ 0x4D != data[off + j0] or data[off + 1] ^ 0x5A != data[off + j1]:
                        continue
                    if skipped(off) or off in found:
                        continue
                    hit = find_xor_pe(data[off:off + 0x1000], max_skip=0)
                    if hit and hit["encrypted"]:
                        found[off] = {"offset": off, "encrypted": True, "key": hit["key"],
                                      "key_length": hit["key_length"]}
                        break
    out = []
    for off in sorted(found):
        h = found[off]
        h.update(_describe(_decoded_head(data, off, bytes.fromhex(h["key"]) if h["key"] else b"")))
        out.append(h)
    return out
