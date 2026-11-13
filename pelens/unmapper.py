"""Rebuilding a PE dumped from memory.

A dump taken from a process has the sections at their virtual addresses ("mapped" layout), the pointers already
relocated to the load base and often the IAT filled with API addresses. Here we:
- recognize the layout (mapped or raw) and the load base (from the relocated values);
- rebuild the file: "unmap" (sections at the raw offsets of the headers), "realign" (raw = virtual, robust when
  the dump's headers are dirty) or "auto";
- rebase to another base applying the relocations (optional);
- restore the IAT from the INT (OriginalFirstThunk) if the dump kept it.
Nothing is executed.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

import pefile

ALIGN_64K = 0x10000


@dataclass
class UnmapResult:
    data: bytes
    mode: str
    layout: str
    load_base: int
    image_base: int
    log: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    relocations: int = 0
    iat_restored: int = 0

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d.pop("data")
        d["size"] = len(self.data)
        return d


def _align(v: int, a: int) -> int:
    return (v + a - 1) // a * a if a else v


class Dump:
    """Headers and sections read from the dump (the headers are always at the start, in both layouts)."""

    def __init__(self, data: bytes, headers_from: bytes | None = None):
        self.raw = data
        hdr_src = headers_from if headers_from is not None else data
        if hdr_src[:2] != b"MZ":
            raise ValueError("the dump has no PE headers (MZ missing): they were probably wiped. "
                             "Provide the original file to take the headers from.")
        try:
            pe = pefile.PE(data=bytes(hdr_src[:0x4000]), fast_load=True)
        except pefile.PEFormatError as e:
            raise ValueError(f"PE headers are damaged: {e}") from e
        oh = pe.OPTIONAL_HEADER
        self.is64 = oh.Magic == 0x20B
        self.header_base = oh.ImageBase
        self.size_of_image = oh.SizeOfImage
        self.size_of_headers = oh.SizeOfHeaders
        self.sec_align = oh.SectionAlignment or 0x1000
        self.file_align = oh.FileAlignment or 0x200
        self.lfanew = pe.DOS_HEADER.e_lfanew
        self.opt_off = self.lfanew + 24
        self.sec_table = self.opt_off + pe.FILE_HEADER.SizeOfOptionalHeader
        self.sections = [{"name": s.Name.rstrip(b"\0").decode("latin-1"), "va": s.VirtualAddress,
                          "vsize": s.Misc_VirtualSize, "raw_ptr": s.PointerToRawData, "raw_size": s.SizeOfRawData,
                          "chars": s.Characteristics} for s in pe.sections]
        dd = oh.DATA_DIRECTORY
        self.reloc = (dd[5].VirtualAddress, dd[5].Size) if len(dd) > 5 else (0, 0)
        self.imports = (dd[1].VirtualAddress, dd[1].Size) if len(dd) > 1 else (0, 0)
        self.headers = bytes(hdr_src[:max(self.size_of_headers, 0x200)])
        pe.close()


# --- layout ------------------------------------------------------------------------------------------

def _rva_to_raw(d: Dump, rva: int) -> int | None:
    if rva < d.size_of_headers:
        return rva
    for s in d.sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
            off = rva - s["va"]
            return s["raw_ptr"] + off if off < s["raw_size"] else None
    return None


def _count_valid_imports(d: Dump, buf: bytes, mapped: bool) -> int:
    rva = d.imports[0]
    if not rva:
        return 0
    conv = (lambda r: r) if mapped else (lambda r: _rva_to_raw(d, r))
    off = conv(rva)
    good = 0
    for i in range(64):
        if off is None or off + 20 > len(buf):
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", buf, off + 20 * i)
        if not (oft or name_rva or ft):
            break
        n = conv(name_rva) if name_rva else None
        if n is None or n >= len(buf):
            break
        name = buf[n:n + 64].split(b"\0")[0]
        if name.lower().endswith((b".dll", b".drv", b".sys", b".exe", b".ocx")) and name.isascii():
            good += 1
        else:
            break
    return good


def detect_layout(d: Dump) -> tuple[str, str]:
    """('mapped' | 'raw', reason)."""
    buf = d.raw
    vm = _count_valid_imports(d, buf, True)
    vr = _count_valid_imports(d, buf, False)
    if vm != vr:
        return ("mapped" if vm > vr else "raw"), f"import table readable as {'virtual' if vm > vr else 'raw'} layout"
    differs = [s for s in d.sections if s["va"] != s["raw_ptr"] and s["raw_size"]]
    if not differs:
        return "raw", "raw and virtual layouts coincide"
    if len(buf) >= d.size_of_image:
        # where is the section data? compare the content at the virtual address and at the raw offset
        mapped_hits = sum(1 for s in differs if any(buf[s["va"]:s["va"] + 0x200]))
        raw_hits = sum(1 for s in differs if any(buf[s["raw_ptr"]:s["raw_ptr"] + 0x200]))
        if mapped_hits >= raw_hits:
            return "mapped", "file size ≥ SizeOfImage and section data at the virtual addresses"
    return "raw", "file smaller than SizeOfImage"


def to_mapped(d: Dump, layout: str) -> bytearray:
    """In-memory image (SizeOfImage bytes) from the dump."""
    size = max(d.size_of_image, max((s["va"] + max(s["vsize"], s["raw_size"]) for s in d.sections), default=0))
    mem = bytearray(size)
    if layout == "mapped":
        n = min(len(d.raw), size)
        mem[:n] = d.raw[:n]
    else:
        mem[:d.size_of_headers] = d.raw[:d.size_of_headers]
        for s in d.sections:
            chunk = d.raw[s["raw_ptr"]:s["raw_ptr"] + min(s["raw_size"], max(s["vsize"], s["raw_size"]))]
            mem[s["va"]:s["va"] + len(chunk)] = chunk
    # headers taken from another file (dump with wiped headers)
    mem[:len(d.headers)] = d.headers[:len(mem)]
    return mem


# --- relocations and base ----------------------------------------------------------------------------------

def relocations(d: Dump, mem: bytes) -> list[tuple[int, int]]:
    """(rva, type) of the values to relocate: 3 = HIGHLOW (32 bit), 10 = DIR64."""
    rva, size = d.reloc
    out = []
    off, end = rva, min(rva + size, len(mem))
    while 0 < off + 8 <= end:
        page, block = struct.unpack_from("<II", mem, off)
        if block < 8 or off + block > end:
            break
        for i in range((block - 8) // 2):
            e = struct.unpack_from("<H", mem, off + 8 + 2 * i)[0]
            t, o = e >> 12, e & 0xFFF
            if t in (3, 10):
                out.append((page + o, t))
        off += block
    return out


def _ptr(mem: bytes, rva: int, t: int) -> int | None:
    n = 8 if t == 10 else 4
    if rva + n > len(mem):
        return None
    return int.from_bytes(mem[rva:rva + n], "little")


def detect_load_base(d: Dump, mem: bytes, relocs: list) -> tuple[int, str]:
    """Base the module was loaded at: the relocated pointers must fall inside [base, base + SizeOfImage)."""
    vals = [v for v in (_ptr(mem, r, t) for r, t in relocs[:4000]) if v]
    if not vals:
        return d.header_base, "no relocations: assuming the ImageBase from the header"

    def fits(b):
        return sum(1 for v in vals if b <= v < b + d.size_of_image) / len(vals)

    if fits(d.header_base) >= 0.9:
        return d.header_base, f"relocated pointers fit the ImageBase in the header ({fits(d.header_base):.0%})"
    lo, hi = min(vals), max(vals)
    # base aligned to 64 KB, <= the lowest pointer; the candidate where most of the values fall is chosen
    # (some pointers may have been overwritten at runtime)
    cands = {(v - x) // ALIGN_64K * ALIGN_64K for v in sorted(vals)[:50] for x in range(0, min(d.size_of_image, 0x100000), ALIGN_64K)}
    best = max(cands, key=lambda b: (fits(b), b))
    return best, f"{fits(best):.0%} of the relocated pointers fall inside the image at this base"


def rebase(d: Dump, mem: bytearray, relocs: list, old: int, new: int) -> int:
    delta = new - old
    if not delta:
        return 0
    n = 0
    for rva, t in relocs:
        size = 8 if t == 10 else 4
        if rva + size > len(mem):
            continue
        v = int.from_bytes(mem[rva:rva + size], "little")
        mem[rva:rva + size] = ((v + delta) & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        n += 1
    return n


# --- IAT -----------------------------------------------------------------------------------------------

def restore_iat(d: Dump, mem: bytearray) -> tuple[int, int]:
    """Copies the INT (OriginalFirstThunk) over the IAT (FirstThunk). (restored thunks, DLLs without INT)."""
    rva = d.imports[0]
    if not rva:
        return 0, 0
    tsz = 8 if d.is64 else 4
    restored = missing = 0
    for i in range(512):
        off = rva + 20 * i
        if off + 20 > len(mem):
            break
        oft, _ts, _fc, name, ft = struct.unpack_from("<IIIII", mem, off)
        if not (oft or name or ft):
            break
        if not oft or oft == ft:
            missing += 1
            continue
        for k in range(8192):
            a, b = oft + k * tsz, ft + k * tsz
            if a + tsz > len(mem) or b + tsz > len(mem):
                break
            v = mem[a:a + tsz]
            if mem[b:b + tsz] != v:
                mem[b:b + tsz] = v
                restored += 1
            if not any(v):
                break
    return restored, missing


# --- rebuilding -------------------------------------------------------------------------------------

def _raw_layout_ok(d: Dump) -> tuple[bool, str]:
    secs = [s for s in d.sections if s["raw_size"]]
    if not secs:
        return False, "no section declares raw data"
    prev_end = d.size_of_headers
    for s in sorted(secs, key=lambda s: s["raw_ptr"]):
        if s["raw_ptr"] < prev_end:
            return False, f"section {s['name']} overlaps the previous one in the raw layout"
        if s["raw_ptr"] % max(1, min(d.file_align, 0x200)):
            return False, f"section {s['name']} has a misaligned raw offset"
        if s["raw_size"] > 0x10000000:
            return False, f"section {s['name']} has an implausible raw size"
        prev_end = s["raw_ptr"] + s["raw_size"]
    return True, "raw offsets and sizes in the headers are consistent"


def unmap(data: bytes, *, mode: str = "auto", layout: str = "auto", load_base: int | None = None,
          new_base: int | None = None, restore_imports: bool = True, headers_from: bytes | None = None) -> UnmapResult:
    """Rebuilds a PE from a dump.

    mode: "auto" | "unmap" | "realign"; layout: "auto" | "mapped" | "raw";
    load_base: base it was loaded at (None = detected); new_base: base of the rebuilt file (None = load_base).
    """
    d = Dump(data, headers_from)
    log, warn = [], []
    if headers_from is not None:
        log.append("headers taken from the reference file")
    if layout == "auto":
        layout, why = detect_layout(d)
        log.append(f"layout: {layout} ({why})")
    else:
        log.append(f"layout: {layout} (forced)")
    if layout == "mapped" and len(data) < d.size_of_image:
        warn.append(f"the dump is shorter than SizeOfImage (0x{len(data):x} < 0x{d.size_of_image:x}): "
                    "the missing part is filled with zeros")
    mem = to_mapped(d, layout)
    rel = relocations(d, mem)
    if load_base is None:
        if layout == "mapped":
            load_base, why = detect_load_base(d, mem, rel)
            log.append(f"load base: 0x{load_base:x} ({why})")
        else:
            load_base = d.header_base
            log.append(f"load base: 0x{load_base:x} (raw file: ImageBase from the header)")
    else:
        log.append(f"load base: 0x{load_base:x} (given)")
    target = load_base if new_base is None else new_base
    n_rel = rebase(d, mem, rel, load_base, target)
    if target != load_base:
        log.append(f"rebased from 0x{load_base:x} to 0x{target:x}: {n_rel} relocations applied")
    elif not rel:
        warn.append("no relocation table: the base cannot be changed")
    restored = 0
    if restore_imports:
        restored, missing = restore_iat(d, mem)
        if restored:
            log.append(f"IAT restored from the import name table: {restored} thunks")
        if missing:
            warn.append(f"{missing} imported DLL(s) have no name table (OriginalFirstThunk): their IAT still holds "
                        "resolved addresses; rebuild them with Scylla if needed")

    if mode == "auto":
        ok, why = _raw_layout_ok(d)
        mode = "unmap" if ok else "realign"
        log.append(f"mode: {mode} ({why})")
    else:
        log.append(f"mode: {mode} (forced)")

    secs = []
    if mode == "unmap":
        out_size = max([d.size_of_headers] + [s["raw_ptr"] + s["raw_size"] for s in d.sections if s["raw_size"]])
        out = bytearray(out_size)
        out[:d.size_of_headers] = mem[:d.size_of_headers]
        for s in d.sections:
            n = min(s["raw_size"], max(0, len(mem) - s["va"]))
            out[s["raw_ptr"]:s["raw_ptr"] + n] = mem[s["va"]:s["va"] + n]
            secs.append({**s, "new_raw_ptr": s["raw_ptr"], "new_raw_size": s["raw_size"]})
        file_align = d.file_align
    else:   # realign: each section is in the file at the same offset as its virtual address
        out = bytearray(mem[:_align(len(mem), d.sec_align)].ljust(_align(len(mem), d.sec_align), b"\0"))
        for s in d.sections:
            size = _align(max(s["vsize"], s["raw_size"]), d.sec_align)
            size = min(size, len(out) - s["va"])
            secs.append({**s, "new_raw_ptr": s["va"], "new_raw_size": max(0, size)})
        file_align = d.sec_align

    # headers: section table, ImageBase, FileAlignment
    for i, s in enumerate(secs):
        o = d.sec_table + 40 * i
        struct.pack_into("<II", out, o + 16, s["new_raw_size"], s["new_raw_ptr"])
    if d.is64:
        struct.pack_into("<Q", out, d.opt_off + 24, target)
    else:
        struct.pack_into("<I", out, d.opt_off + 28, target)
    struct.pack_into("<I", out, d.opt_off + 36, file_align)
    # the Certificate Table makes no sense in a dump (it is an offset in the original file)
    dd = d.opt_off + (112 if d.is64 else 96)
    struct.pack_into("<II", out, dd + 4 * 8, 0, 0)

    try:
        pe = pefile.PE(data=bytes(out), fast_load=True)
        if struct.unpack_from("<I", out, d.opt_off + 64)[0]:   # recomputed only if the header had one
            struct.pack_into("<I", out, d.opt_off + 64, pe.generate_checksum())
        pe.close()
    except pefile.PEFormatError as e:
        warn.append(f"the rebuilt file does not parse cleanly: {e}")
    log.append(f"output: {len(out):,} bytes, ImageBase 0x{target:x}")
    return UnmapResult(bytes(out), mode, layout, load_base, target, log, warn, secs, n_rel, restored)


def map_image(data: bytes, base: int | None = None, fill_iat: bool = True) -> bytes:
    """The opposite: simulates the loader (sections at the virtual addresses, relocations on the given base, IAT
    filled with fake addresses). Used by the tests and to try the unmapper."""
    d = Dump(data)
    mem = to_mapped(d, "raw")
    rel = relocations(d, mem)
    if base is not None and base != d.header_base:
        rebase(d, mem, rel, d.header_base, base)
        if d.is64:
            struct.pack_into("<Q", mem, d.opt_off + 24, base)
        else:
            struct.pack_into("<I", mem, d.opt_off + 28, base)
    if fill_iat and d.imports[0]:
        tsz = 8 if d.is64 else 4
        fake = 0x7FF800000000 if d.is64 else 0x76000000
        for i in range(512):
            off = d.imports[0] + 20 * i
            oft, _ts, _fc, name, ft = struct.unpack_from("<IIIII", mem, off)
            if not (oft or name or ft):
                break
            for k in range(8192):
                b = ft + k * tsz
                if b + tsz > len(mem) or not any(mem[b:b + tsz]):
                    break
                mem[b:b + tsz] = (fake + 0x10 * k + 0x10000 * i).to_bytes(tsz, "little")
    return bytes(mem)
