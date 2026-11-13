"""Resource content in readable form: icons, bitmaps, manifests, version info, string tables.

Format conversions for the preview only (no dependency on the GUI, so it can be tested).
"""
from __future__ import annotations

import re
import struct

# magic of the images Qt can show
_IMAGE_MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG"), (b"GIF87a", "GIF"), (b"GIF89a", "GIF"), (b"\xff\xd8\xff", "JPEG"),
                (b"BM", "BMP"), (b"\x00\x00\x01\x00", "ICO"), (b"\x00\x00\x02\x00", "CUR")]


def image_format(blob: bytes) -> str | None:
    for magic, name in _IMAGE_MAGIC:
        if blob.startswith(magic):
            if name == "BMP" and (len(blob) < 26 or int.from_bytes(blob[2:6], "little") > len(blob) * 4 + 1024):
                continue
            return name
    return None


def dib_to_bmp(dib: bytes) -> bytes | None:
    """RT_BITMAP holds a DIB without BITMAPFILEHEADER: we add it."""
    if len(dib) < 16:
        return None
    hsize = int.from_bytes(dib[:4], "little")
    if hsize not in (12, 40, 52, 56, 108, 124):
        return None
    if hsize == 12:
        bits = int.from_bytes(dib[10:12], "little")
        colors = (1 << bits) if bits <= 8 else 0
        palette = colors * 3
    else:
        bits = int.from_bytes(dib[14:16], "little")
        compression = int.from_bytes(dib[16:20], "little")
        used = int.from_bytes(dib[32:36], "little") if len(dib) >= 36 else 0
        colors = used or ((1 << bits) if bits <= 8 else 0)
        palette = colors * 4 + (12 if compression == 3 and hsize == 40 else 0)
    pixels = 14 + hsize + palette
    return b"BM" + struct.pack("<IHHI", 14 + len(dib), 0, 0, pixels) + dib


def group_icon_to_ico(group: bytes, icons: dict[int, bytes], cursor: bool = False) -> bytes | None:
    """RT_GROUP_ICON (GRPICONDIR) + the RT_ICONs it points to -> .ico file."""
    if len(group) < 6:
        return None
    _, typ, count = struct.unpack_from("<HHH", group)
    entry = 14
    imgs = []
    for i in range(count):
        o = 6 + i * entry
        if o + entry > len(group):
            break
        w, h, cc, _r, planes, bits, size, rid = struct.unpack_from("<BBBBHHIH", group, o)
        blob = icons.get(rid)
        if blob:
            imgs.append(((w, h, cc, planes, bits), blob))
    if not imgs:
        return None
    out = bytearray(struct.pack("<HHH", 0, 2 if cursor else 1, len(imgs)))
    off = 6 + 16 * len(imgs)
    for (w, h, cc, planes, bits), blob in imgs:
        out += struct.pack("<BBBBHHII", w, h, cc, 0, planes, bits, len(blob), off)
        off += len(blob)
    for _, blob in imgs:
        out += blob
    return bytes(out)


def icon_to_ico(blob: bytes) -> bytes:
    """A single RT_ICON (DIB or PNG) as an .ico with one image."""
    w = h = 0
    if blob.startswith(b"\x89PNG"):
        w, h = struct.unpack(">II", blob[16:24])
    elif len(blob) >= 12:
        w = int.from_bytes(blob[4:8], "little")
        h = int.from_bytes(blob[8:12], "little", signed=True) // 2
    return struct.pack("<HHHBBBBHHII", 0, 1, 1, w & 0xFF, h & 0xFF, 0, 0, 1, 32, len(blob), 22) + blob


def string_table(blob: bytes, block_id: int | None) -> list[tuple[int, str]]:
    """RT_STRING: blocks of 16 length-prefixed UTF-16 strings; the ID is (block-1)*16 + index."""
    out = []
    pos = 0
    base = (block_id - 1) * 16 if block_id else 0
    for i in range(16):
        if pos + 2 > len(blob):
            break
        n = int.from_bytes(blob[pos:pos + 2], "little")
        pos += 2
        if n:
            out.append((base + i, blob[pos:pos + n * 2].decode("utf-16-le", "replace")))
        pos += n * 2
    return out


def decode_text(blob: bytes) -> str | None:
    """Text (manifest, script, config) in UTF-8/UTF-16, if it really is text."""
    if blob.startswith(b"\xef\xbb\xbf"):
        blob = blob[3:]
    if blob.startswith((b"\xff\xfe", b"\xfe\xff")) or (len(blob) > 8 and blob[1:8:2] == b"\0\0\0\0"):
        try:
            t = blob.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        try:
            t = blob.decode("utf-8")
        except UnicodeDecodeError:
            return None
    t = t.rstrip("\0")
    if not t:
        return None
    printable = sum(c.isprintable() or c in "\r\n\t" for c in t)
    return t if printable / len(t) > 0.95 else None


def manifest_notes(text: str) -> list[str]:
    """Important details of a manifest: requested privilege level, uiAccess, DPI..."""
    notes = []
    m = re.search(r'requestedExecutionLevel[^>]*level\s*=\s*["\'](\w+)', text)
    if m:
        lvl = m.group(1)
        notes.append({"requireAdministrator": "asks for administrator rights (UAC prompt)",
                      "highestAvailable": "runs with the highest rights the user has",
                      "asInvoker": "runs with the rights of the caller"}.get(lvl, f"execution level {lvl}"))
    if re.search(r'uiAccess\s*=\s*["\']true', text, re.I):
        notes.append("uiAccess=true: may drive the UI of elevated windows")
    if re.search(r"<autoElevate>\s*true", text, re.I):
        notes.append("autoElevate: elevates without a UAC prompt (Windows binaries only)")
    return notes


def version_text(info: dict | None) -> str:
    if not info:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in info.items() if not isinstance(v, (dict, list)))


def preview(res: dict, blob: bytes, read_res, version_info: dict | None = None) -> dict:
    """Preview of a PE resource.

    read_res(type, name) -> bytes or None: reads another resource (the icons of the group).
    Returns {"kind": "image"|"text"|"hex", "data": ..., "format": ..., "notes": [...]}.
    """
    t = str(res.get("type", ""))
    if t in ("RT_GROUP_ICON", "RT_GROUP_CURSOR"):
        if len(blob) >= 6:
            count = struct.unpack_from("<H", blob, 4)[0]
            icons = {}
            sub = "RT_ICON" if t == "RT_GROUP_ICON" else "RT_CURSOR"
            for i in range(count):
                o = 6 + i * 14
                if o + 14 <= len(blob):
                    rid = struct.unpack_from("<H", blob, o + 12)[0]
                    b = read_res(sub, str(rid))
                    if b:
                        icons[rid] = b[4:] if sub == "RT_CURSOR" else b   # the cursor has the hotspot in front
            ico = group_icon_to_ico(blob, icons, cursor=t == "RT_GROUP_CURSOR")
            if ico:
                return {"kind": "image", "data": ico, "format": "ICO", "notes": [f"{len(icons)} images"]}
    if t == "RT_CURSOR" and len(blob) > 8:
        return {"kind": "image", "data": icon_to_ico(blob[4:]), "format": "CUR", "notes": [
            f"hotspot {struct.unpack_from('<H', blob)[0]},{struct.unpack_from('<H', blob, 2)[0]}"]}
    if t == "RT_ICON":
        return {"kind": "image", "data": icon_to_ico(blob), "format": "ICO", "notes": []}
    if t == "RT_BITMAP":
        bmp = dib_to_bmp(blob)
        if bmp:
            return {"kind": "image", "data": bmp, "format": "BMP", "notes": []}
    if t == "RT_VERSION" and version_info:
        return {"kind": "text", "data": version_text(version_info), "format": "version info", "notes": []}
    if t == "RT_STRING":
        try:
            bid = int(res.get("name"))
        except (TypeError, ValueError):
            bid = None
        rows = string_table(blob, bid)
        return {"kind": "text", "data": "\n".join(f"{i:>6}  {s}" for i, s in rows), "format": "string table",
                "notes": []}
    fmt = image_format(blob)
    if fmt:
        return {"kind": "image", "data": blob, "format": fmt, "notes": []}
    text = decode_text(blob) if len(blob) <= 1 << 20 else None
    if text:
        notes = manifest_notes(text) if t == "RT_MANIFEST" or "<assembly" in text[:400] else []
        return {"kind": "text", "data": text, "format": "manifest" if t == "RT_MANIFEST" else "text", "notes": notes}
    return {"kind": "hex", "data": blob, "format": "", "notes": []}
