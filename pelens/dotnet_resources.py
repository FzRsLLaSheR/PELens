""".NET resources: the .resources format (ResourceReader) and analysis of embedded images.

Many .NET loaders (AgentTesla, Formbook, Remcos & co.) hide the encrypted payload in the pixels of a
Bitmap in the resources and rebuild it with GetPixel/LockBits. The PNG entropy does not help (a PNG is
always compressed), but the pixels do: a real image compresses well, an encrypted payload is pure noise.
"""
from __future__ import annotations

import struct
import zlib

from . import entropy

MAGIC = 0xBEEFCACE

# type codes of the ResourceWriter primitive types
_PRIMITIVE = {0: "null", 1: "string", 2: "bool", 3: "char", 4: "byte", 5: "sbyte", 6: "int16", 7: "uint16",
              8: "int32", 9: "uint32", 10: "int64", 11: "uint64", 12: "single", 13: "double", 14: "decimal",
              15: "DateTime", 16: "TimeSpan", 0x20: "byte[]", 0x21: "Stream"}

NOISE_ENTROPY = 7.5       # pixel entropy (bits/byte)
NOISE_RESIDUAL = 7.5      # entropy of the residuals (pixel minus its left neighbour): ~3-5 in a real image,
                          # even a noisy photo; ~8 if the pixels are encrypted data
MIN_PIXEL_BYTES = 16384   # below 16 KB of pixels (icons, logos) no judgement is made


def _read_7bit(data: bytes, off: int) -> tuple[int, int]:
    val = shift = 0
    for i in range(5):
        b = data[off + i]
        val |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return val, off + i + 1
    raise ValueError("bad 7-bit encoded int")


def _read_str(data: bytes, off: int, enc: str) -> tuple[str, int]:
    n, off = _read_7bit(data, off)
    if off + n > len(data):
        raise ValueError("string out of bounds")
    return data[off:off + n].decode(enc, "replace"), off + n


def parse_resource_set(data: bytes) -> list[dict] | None:
    """Elements of a .resources file: name, type, position and bytes of the value. None if it is not a .resources."""
    if len(data) < 28 or struct.unpack_from("<I", data, 0)[0] != MAGIC:
        return None
    try:
        _readers, skip = struct.unpack_from("<II", data, 4)
        off = 12 + skip
        version, n_res, n_types = struct.unpack_from("<III", data, off)
        off += 12
        if n_res > 100000 or n_types > 10000:
            return None
        types = []
        for _ in range(n_types):
            t, off = _read_str(data, off, "utf-8")
            types.append(t)
        # 8-byte alignment (the padding bytes are "PAD")
        off += (-off) % 8
        off += 4 * n_res                       # name hashes
        name_pos = struct.unpack_from(f"<{n_res}I", data, off)
        off += 4 * n_res
        data_section = struct.unpack_from("<I", data, off)[0]
        names_start = off + 4
        entries = []
        for p in name_pos:
            name, o = _read_str(data, names_start + p, "utf-16-le")
            entries.append({"name": name, "data_offset": data_section + struct.unpack_from("<I", data, o)[0]})
    except (struct.error, ValueError, IndexError):
        return None
    ends = sorted({e["data_offset"] for e in entries} | {len(data)})
    for e in entries:
        start = e["data_offset"]
        end = next((x for x in ends if x > start), len(data))
        raw = data[start:end]
        e.update(_decode_value(raw, types, version))
        e["value_offset"] = start + e.pop("_skip", 0)
    return entries


def _decode_value(raw: bytes, types: list[str], version: int) -> dict:
    """Type and useful bytes of the value. For serialized types (e.g. Bitmap) the bytes are the BinaryFormatter blob."""
    try:
        if version >= 2:
            code, o = _read_7bit(raw, 0)
            if code >= 0x40:
                idx = code - 0x40
                tname = types[idx] if idx < len(types) else f"user type #{idx}"
                return {"type": tname.split(",")[0], "value": raw[o:], "_skip": o}
            tname = _PRIMITIVE.get(code, f"type code {code}")
            if code in (0x20, 0x21):
                n = struct.unpack_from("<I", raw, o)[0]
                return {"type": tname, "value": raw[o + 4:o + 4 + n], "_skip": o + 4}
            if code == 1:
                s, _ = _read_str(raw, o, "utf-8")
                return {"type": tname, "value": s.encode("utf-8"), "_skip": o, "text": s[:200]}
            return {"type": tname, "value": raw[o:], "_skip": o}
        idx, o = _read_7bit(raw, 0)
        tname = types[idx] if idx < len(types) else "?"
        return {"type": tname.split(",")[0], "value": raw[o:], "_skip": o}
    except (struct.error, ValueError, IndexError):
        return {"type": "?", "value": raw, "_skip": 0}


# --- XOR-encrypted PE (known-plaintext attack on the DOS header) ---------------------------

# the first 0x3c bytes of the DOS header are almost always these (MSVC, csc/.NET, MinGW, Go, ...)
# MSVC DOS header (reference only: the search uses "MZ" and the reserved bytes, the same for every compiler)
DOS_HEADER = bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000"
                           "000000000000000000000000000000000000000000000000")
MAX_KEY = 32      # keys up to 32 bytes (a 16-character UTF-16 string too)
MAX_SKIP = 16     # header before the PE (e.g. a 4-byte length)


def find_xor_pe(stream: bytes, max_skip: int = MAX_SKIP, capacity: int | None = None,
                max_key: int = MAX_KEY) -> dict | None:
    """PE in clear or encrypted with a repeating-key XOR at the start of a stream.

    Known plaintext: "MZ" and the 32 reserved bytes 0x1C-0x3B of the DOS header, which are zero in practically
    every PE (any compiler). There the ciphertext is the key itself: if it is periodic and decrypting finds
    the "PE\\0\\0" signature at e_lfanew, there is an executable. Nothing else is decrypted.
    """
    for skip in range(0, max_skip + 1):
        c = stream[skip:skip + 0x40]
        if len(c) < 0x40:
            break
        for period in range(1, max_key + 1):
            key: list[int | None] = [None] * period
            ok = True
            for i in range(0x1C, 0x3C):
                k = key[i % period]
                if k is None:
                    key[i % period] = c[i]
                elif k != c[i]:
                    ok = False
                    break
            if not ok:
                continue
            for i, plain in ((0, 0x4D), (1, 0x5A)):
                k = c[i] ^ plain
                if key[i % period] is None:
                    key[i % period] = k
                elif key[i % period] != k:
                    ok = False
            if not ok or None in key:
                continue
            kb = bytes(key)
            head = stream[skip:skip + 0x1000]
            dec = bytes(b ^ kb[i % period] for i, b in enumerate(head))
            lfanew = struct.unpack_from("<I", dec, 0x3C)[0]
            if not (0x40 <= lfanew <= len(dec) - 4 and dec[lfanew:lfanew + 4] == b"PE\0\0"):
                continue
            if len(set(kb)) == 1:          # single-byte repeated key
                kb = kb[:1]
            out = {"offset": skip, "key": kb.hex(), "key_length": len(kb), "encrypted": any(kb)}
            if len(kb) % 2 == 0 and len(kb) >= 4 and not any(kb[1::2]) and all(32 <= b < 127 for b in kb[0::2]):
                out["key_text"] = kb[0::2].decode() + " (UTF-16)"
            elif all(32 <= b < 127 for b in kb) and len(kb) >= 4:
                out["key_text"] = kb.decode()
            if skip >= 4:
                ln = struct.unpack_from("<I", stream, skip - 4)[0]
                if 0x200 <= ln <= (capacity if capacity is not None else len(stream)):
                    out["length_header"] = ln
            return out
    return None


# pixel reading orders common in decoders: GetPixel(x, y) by rows or by columns, and the color
# bytes as R,G,B,A (Color.R/G/B/A) or B,G,R,A (BitConverter.GetBytes(color.ToArgb()))
_CHANNEL_ORDERS = {4: [("R,G,B,A", (0, 1, 2, 3)), ("B,G,R,A", (2, 1, 0, 3)), ("A,R,G,B", (3, 0, 1, 2)),
                       ("A,B,G,R", (3, 2, 1, 0)), ("R,G,B", (0, 1, 2)), ("B,G,R", (2, 1, 0))],
                   3: [("R,G,B", (0, 1, 2)), ("B,G,R", (2, 1, 0))]}


# position of R, G, B, A in the stored bytes: PNG = R,G,B,A; BMP = B,G,R,A
_STORAGE = {"PNG": (0, 1, 2, 3), "BMP": (2, 1, 0, 3)}


def _pixel_streams(pixels: bytes, w: int, h: int, bpp: int, bottom_up: bool, need: int, fmt: str = "PNG"):
    """The first `need` bytes of the possible streams a decoder derives from the pixels."""
    if bpp not in _CHANNEL_ORDERS or w <= 0 or h <= 0:
        return
    pos = _STORAGE.get(fmt, _STORAGE["PNG"])
    stride = len(pixels) // h if h else 0
    def px(x, y):
        yy = h - 1 - y if bottom_up else y
        return yy * stride + x * bpp
    n_px = need // 3 + 2
    for major in ("rows", "columns"):
        coords = [((i % w), (i // w)) if major == "rows" else ((i // h), (i % h)) for i in range(min(n_px, w * h))]
        for name, logical in _CHANNEL_ORDERS[bpp]:
            chans = [pos[c] for c in logical]
            out = bytearray()
            for x, y in coords:
                p = px(x, y)
                if p + bpp > len(pixels):
                    break
                out += bytes(pixels[p + c] for c in chans)
            yield f"{major}, {name}", bytes(out)


def find_pe_in_pixels(pixels: bytes, w: int, h: int, bpp: int, bottom_up: bool = False,
                      fmt: str = "PNG") -> dict | None:
    for layout, stream in _pixel_streams(pixels, w, h, bpp, bottom_up, 0x1000 + MAX_SKIP, fmt):
        hit = find_xor_pe(stream, capacity=len(pixels))
        if hit:
            hit["layout"] = layout
            return hit
    return None


# --- images --------------------------------------------------------------------------------------

_IMG_MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG"), (b"BM", "BMP"), (b"GIF87a", "GIF"), (b"GIF89a", "GIF"),
              (b"\xff\xd8\xff", "JPEG")]


def find_image(blob: bytes) -> tuple[int, str] | None:
    """Image inside a value (also inside the BinaryFormatter blob of a Bitmap)."""
    best = None
    for magic, fmt in _IMG_MAGIC:
        i = blob.find(magic, 0, 4096)
        if fmt == "BMP" and i >= 0:
            # "BM" is short: it must be confirmed by a plausible file size and pixel offset
            ok = False
            while i >= 0 and not ok:
                if i + 14 <= len(blob):
                    size, _r, pix = struct.unpack_from("<IIi", blob, i + 2)
                    ok = 54 <= pix < size <= len(blob) - i + 16
                if not ok:
                    i = blob.find(magic, i + 1, 4096)
        if i >= 0 and (best is None or i < best[0]):
            best = (i, fmt)
    return best


def _png(data: bytes) -> dict | None:
    off = 8
    idat = []
    w = h = depth = ctype = None
    while off + 8 <= len(data):
        n, typ = struct.unpack_from(">I4s", data, off)
        body = data[off + 8:off + 8 + n]
        if typ == b"IHDR" and len(body) >= 13:
            w, h, depth, ctype = struct.unpack_from(">IIBB", body)
        elif typ == b"IDAT":
            idat.append(body)
        elif typ == b"IEND":
            off += 12 + n
            break
        off += 12 + n
    if w is None or not idat:
        return None
    comp = b"".join(idat)
    try:
        raw = zlib.decompressobj().decompress(comp, 64 * 1024 * 1024)
    except zlib.error:
        return None
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype, 3)
    stride = (w * channels * depth + 7) // 8
    # pixels without the filter byte of each row
    rows = [raw[r * (stride + 1) + 1:(r + 1) * (stride + 1)] for r in range(min(h, len(raw) // (stride + 1)))]
    pixels = b"".join(rows)
    return {"format": "PNG", "width": w, "height": h, "bits": depth * channels, "size": off,
            "pixels": pixels, "compressed": len(comp)}


def _bmp(data: bytes) -> dict | None:
    if len(data) < 54:
        return None
    size, _r, pix = struct.unpack_from("<IIi", data, 2)
    w, h = struct.unpack_from("<ii", data, 18)
    bpp, compression = struct.unpack_from("<HI", data, 28)
    if compression not in (0, 3) or pix >= len(data):
        return None
    pixels = data[pix:min(size, len(data))]
    return {"format": "BMP", "width": w, "height": abs(h), "bits": bpp, "size": size, "pixels": pixels,
            "compressed": None, "bottom_up": h > 0}


def _residual_entropy(pixels: bytes, w: int, h: int, bpp: int, budget: int = 262144) -> float:
    """Entropy of the differences between each byte and the same channel of the pixel on the left, on sample rows."""
    if w < 2 or h < 1:
        return 0.0
    stride = len(pixels) // h
    row_len = w * bpp
    if stride < row_len:
        return 0.0
    n_rows = max(1, min(h, budget // max(1, row_len)))
    step = max(1, h // n_rows)
    out = bytearray()
    for y in range(0, h, step):
        r = pixels[y * stride:y * stride + row_len]
        out += bytes((r[i] - r[i - bpp]) & 0xFF for i in range(bpp, len(r)))
        if len(out) >= budget:
            break
    return entropy.shannon(bytes(out))


def analyze_image(blob: bytes) -> dict | None:
    found = find_image(blob)
    if not found:
        return None
    start, fmt = found
    data = blob[start:]
    info = _png(data) if fmt == "PNG" else _bmp(data) if fmt == "BMP" else None
    if info is None:
        return {"format": fmt, "offset_in_value": start}
    pixels = info.pop("pixels")
    sample = pixels[:4 * 1024 * 1024]
    ratio = len(zlib.compress(sample, 6)) / max(1, len(sample)) if sample else 0.0
    ent = entropy.shannon(sample)
    bpp_ = max(1, info["bits"] // 8)
    resid = _residual_entropy(pixels, info["width"], info["height"], bpp_)
    # payload in clear inside the pixels (RGB or BGR, or with alpha): look for the signatures of a PE
    head = sample[:1 << 20]
    pe_inside = b"This program cannot be run" in head or b"This program must be run" in head
    bpp = info["bits"] // 8 if info["bits"] % 8 == 0 else 0
    hidden = find_pe_in_pixels(pixels, info["width"], info["height"], bpp,
                               bottom_up=info["format"] == "BMP" and info.get("bottom_up", True), fmt=info["format"])
    if hidden:
        info["hidden_pe"] = hidden
    info.update({
        "offset_in_value": start, "pixel_bytes": len(pixels), "pixel_entropy": round(ent, 3),
        "compress_ratio": round(ratio, 3), "residual_entropy": round(resid, 3),
        "noise": len(pixels) >= MIN_PIXEL_BYTES and ent >= NOISE_ENTROPY and resid >= NOISE_RESIDUAL,
        "embedded_pe": pe_inside or bool(hidden),
    })
    return info


def analyze_resource(data: bytes, file_offset: int | None) -> dict:
    """Summary of a manifest resource: if it is a .resources it lists its elements and analyzes the images."""
    out = {"size": len(data), "entropy": round(entropy.shannon(data), 3), "embedded_pe": data[:2] == b"MZ",
           "magic": data[:4].hex(), "offset": file_offset, "entries": []}
    entries = parse_resource_set(data)
    if entries is None:
        hidden = find_xor_pe(data) if len(data) >= 0x400 else None
        if hidden:
            out["hidden_pe"] = hidden
            out["embedded_pe"] = True
        img = analyze_image(data)
        if img:
            out["image"] = img
        return out
    out["format"] = ".resources"
    for e in entries[:500]:
        val = e["value"]
        item = {"name": e["name"], "type": e["type"], "size": len(val), "entropy": round(entropy.shannon(val), 3),
                "offset": file_offset + e["value_offset"] if file_offset is not None else None,
                "embedded_pe": val[:2] == b"MZ"}
        if "text" in e:
            item["text"] = e["text"]
        hidden = find_xor_pe(val) if len(val) >= 0x400 else None
        if hidden:
            item["hidden_pe"] = hidden
            item["embedded_pe"] = True
        img = analyze_image(val)
        if img:
            if item["offset"] is not None:
                img["offset"] = item["offset"] + img["offset_in_value"]
            item["image"] = img
        out["entries"].append(item)
    return out
