"""Analysis of the IL code of .NET methods (without running it).

It looks for two things, generically:
- the string decryptor: a static method that takes integers (or an index) and returns a string or a
  generic type (the pattern of ConfuserEx, .NET Reactor, SmartAssembly and home-made crypters), called from
  many different places almost always with a constant as argument;
- XOR loops: an `xor` inside a loop that reads/writes bytes (ldelem.u1 / stelem.i1 / conv.u1) or the characters
  of a string.
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict

# operand size of one-byte opcodes (missing ones have no operand)
_OP1 = {0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x1F: 1, 0x20: 4, 0x21: 8, 0x22: 4, 0x23: 8,
        0x27: 4, 0x28: 4, 0x29: 4, 0x6F: 4, 0x70: 4, 0x71: 4, 0x72: 4, 0x73: 4, 0x74: 4, 0x75: 4, 0x79: 4,
        0x7B: 4, 0x7C: 4, 0x7D: 4, 0x7E: 4, 0x7F: 4, 0x80: 4, 0x81: 4, 0x8C: 4, 0x8D: 4, 0x8F: 4, 0xA3: 4,
        0xA4: 4, 0xA5: 4, 0xC2: 4, 0xC6: 4, 0xD0: 4, 0xDD: 4, 0xDE: 1}
_OP1.update({op: 1 for op in range(0x2B, 0x38)})   # short branches
_OP1.update({op: 4 for op in range(0x38, 0x45)})   # long branches
# two-byte opcodes (0xFE xx)
_OP2 = {0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2, 0x12: 1, 0x15: 4, 0x16: 4,
        0x19: 1, 0x1C: 4}

LDC = set(range(0x15, 0x1F)) | {0x1F, 0x20, 0x21}          # ldc.i4.m1 … ldc.i4.8, ldc.i4.s, ldc.i4, ldc.i8
BYTE_OPS = {0x91, 0x9C, 0xD2, 0x90, 0xB3}                     # ldelem.u1, stelem.i1, conv.u1, ldelem.i1, conv.ovf.u1
CALLS = {0x28, 0x6F, 0x73}

MIN_CALLS = 20           # calls needed for a method to be a string decryptor…
MIN_CALLERS = 2          # …from at least 2 different methods
MIN_CONST_RATIO = 0.7    # share of calls with a constant argument


def iter_il(code: bytes):
    """(offset, opcode, integer operand or None); branches have the target offset as operand."""
    i, n = 0, len(code)
    while i < n:
        start = i
        op = code[i]
        i += 1
        if op == 0xFE and i < n:
            op = 0xFE00 | code[i]
            i += 1
            size = _OP2.get(op & 0xFF, 0)
        elif op == 0x45:                       # switch: n, then n targets
            if i + 4 > n:
                return
            cnt = struct.unpack_from("<I", code, i)[0]
            i += 4 + 4 * min(cnt, 10000)
            yield start, op, None
            continue
        else:
            size = _OP1.get(op, 0)
        if i + size > n:
            return
        val = None
        if size == 1:
            val = struct.unpack_from("<b", code, i)[0] if (0x2B <= op <= 0x37 or op in (0x1F, 0xDE)) else code[i]
        elif size == 2:
            val = struct.unpack_from("<H", code, i)[0]
        elif size == 4:
            val = struct.unpack_from("<i" if (0x38 <= op <= 0x44 or op in (0x20, 0xDD)) else "<I", code, i)[0]
        elif size == 8:
            val = struct.unpack_from("<q", code, i)[0]
        i += size
        if 0x2B <= op <= 0x44 or op in (0xDD, 0xDE):
            val = i + val                       # absolute target
        yield start, op, val


def method_body(data: bytes, off: int) -> bytes | None:
    if off is None or off >= len(data):
        return None
    b = data[off]
    if b & 3 == 2:                              # tiny
        return data[off + 1:off + 1 + (b >> 2)]
    if b & 3 == 3 and off + 12 <= len(data):    # fat
        flags = struct.unpack_from("<H", data, off)[0]
        hdr = (flags >> 12) * 4
        size = struct.unpack_from("<I", data, off + 4)[0]
        if hdr < 12 or size > 16 * 1024 * 1024:
            return None
        return data[off + hdr:off + hdr + size]
    return None


# elementary types in method signatures
_INT_TYPES = {0x08, 0x09, 0x0A, 0x0B, 0x06, 0x07}    # i4 u4 i8 u8 i2 u2
_RET_OK = {0x0E: "string", 0x1E: "generic T", 0x13: "generic T"}


def _sig(blob: bytes) -> tuple[int | None, list[int]] | None:
    """(return type, parameter types) for simple signatures; None if the signature is more complex."""
    try:
        i = 0
        conv = blob[i]
        i += 1
        if conv & 0x10:                          # generic: number of generic parameters
            i += 1
        npar = blob[i]
        i += 1
        if npar > 8:
            return None
        ret = blob[i]
        i += 1
        if ret in (0x15, 0x1D, 0x11, 0x12, 0x14):   # composite types: not needed here
            ret = None
        elif ret in (0x13, 0x1E):
            i += 1
        params = []
        for _ in range(npar):
            t = blob[i]
            i += 1
            if t in (0x11, 0x12, 0x15, 0x1D, 0x14, 0x0F, 0x10, 0x13, 0x1E):
                return ret, params + [-1] * (npar - len(params))
            params.append(t)
        return ret, params
    except IndexError:
        return None


def analyze(pe, data: bytes, method_names: list[str], type_of: list[str], memberrefs: list[str]) -> dict:
    """method_names / type_of: for each MethodDef (0-based index) the name and the type that contains it."""
    md = getattr(pe.net.mdtables, "MethodDef", None)
    if not md:
        return {}
    ms = getattr(pe.net.mdtables, "MethodSpec", None)
    spec_target = {}
    for i, r in enumerate(ms or [], 1):
        try:
            m = r.Method
            if m is not None and m.table is not None and m.table.name == "MethodDef":
                spec_target[0x2B000000 | i] = 0x06000000 | m.row_index
        except Exception:
            pass

    callers: dict[int, set] = defaultdict(set)     # token of the called method -> calling methods
    calls: Counter = Counter()
    const_calls: Counter = Counter()
    xor_loops = []
    n_bodies = 0
    for idx, row in enumerate(md, 1):
        rva = getattr(row, "Rva", 0)
        if not rva:
            continue
        try:
            off = pe.get_offset_from_rva(rva)
        except Exception:
            continue
        code = method_body(data, off)
        if not code:
            continue
        n_bodies += 1
        prev = []
        has_xor = has_back = byte_ops = chars = False
        for at, op, val in iter_il(code):
            if op == 0x61:
                has_xor = True
            elif op in BYTE_OPS:
                byte_ops = True
            elif (0x2B <= op <= 0x44) and val is not None and val <= at:
                has_back = True
            elif op in CALLS and val is not None:
                tok = spec_target.get(val, val)
                callers[tok].add(idx)
                calls[tok] += 1
                if prev and prev[-1] in LDC:
                    const_calls[tok] += 1
                if (val >> 24) == 0x0A and 0 < (val & 0xFFFFFF) <= len(memberrefs):
                    name = memberrefs[(val & 0xFFFFFF) - 1]
                    if name.endswith(("String::get_Chars", "String::ToCharArray", "Char::op_Implicit")):
                        chars = True
            prev = (prev + [op])[-2:]
        if has_xor and has_back and (byte_ops or chars):
            xor_loops.append(idx)

    # string decryptors
    decryptors = []
    for tok, who in callers.items():
        if (tok >> 24) != 0x06 or calls[tok] < MIN_CALLS or len(who) < MIN_CALLERS:
            continue
        idx = tok & 0xFFFFFF
        if not 0 < idx <= len(md):
            continue
        row = md[idx - 1]
        try:
            static = bool(row.Flags.mdStatic)
            sig = _sig(bytes(getattr(row.Signature, "value", b"") or b""))
        except Exception:
            continue
        if not static or not sig:
            continue
        ret, params = sig
        if ret not in _RET_OK or not params or not all(p in _INT_TYPES for p in params):
            continue
        ratio = const_calls[tok] / max(1, calls[tok])
        if ratio < MIN_CONST_RATIO:
            continue
        decryptors.append({
            "method": f"{type_of[idx - 1]}::{method_names[idx - 1]}" if type_of[idx - 1] else method_names[idx - 1],
            "token": f"0x{tok:08x}", "returns": _RET_OK[ret], "params": len(params),
            "calls": calls[tok], "callers": len(who), "constant_args": round(ratio, 2),
            "xor_loop": idx in xor_loops,
        })
    decryptors.sort(key=lambda d: -d["calls"])
    loops = [{"method": f"{type_of[i - 1]}::{method_names[i - 1]}" if type_of[i - 1] else method_names[i - 1],
              "token": f"0x{0x06000000 | i:08x}", "callers": len(callers.get(0x06000000 | i, ()))}
             for i in xor_loops]
    loops.sort(key=lambda x: -x["callers"])
    return {"method_bodies": n_bodies, "string_decryptors": decryptors[:10], "xor_loops": loops[:50]}
