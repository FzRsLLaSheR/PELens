"""Code analysis with Capstone, in a single pass over the executable sections.

- stack strings: sequences of `mov [reg+off], imm` that build a string on the stack;
- RC4: the key scheduling (KSA) can only be recognized from the code, because RC4 has no constants;
- XOR loops: "home-made" decryption routines (typical of the encrypted strings of infostealers).
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

import capstone
import pefile

from .loader_traits import LoaderScanner, LoaderTraits
from .strings import FoundString, classify, is_noise

MAX_SCAN = 32 * 1024 * 1024   # at most 32 MB of code
MIN_LEN = 5

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


@dataclass
class CodeScanResult:
    stack_strings: list[FoundString] = field(default_factory=list)
    rc4_candidates: list[int] = field(default_factory=list)   # VAs of the possible KSAs
    rc4_variants: dict[int, dict] = field(default_factory=dict)  # VA -> {ksa_xor, drop, extra_xor}
    crypto_instructions: dict[str, tuple[int, int]] = field(default_factory=dict)  # mnemonic -> (first VA, count)
    xor_loops: list[dict] = field(default_factory=list)   # {va, multibyte_key, rolling, function, fan_in, ptr_sites}
    enc_blobs: list[int] = field(default_factory=list)    # end VAs of mov sequences with non-printable data
    # functions often called with 2+ pointers to data: {target: (calls, calls with 2+ pointers)}
    call_patterns: dict[int, tuple[int, int]] = field(default_factory=dict)
    # functions called right after writing encrypted constants to the stack: {target: (calls, of which after a blob)}
    blob_calls: dict[int, tuple[int, int]] = field(default_factory=dict)
    loader: LoaderTraits = field(default_factory=LoaderTraits)   # loader techniques (PEB, exports, hashing...)
    # references from code to high-entropy areas (probably encrypted payloads)
    blob_refs: list[tuple[int, int]] = field(default_factory=list)      # (instruction VA, referenced VA)
    blob_ref_calls: dict[int, int] = field(default_factory=dict)        # function -> calls that pass it the blob
    arch: str = ""


# --- Stack strings ----------------------------------------------------------------------------

_MOV_IMM_RE = re.compile(
    r"^(byte|word|dword|qword) ptr \[([a-z0-9]+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\], (-?0x[0-9a-f]+|-?\d+)$")
_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
# constant loaded into a register (movabs rax, imm64 / mov eax, imm32) and then written to the stack
_REG_IMM_RE = re.compile(r"^([a-z0-9]+), (-?0x[0-9a-f]+|-?\d+)$")
_MOV_REG_RE = re.compile(
    r"^(dword|qword) ptr \[([a-z0-9]+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\], ([a-z0-9]+)$")
_GAP = 3        # "foreign" instructions tolerated inside a sequence
_MIN_MOVS = 3   # below this number of movs we do not consider it a stack string


def _strings_in_buffer(buf: bytes) -> list[tuple[str, str]]:
    out = [(m.group().decode("ascii"), "ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_LEN, buf)]
    out += [(m.group().decode("utf-16le"), "utf-16le")
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN, buf)]
    return out


class _FakeMatch:
    def __init__(self, groups):
        self._g = groups

    def groups(self):
        return self._g


class _StackStrings:
    def __init__(self, sec_name: str):
        self.found: list[FoundString] = []
        self.seen: set[str] = set()
        self.sec_name = sec_name
        self.enc_blobs: list[int] = []
        self.image_range = (0, 0)
        self._reset()

    def _reset(self):
        self.writes: dict[str, dict[int, int]] = {}
        self.start, self.n, self.gap, self.last = 0, 0, 0, 0
        self.has_pointer = False
        self.reg_consts: dict[str, int] = {}

    def _flush(self):
        # non-printable data written with immediate movs (>= 8 bytes): candidate "encrypted strings on the stack"
        if self.n >= 2 and not self.has_pointer:
            raw = [b for slot in self.writes.values() for b in slot.values()]
            nz = [b for b in raw if b]
            if len(raw) >= 8 and nz and sum(b in _PRINTABLE for b in nz) / len(nz) < 0.7:
                self.enc_blobs.append(self.last)
        if self.n >= _MIN_MOVS:
            for buf_map in self.writes.values():
                lo, hi = min(buf_map), max(buf_map)
                if hi - lo > 4096:
                    continue
                buf = bytes(buf_map.get(i, 0) for i in range(lo, hi + 1))
                nonzero = sum(1 for b in buf if b)
                for value, enc in _strings_in_buffer(buf):
                    tags = classify(value)
                    if value in self.seen or (not tags and is_noise(value)):
                        continue
                    # numeric constants (e.g. floats) give short printable runs among random bytes
                    if len(value) * (2 if enc == "utf-16le" else 1) < 0.6 * nonzero:
                        continue
                    self.seen.add(value)
                    self.found.append(FoundString(value, "stack", enc, va=self.start, section=self.sec_name,
                                                  tags=tags))
        self._reset()

    def feed(self, addr: int, mnem: str, ops: str):
        if mnem in ("mov", "movabs"):
            rm = _REG_IMM_RE.match(ops)
            if rm and not ops.startswith(("byte", "word", "dword", "qword")):
                self.reg_consts[rm.group(1)] = int(rm.group(2), 0)   # e.g. movabs rax, 0xafca1657f8205897
                if self.n:
                    self.gap += 1
                return
        m = _MOV_IMM_RE.match(ops) if mnem == "mov" else None
        if m is None and mnem == "mov":
            mr = _MOV_REG_RE.match(ops)
            if mr and mr.group(5) in self.reg_consts:
                # mov qword ptr [rsp + 0x20], rax  with rax = constant: same as an immediate mov
                m = _FakeMatch(mr.groups()[:4] + (hex(self.reg_consts[mr.group(5)]),))
        if m:
            width, reg, sign, disp, imm = m.groups()
            off = int(disp, 0) if disp else 0
            off = -off if sign == "-" else off
            size = _SIZES[width]
            val = int(imm, 0) & ((1 << (8 * size)) - 1)
            data = val.to_bytes(size, "little")
            # a "useful" mov contains at least one printable character or the terminator
            # (4/8-byte movs are always kept: they may be encrypted data)
            if any(b in _PRINTABLE for b in data) or val == 0 or size >= 4:
                if self.n == 0:
                    self.start = addr
                if size >= 4 and self.image_range[0] <= val < self.image_range[1]:
                    self.has_pointer = True   # pointer into the image: a call argument, not encrypted data
                slot = self.writes.setdefault(reg, {})
                for i, b in enumerate(data):
                    slot[off + i] = b
                self.n += 1
                self.gap = 0
                self.last = addr
                return
        if mnem in ("call", "ret", "jmp"):
            self.reg_consts = {}
        if self.n:
            self.gap += 1
            if self.gap > _GAP or mnem in ("call", "ret", "jmp"):
                consts = self.reg_consts
                self._flush()
                self.reg_consts = consts

    def finish(self):
        self._flush()


# --- RC4 ----------------------------------------------------------------------------------
#
# RC4 has no constants: it is recognized by the shape of the code. Its core is the swap S[i] <-> S[j]
# with indexes truncated to a byte, present both in the key scheduling (KSA) and in the keystream
# generation (PRGA):
#     j = (j + S[i] + key[...]) & 0xFF;  t = S[i]; S[i] = S[j]; S[j] = t
# We look for short loops that, in one iteration, read at least 2 bytes from memory and write back
# at least 2 of those values (the swap), truncating an index to 8 bits ("swap loop").
# Two nearby swap loops = RC4 (KSA + PRGA).
# As an alternative confirmation: an initialization loop up to 256 followed by a swap loop.

_BYTE_LOAD_RE = re.compile(r"^[a-z0-9]+, byte ptr \[")
_BYTE_STORE_RE = re.compile(r"^byte ptr \[[^\]]+\], (?:[a-d]l|[sd]il|[sb]pl|r\d+b)$")
_TRUNC_RE = re.compile(r"^[a-z0-9]+, (?:[a-d]l|[sd]il|[sb]pl|r\d+b)$")
_CMP_256_RE = re.compile(r"^(?:[a-z0-9]+|dword ptr \[[^\]]+\]), (?:0x100|0xff)$")  # counter in memory too (-O0)
_REG_RE = re.compile(r"^([a-z0-9]+)(?:, (.*))?$")
_RC4_DISTANCE = 0x200    # maximum distance between the two loops
_RC4_GROUP = 0x400       # maximum extent of an RC4 instance (KSA + drop + PRGA; longer without optimizations)
_MAX_LOOP = 0x140        # maximum size of a loop body (bytes; without optimizations loops are long)
_MAX_LOOP_OPT = 0xa0     # beyond this size the signs of unoptimized code are required


_FAMILIES = {}
for _fam, _names in {
    "a": "al ah ax eax rax", "b": "bl bh bx ebx rbx", "c": "cl ch cx ecx rcx", "d": "dl dh dx edx rdx",
    "si": "sil si esi rsi", "di": "dil di edi rdi", "bp": "bpl bp ebp rbp", "sp": "spl sp esp rsp",
}.items():
    for _n in _names.split():
        _FAMILIES[_n] = _fam
for _i in range(8, 16):
    for _n in (f"r{_i}b", f"r{_i}w", f"r{_i}d", f"r{_i}"):
        _FAMILIES[_n] = f"r{_i}"
_ALL_FAMILIES = set(_FAMILIES.values())


def _family(reg: str) -> str:
    """al, ax, eax, rax -> 'a';  r8b, r8d, r8 -> 'r8'."""
    return _FAMILIES.get(reg.strip(), reg.strip())


_IMM_RE = re.compile(r", (0x[0-9a-f]+|\d+)$")
_REG_ONLY_RE = re.compile(r"^[a-z0-9]+$")
_VEC_LOAD_RE = re.compile(r"^(xmm\d+), xmmword ptr \[rip ([+-]) (0x[0-9a-f]+)\]$")


class _RC4:
    def __init__(self, read=None):
        self.candidates: list[int] = []
        self.recent: list[tuple[int, int, str, str]] = []   # last instructions (addr, size, mnemonic, operands)
        self.swap_loops: list[int] = []
        self.init_loops: list[int] = []
        self.loops_info: list[dict] = []    # for each swap loop: {start, end, xors, count}
        self.ksa_xor: dict[int, int] = {}   # start of the first swap loop -> constant of the init S[i] = i ^ c
        self.read = read                    # callback (va, n) -> bytes, to read vector constants
        self._loop_len = 0
        self._closing = ""
        self._pending_cmp: int | None = None
        self.vec_init: list[int] = []

    def _is_swap_loop(self, start: int) -> bool:
        loads = swap_stores = trunc = 0
        loaded: set[str] = set()   # registers holding a byte read from memory
        for addr, _sz, mnem, ops in self.recent:
            if addr < start:
                continue
            m = _REG_RE.match(ops)
            dst, src = (m.group(1), m.group(2) or "") if m else ("", "")
            if mnem in ("movzx", "mov") and _BYTE_LOAD_RE.match(ops):
                loads += 1
                loaded.add(_family(dst))
            elif mnem == "mov" and _BYTE_STORE_RE.match(ops):
                if _family(ops.rsplit(", ", 1)[1]) in loaded:
                    swap_stores += 1
            elif mnem == "movzx" and _TRUNC_RE.match(ops):
                trunc += 1
                if _family(src) in loaded:
                    loaded.add(_family(dst))
                else:
                    loaded.discard(_family(dst))
            elif mnem == "mov" and src and _family(src) in _ALL_FAMILIES:
                (loaded.add if _family(src) in loaded else loaded.discard)(_family(dst))
            elif mnem in ("mov", "lea", "xor") and dst:
                if not (mnem == "xor" and src != dst):
                    loaded.discard(_family(dst))
            elif mnem == "and" and ops.endswith(", 0xff"):
                trunc += 1
        # RC4 loops do not call functions (rules out, for example, parsing loops with callbacks)
        if any(m == "call" for a, _z, m, o in self.recent if a >= start):
            return False
        long_loop = self._loop_len > _MAX_LOOP_OPT or self._closing == "jmp"
        if long_loop:
            # unoptimized code: the index can be a byte variable on the stack (add byte ptr [..], 1)
            # instead of "movzx eax, al"; an explicit sign of modulo-256 arithmetic is still required
            mod256 = any((m == "and" and o.endswith(", 0xff")) or (m == "cmp" and _CMP_256_RE.match(o))
                         or (m in ("add", "inc", "sub") and o.startswith("byte ptr"))
                         or (m == "movzx" and _TRUNC_RE.match(o))
                         for a, _z, m, o in self.recent if a >= start)
            if not (loads >= 2 and mod256):
                return False
        elif not (loads >= 2 and trunc >= 1):
            return False
        # long loops only with the unoptimized pattern (t = S[i]; S[i] = S[j]; S[j] = t: 3 writes)
        return swap_stores >= (3 if self._loop_len > _MAX_LOOP_OPT else 2)

    def _add(self, addr: int):
        if not self.candidates or addr - self.candidates[-1] > _RC4_DISTANCE:
            self.candidates.append(addr)

    def _loop_features(self, start: int, end: int) -> dict:
        """Number of xors in the body and number of iterations if constant (for the "drop" of the variants)."""
        body = [(a, m, o) for a, _z, m, o in self.recent if start <= a <= end]
        closing = next((m for a, m, o in body if a == end), "")
        xors = sum(1 for _a, m, o in body if m == "xor" and len(set(o.split(", "))) == 2
                   and not o.endswith(", 0xff"))
        count = None
        for _a, m, o in body:
            if m == "cmp":
                mm = _IMM_RE.search(o)
                if mm and int(mm.group(1), 0) not in (0x100, 0xff):
                    count = int(mm.group(1), 0)
                    if closing in ("jle", "jbe", "jng", "jna"):
                        count += 1      # "i <= N" = N + 1 iterations
            elif (m == "sub" and o.endswith(", 1")) or m == "dec":
                reg = _family(o.split(",")[0])
                # backward counter: "mov reg, N" shortly before the loop (also through mov reg, reg copies)
                consts: dict[str, int] = {}
                for a, _z, m2, o2 in self.recent:
                    if a >= start or start - a > 0x30 or m2 != "mov":
                        continue
                    d2, _, s2 = o2.partition(", ")
                    if _IMM_RE.search(o2) and _REG_ONLY_RE.match(d2):
                        consts[_family(d2)] = int(s2, 0)
                    elif _REG_ONLY_RE.match(d2) and _REG_ONLY_RE.match(s2) and _family(s2) in consts:
                        consts[_family(d2)] = consts[_family(s2)]
                if consts.get(reg, 0) > 1:
                    count = consts[reg]
        ksa256 = any(m == "cmp" and _CMP_256_RE.match(o)
                     and (o.endswith("0x100") or body[n + 1][1] not in ("je", "jne", "jz", "jnz"))
                     for n, (_a, m, o) in enumerate(body[:-1]))
        if closing == "jmp":
            # loop with the check at the top: "cmp i, N / jg end" = N + 1 iterations
            for n, (_a, m, o) in enumerate(body[:-1]):
                mm = _IMM_RE.search(o) if m == "cmp" else None
                if mm and int(mm.group(1), 0) not in (0x100, 0xff):
                    nxt = body[n + 1][1]
                    count = int(mm.group(1), 0) + (1 if nxt in ("jg", "ja", "jnle", "jnbe") else 0)
                    break
        # evidence of S initialization shortly before: a loop counting up to 256 or vector code
        has_init = ksa256 or any(0 < start - a <= 0x120 for a in self.init_loops + self.vec_init)
        return {"start": start, "end": end, "xors": xors, "count": count, "ksa256": ksa256,
                "has_init": has_init, "init_xor": self._init_xor_const(start)}

    def _init_xor_const(self, first_swap: int) -> int | None:
        """Looks before the KSA for the modified initialization S[i] = i ^ c (scalar or vector)."""
        regs_const: dict[str, int] = {}
        found = None
        xor_imms: list[tuple[int, int]] = []
        cmps: list[int] = []
        for a, z, m, o in self.recent:
            if a >= first_swap or first_swap - a > 0x180:
                continue
            mm = _VEC_LOAD_RE.match(o) if m in ("movdqu", "movdqa", "movaps", "movups") else None
            if mm and self.read:
                disp = int(mm.group(3), 16)
                blob = self.read(a + z + (disp if mm.group(2) == "+" else -disp), 16)
                if blob and len(set(blob)) == 1 and blob[0] not in (0, 0xff):
                    regs_const[mm.group(1)] = blob[0]
            elif m in ("pxor", "xorps", "vpxor"):
                for r in o.split(", ")[1:]:
                    if r in regs_const:
                        found = regs_const[r]
            elif m == "xor":
                mm2 = _IMM_RE.search(o)
                if mm2 and not o.startswith("byte ptr"):
                    c = int(mm2.group(1), 0)
                    if c > 0xff and (c | 0xff) in (0xffffffff, 0xffffffffffffffff):
                        c &= 0xff                   # xor edx, 0xffffffe5 = xor with 0xE5 sign-extended
                    if 0 < c < 0xff:
                        xor_imms.append((c, a))     # scalar version: xor reg, c ...
            elif m == "cmp" and _CMP_256_RE.match(o):
                cmps.append(a)
        # ... inside the initialization loop: near (before or after) the comparison with 256
        for c, a in xor_imms:
            if any(abs(a - ca) <= 0x30 for ca in cmps):
                found = c
        return found

    def feed(self, addr: int, mnem: str, ops: str, size: int = 0):
        self.recent.append((addr, size, mnem, ops))
        if len(self.recent) > 192:
            del self.recent[:32]
        if self._pending_cmp is not None:
            # "cmp x, 0xff / je" is a sentinel value (0xff fits in a byte), not the bound of a 256 loop
            if mnem not in ("je", "jne", "jz", "jnz"):
                self.init_loops.append(self._pending_cmp)
                self.init_loops = self.init_loops[-8:]
            self._pending_cmp = None
        if mnem == "cmp" and _CMP_256_RE.match(ops):
            if ops.endswith("0x100"):
                self.init_loops.append(addr)
                self.init_loops = self.init_loops[-8:]
            else:
                self._pending_cmp = addr
        elif mnem in ("paddb", "paddd", "packuswb"):
            self.vec_init.append(addr)          # S initialization vectorized by the compiler
            self.vec_init = self.vec_init[-8:]
        # short backward jump = end of a loop (jmp too: MSVC /Od closes for loops this way)
        if mnem.startswith("j") and ops.startswith("0x"):
            target = int(ops, 16)
            self._loop_len = addr - target
            self._closing = mnem
            if 0 < addr - target <= _MAX_LOOP and self._is_swap_loop(target):
                self.loops_info.append(self._loop_features(target, addr))
                near_swap = [a for a in self.swap_loops if 0 < target - a <= _RC4_DISTANCE]
                near_init = [a for a in self.init_loops if 0 < target - a <= 0x80]
                if near_swap:
                    self._add(near_swap[-1])
                elif near_init:
                    self._add(target)
                self.swap_loops.append(target)
                self.swap_loops = self.swap_loops[-8:]


# --- XOR loops ---------------------------------------------------------------------------------
#
# A "home-made" XOR is a short loop that combines bytes with XOR (not `xor eax, eax`,
# which zeroes a register) and writes the result back to memory:
#     for (i = 0; i < len; i++) out[i] = in[i] ^ key[i % keylen];
# If the loop reads at least two bytes from memory (data + key) the key is multi-byte.

_REG8 = r"(?:[a-d]l|[a-d]h|[sd]il|[sb]pl|r\d+b)"
_XOR_BYTE_RE = re.compile(rf"^(?:byte ptr \[[^\]]+\]|{_REG8}), (?:byte ptr \[[^\]]+\]|{_REG8}|0x[0-9a-f]+|\d+)$")
_BYTE_MEM_READ_RE = re.compile(r"byte ptr \[")
_MAX_XOR_LOOP = 0x100


class _XorLoops:
    """XOR loops. The XOR can be between bytes (`xor al, byte ptr [..]`) or between full registers that
    hold bytes just read from memory (`movzx eax, byte ptr [..]; ...; xor eax, ecx`), as code compiled
    without optimizations does (e.g. MSVC in debug)."""

    def __init__(self):
        self.loops: list[dict] = []
        self.recent: list[tuple[int, str, str]] = []

    def feed(self, addr: int, mnem: str, ops: str):
        self.recent.append((addr, mnem, ops))
        if len(self.recent) > 96:
            del self.recent[:32]
        # end of a loop = short backward jump. "jmp" too: MSVC without optimizations puts
        # the check at the top of the loop and goes back with an unconditional jump.
        if not (mnem.startswith("j") and ops.startswith("0x")):
            return
        target = int(ops, 16)
        if not 0 < addr - target <= _MAX_XOR_LOOP:
            return
        xor_ok = store = rolling = False
        reads = mov_stores = 0
        loaded: set[str] = set()   # registers holding a byte read from memory
        xored: set[str] = set()    # registers holding the result of an xor
        for a, m, o in self.recent:
            if a < target:
                continue
            parts = o.split(", ", 1)
            dst, src = (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "")
            if m == "add" and _REG_ONLY_RE.match(dst) and _REG_ONLY_RE.match(src) \
                    and _family(src) in xored and _family(dst) != _family(src):
                rolling = True            # state += decrypted byte (XOR with variable state)
            if m == "xor" and dst != src:
                if _REG_ONLY_RE.match(dst):
                    xored.add(_family(dst))
                if _XOR_BYTE_RE.match(o):
                    xor_ok = True
                    if dst.startswith("byte ptr"):
                        store = True          # xor directly in memory
                    if src.startswith("byte ptr"):
                        reads += 1
                elif _REG_ONLY_RE.match(dst) and _REG_ONLY_RE.match(src) and \
                        (_family(dst) in loaded or _family(src) in loaded):
                    xor_ok = True
                    loaded.add(_family(dst))
            elif m in ("mov", "movzx", "movsx") and _BYTE_MEM_READ_RE.search(o):
                if dst.startswith("byte ptr"):
                    store = True
                    # RC4-style swap: a byte just read and not touched by the xor is written back
                    if _REG_ONLY_RE.match(src) and _family(src) in loaded and _family(src) not in xored:
                        mov_stores += 1
                else:
                    reads += 1
                    loaded.add(_family(dst))
            elif m == "mov" and _REG_ONLY_RE.match(dst):
                if _REG_ONLY_RE.match(src) and _family(src) in loaded:
                    loaded.add(_family(dst))
                else:
                    loaded.discard(_family(dst))
            elif m in ("lea", "movzx", "movsx", "pop") and _REG_ONLY_RE.match(dst):
                if not (m in ("movzx", "movsx") and _family(src) in loaded):
                    loaded.discard(_family(dst))
        # XOR + swap of two bytes = RC4 PRGA, already recognized separately (writes of xor results,
        # even more than one as in multi-pass decryptors, do not count as a swap)
        if xor_ok and store and mov_stores < 2:
            self.loops.append({"va": target, "multibyte_key": reads >= 2, "rolling": rolling,
                               "conditional": mnem != "jmp"})


# --- Call arguments ----------------------------------------------------------------------------
#
# A string decryptor is called passing each time pointers to data in the file
# (e.g. Vidar: push length / pop reg / push key / push data / call decrypt).
# For each call we count how many immediates, in the instructions before it, point to data sections.

_IMM_SRC_RE = re.compile(r", (0x[0-9a-f]+)$")
_RIP_RE = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+)\]")
_ARG_WINDOW = 8


def _data_pointer(addr: int, size: int, mnem: str, ops: str, in_data) -> bool:
    if mnem == "push" and ops.startswith("0x"):
        return in_data(int(ops, 16))
    if mnem == "mov":
        m = _IMM_SRC_RE.search(ops)
        return bool(m) and in_data(int(m.group(1), 16))
    if mnem == "lea":
        m = _RIP_RE.search(ops)
        if m:
            disp = int(m.group(2), 16)
            return in_data(addr + size + (disp if m.group(1) == "+" else -disp))
    return False


# --- Hardware crypto instructions --------------------------------------------------------------
# AES-NI and SHA extensions: if the program uses them, it implements (or includes) AES / SHA.

CRYPTO_MNEMONICS = {
    "aesenc": "AES", "aesenclast": "AES", "aesdec": "AES", "aesdeclast": "AES", "aeskeygenassist": "AES",
    "aesimc": "AES", "vaesenc": "AES", "vaesenclast": "AES", "vaesdec": "AES", "vaesdeclast": "AES",
    "sha1rnds4": "SHA-1", "sha1nexte": "SHA-1", "sha1msg1": "SHA-1", "sha1msg2": "SHA-1",
    "sha256rnds2": "SHA-256", "sha256msg1": "SHA-256", "sha256msg2": "SHA-256",
}


# --- Single pass -------------------------------------------------------------------------------

_HEX_RE = re.compile(r"0x[0-9a-f]{5,16}")


def _referenced(addr: int, size: int, ops: str) -> list[int]:
    """Absolute addresses an instruction refers to (immediates, [abs], [rip + d])."""
    out = []
    m = _RIP_RE.search(ops)
    if m:
        d = int(m.group(2), 16)
        out.append(addr + size + (d if m.group(1) == "+" else -d))
    else:
        out.extend(int(h, 16) for h in _HEX_RE.findall(ops))
    return out


def scan(pe: pefile.PE, hot_ranges: list[tuple[int, int]] | None = None) -> CodeScanResult:
    """hot_ranges: high-entropy VA ranges (encrypted payloads) whose references in the code are searched for."""
    hot = hot_ranges or []
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        mode, arch = capstone.CS_MODE_32, "x86"
    elif machine == 0x8664:
        mode, arch = capstone.CS_MODE_64, "x64"
    else:
        return CodeScanResult(arch="unsupported")
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.skipdata = True

    result = CodeScanResult(arch=arch)
    base, budget = pe.OPTIONAL_HEADER.ImageBase, MAX_SCAN
    seen_strings: set[str] = set()

    def read_va(va: int, n: int) -> bytes | None:
        try:
            return pe.get_data(va - base, n)
        except Exception:
            return None

    last_blob_ref = -10**9
    blob_ref_calls: Counter[int] = Counter()
    ld = LoaderScanner(x64=(arch == "x64"), export_dir_disp=0x88 if arch == "x64" else 0x78)
    calls: Counter[int] = Counter()
    ptr_calls: Counter[int] = Counter()   # calls with at least 2 pointers to data among the arguments
    ptr1_calls: Counter[int] = Counter()  # calls with at least 1 pointer to data
    blob_calls: Counter[int] = Counter()  # calls preceded by encrypted constants written to the stack
    data_ranges = [(base + sc.VirtualAddress, base + sc.VirtualAddress + max(sc.Misc_VirtualSize, sc.SizeOfRawData))
                   for sc in pe.sections if not sc.Characteristics & 0x20000000 and sc.SizeOfRawData]

    def in_data(va: int) -> bool:
        return any(lo <= va < hi for lo, hi in data_ranges)

    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000 or budget <= 0:  # executable sections only
            continue
        code = sec.get_data()[:budget]
        budget -= len(code)
        name = sec.Name.rstrip(b"\x00").decode("latin-1")
        ss, rc4, xl = _StackStrings(name), _RC4(read=read_va), _XorLoops()
        ss.image_range = (base, base + pe.OPTIONAL_HEADER.SizeOfImage)
        ss.seen = seen_strings
        insns = result.crypto_instructions
        window: list[tuple[int, int, str, str]] = []
        for addr, _size, mnem, ops in md.disasm_lite(code, base + sec.VirtualAddress):
            ss.feed(addr, mnem, ops)
            rc4.feed(addr, mnem, ops, _size)
            xl.feed(addr, mnem, ops)
            ld.feed(addr, _size, mnem, ops)
            if hot and ("0x" in ops):
                for ref in _referenced(addr, _size, ops):
                    if any(lo <= ref < hi for lo, hi in hot):
                        result.blob_refs.append((addr, ref))
                        last_blob_ref = addr
                        break
            if mnem == "call" and ops.startswith("0x"):
                tgt = int(ops, 16)
                calls[tgt] += 1
                if addr - last_blob_ref <= 0x30:     # pointer to the blob passed as an argument
                    blob_ref_calls[tgt] += 1
                if ss.enc_blobs and 0 <= addr - ss.enc_blobs[-1] <= 0x40:
                    blob_calls[tgt] += 1
                n_ptr = sum(_data_pointer(a, z, m, o, in_data) for a, z, m, o in window)
                if n_ptr >= 1:
                    ptr1_calls[tgt] += 1
                if n_ptr >= 2:
                    ptr_calls[tgt] += 1
            if mnem in ("call", "ret", "jmp"):
                window = []
            else:
                window.append((addr, _size, mnem, ops))
                if len(window) > _ARG_WINDOW:
                    window.pop(0)
            if mnem in CRYPTO_MNEMONICS:
                first, n = insns.get(mnem, (addr, 0))
                insns[mnem] = (first, n + 1)
        ss.finish()
        result.stack_strings.extend(ss.found)
        # Groups swap loops into RC4 instances. Start of an instance = KSA (swap loop counting
        # up to 256) followed by another swap loop; if the KSA does not count up to 256 (e.g. a loop over
        # pointers), the old rule of pairs of nearby loops still applies.
        infos = sorted(rc4.loops_info, key=lambda li: li["start"])
        # KSA = swap loop with evidence of S initialization (256 loop or vector), followed by another
        # swap loop. Obfuscators' junk code does byte operations but does not initialize S.
        ksa = []
        for li in infos:
            if li["has_init"] and any(0 < o["start"] - li["start"] <= _RC4_GROUP for o in infos) \
                    and not (ksa and li["start"] - ksa[-1] <= _RC4_GROUP and not li["ksa256"]):
                if not ksa or li["start"] - ksa[-1] > 0x40:
                    ksa.append(li["start"])
        cands = sorted(set(ksa))
        for n, cand in enumerate(cands):
            nxt = cands[n + 1] if n + 1 < len(cands) else cand + _RC4_GROUP
            group = [li for li in infos if cand <= li["start"] < min(nxt, cand + _RC4_GROUP)]
            first = group[0] if group else {}
            drops = [li["count"] for li in group[1:] if li["xors"] == 0 and li["count"]]
            result.rc4_variants[cand] = {"ksa_xor": first.get("init_xor"), "drop": drops[0] if drops else None,
                                         "extra_xor": max((li["xors"] for li in group), default=0) >= 2}
        result.rc4_candidates.extend(cands)
        result.xor_loops.extend(xl.loops)
        result.enc_blobs.extend(ss.enc_blobs)

    iat = {imp.address: (imp.name or b"").decode("latin-1")
           for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT")
           for entry in getattr(pe, attr, []) for imp in entry.imports}
    result.loader = ld.finish(iat)
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp and exp.struct.Name:
        try:
            if pe.get_string_at_rva(exp.struct.Name).lower() in (b"ntdll.dll", b"win32u.dll"):
                result.loader.syscalls = []   # syscalls are normal in ntdll
        except Exception:
            pass
    result.call_patterns = {t: (calls[t], ptr_calls[t]) for t, _ in ptr_calls.most_common(20)}
    result.blob_calls = {t: (calls[t], n) for t, n in blob_calls.most_common(20)}
    result.blob_ref_calls = dict(blob_ref_calls)

    targets_sorted = sorted(calls)
    import bisect as _b
    for cand, var in result.rc4_variants.items():
        i = _b.bisect_right(targets_sorted, cand) - 1
        if i >= 0 and cand - targets_sorted[i] <= 0x400:
            var["function"], var["fan_in"] = targets_sorted[i], calls[targets_sorted[i]]
        else:
            var["function"], var["fan_in"] = None, 0

    # function containing each XOR loop = last call target before it (within 1 KB),
    # fan-in = how many times that function is called
    targets = sorted(calls)
    import bisect
    for loop in result.xor_loops:
        i = bisect.bisect_right(targets, loop["va"]) - 1
        if i >= 0 and loop["va"] - targets[i] <= 0x400:
            loop["function"], loop["fan_in"] = targets[i], calls[targets[i]]
            loop["ptr_sites"], loop["ptr1_sites"] = ptr_calls[targets[i]], ptr1_calls[targets[i]]
        else:
            loop["function"], loop["fan_in"], loop["ptr_sites"], loop["ptr1_sites"] = None, 0, 0, 0
    return result
