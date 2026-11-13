"""Typical loader techniques, recognized in the code (single pass together with codescan).

Loaders import little and have no strings in clear, but they leave traces in the code:
- direct access to the PEB (gs:[0x60] / fs:[0x30]) to find kernel32/ntdll without imports;
- manual parsing of the export table (e_lfanew -> export directory);
- API hashing: loops that "rotate" a hash over the characters of the name, and known hash constants;
- direct syscalls (syscall / sysenter / int 0x2e) outside ntdll;
- allocation of executable memory (PAGE_EXECUTE_READWRITE);
- rdtsc (anti-sandbox timing).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- Known hashes of the APIs most used by loaders -------------------------------------------------------

_API_NAMES = [
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress", "GetModuleHandleA", "VirtualAlloc",
    "VirtualAllocEx", "VirtualProtect", "VirtualFree", "CreateThread", "CreateRemoteThread", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "CreateProcessA", "CreateProcessW", "WinExec", "ExitProcess",
    "WaitForSingleObject", "Sleep", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
    "NtCreateThreadEx", "NtQueueApcThread", "RtlMoveMemory", "InternetOpenA", "InternetOpenUrlA",
    "InternetReadFile", "URLDownloadToFileA", "WSAStartup", "connect", "recv", "send", "HeapAlloc",
    "GetTempPathA", "CreateFileA", "WriteFile", "ShellExecuteA",
]


def _ror(v: int, r: int) -> int:
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF


def _known_hashes() -> dict[int, str]:
    out: dict[int, str] = {}
    for name in _API_NAMES:
        b = name.encode()
        h = 0
        for c in b:                                   # "classic" ROR13 (shellcode, Cobalt Strike, etc.)
            h = (_ror(h, 13) + c) & 0xFFFFFFFF
        out.setdefault(h, f"{name} (ROR13)")
        h = 5381
        for c in b:                                   # djb2
            h = (h * 33 + c) & 0xFFFFFFFF
        out.setdefault(h, f"{name} (djb2)")
        h = 0x811C9DC5
        for c in b:                                   # FNV-1a 32 bit
            h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
        out.setdefault(h, f"{name} (FNV-1a)")
        out.setdefault(_murmur3_32(b), f"{name} (MurmurHash3)")
    return out


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (also used for API hashing)."""
    c1, c2, m = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h = seed
    n = len(data) & ~3
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        k = (k * c2) & m
        h ^= k
        h = ((h << 13) | (h >> 19)) & m
        h = (h * 5 + 0xE6546B64) & m
    k = 0
    tail = data[n:]
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        k = (k * c2) & m
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & m
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & m
    return h ^ (h >> 16)


KNOWN_API_HASHES = _known_hashes()

_PEB_RE = re.compile(r"(?:qword ptr gs:\[0x60\]|dword ptr fs:\[0x30\])")
_ELFANEW_RE = re.compile(r"dword ptr \[(?!r?[sb]p\b|e[sb]p\b)([a-z0-9]+) \+ 0x3c\]")
_IMM_RE = re.compile(r"0x[0-9a-f]{6,8}\b")
_HASH_ROT_RE = re.compile(r"^[a-z0-9]+, (0x[0-9a-f]+|\d+)$")
_SYSCALL_MNEMS = {"syscall", "sysenter"}
_ALLOC_APIS = {"virtualalloc", "virtualallocex", "virtualallocexnuma", "ntallocatevirtualmemory",
               "zwallocatevirtualmemory"}
# global keyboard (and mouse) hooks: those of a keylogger; WH_KEYBOARD (2) and the others are common in GUIs
_HOOKS = {13: "WH_KEYBOARD_LL"}
_IND_CALL_RE = re.compile(r"^(?:qword|dword) ptr \[(?:rip ([+-]) (0x[0-9a-f]+)|(0x[0-9a-f]+))\]$")


@dataclass
class LoaderTraits:
    peb_access: list[int] = field(default_factory=list)
    export_parsing: list[int] = field(default_factory=list)
    hash_loops: list[dict] = field(default_factory=list)          # {va, op}
    api_hashes: list[dict] = field(default_factory=list)          # {va, value, api}
    syscalls: list[int] = field(default_factory=list)
    rwx_alloc: list[dict] = field(default_factory=list)           # {va, api}
    rdtsc: list[int] = field(default_factory=list)
    kbd_hooks: list[dict] = field(default_factory=list)           # {va, api, hook}: global keyboard hook

    def to_dict(self) -> dict:
        return {k: v[:50] if isinstance(v, list) else v for k, v in self.__dict__.items()}


class LoaderScanner:
    def __init__(self, x64: bool, export_dir_disp: int):
        self.t = LoaderTraits()
        self.x64 = x64
        self.export_re = re.compile(r"dword ptr \[[a-z0-9]+(?: \+ [a-z0-9]+)? \+ %s\]" % hex(export_dir_disp))
        self.recent: list[tuple[int, int, str, str]] = []
        self.last_elfanew = -10**9
        self.calls: list[tuple[int, int | None, int | None, bool]] = []  # (addr, target, slot, has_0x40)
        self.thunks: dict[int, int] = {}                                 # thunk VA -> IAT slot
        self.seen_hash: set[int] = set()
        self.pending_export: tuple[int, set] | None = None

    def feed(self, addr: int, size: int, mnem: str, ops: str):
        self.recent.append((addr, size, mnem, ops))
        if len(self.recent) > 64:
            del self.recent[:16]
        t = self.t
        if _PEB_RE.search(ops):
            t.peb_access.append(addr)
        if _ELFANEW_RE.search(ops):
            self.last_elfanew = addr
        elif self.export_re.search(ops) and addr - self.last_elfanew <= 0x40:
            self.pending_export = (addr, set())
        elif self.pending_export:
            start, seen = self.pending_export
            if addr - start > 0x100:
                self.pending_export = None
            else:
                # IMAGE_EXPORT_DIRECTORY fields: NumberOfNames, AddressOfFunctions/Names/NameOrdinals
                for d in ("0x18]", "0x1c]", "0x20]", "0x24]"):
                    if ops.endswith(d) and "dword ptr [" in ops:
                        seen.add(d)
                if len(seen) >= 2:
                    t.export_parsing.append(start)
                    self.pending_export = None
        is_sys = (mnem == "syscall" and self.x64) or (not self.x64 and (mnem == "sysenter" or
                                                                         (mnem == "int" and ops == "0x2e")))
        if is_sys:
            # only inside a stub: "mov eax, <plausible syscall number>" shortly before (and "mov r10, rcx" on x64).
            # An isolated 0F 05 is often data inside .text decoded as an instruction.
            prev = [(m, o) for _a, _z, m, o in self.recent[-6:-1]]
            nums = [int(mm.group(1), 0) for m, o in prev if m == "mov"
                    for mm in [re.match(r"^eax, (0x[0-9a-f]+|\d+)$", o)] if mm]
            has_r10 = any(m == "mov" and o == "r10, rcx" for m, o in prev)
            if nums and nums[-1] < 0x1000 and (has_r10 or not self.x64):
                t.syscalls.append(addr)
        elif mnem == "rdtsc":
            t.rdtsc.append(addr)
        # known API hash constants (immediates in the code)
        if mnem in ("cmp", "mov", "push", "sub", "xor") and "0x" in ops:
            for m in _IMM_RE.finditer(ops):
                v = int(m.group(), 16)
                if v in KNOWN_API_HASHES and v not in self.seen_hash:
                    self.seen_hash.add(v)
                    t.api_hashes.append({"va": addr, "value": v, "api": KNOWN_API_HASHES[v]})
        # hashing loop: rotation (ror/rol) + character read from memory, in a short loop
        if mnem.startswith("j") and ops.startswith("0x"):
            target = int(ops, 16)
            if 0 < addr - target <= 0x60:
                body = [(m, o) for a, _z, m, o in self.recent if a >= target]
                rot = [o for m, o in body if m in ("ror", "rol") and _HASH_ROT_RE.match(o)]
                byte_load = any(m in ("movzx", "movsx", "mov") and "byte ptr [" in o and not o.startswith("byte")
                                for m, o in body)
                # rotation of a 32-bit register (API hashes are 32-bit)
                rot32 = [o for o in rot if o.split(", ")[0].startswith("e") or
                         (o.split(", ")[0].startswith("r") and o.split(", ")[0].endswith("d"))]
                if rot32 and byte_load:
                    t.hash_loops.append({"va": target, "op": rot32[0]})
        # calls (to recognize VirtualAlloc with PAGE_EXECUTE_READWRITE)
        if mnem == "jmp":
            mm = _IND_CALL_RE.match(ops)
            if mm:
                self.thunks[addr] = self._slot(addr, size, mm)
        if mnem == "call":
            has40 = any(self._is_protect40(m, o) for _a, _z, m, o in self.recent[-9:-1])
            arg1 = self._arg1()
            if ops.startswith("0x"):
                self.calls.append((addr, int(ops, 16), None, has40, arg1))
            else:
                mm = _IND_CALL_RE.match(ops)
                if mm:
                    self.calls.append((addr, None, self._slot(addr, size, mm), has40, arg1))

    @staticmethod
    def _slot(addr: int, size: int, mm) -> int:
        if mm.group(3):
            return int(mm.group(3), 16)
        d = int(mm.group(2), 16)
        return addr + size + (d if mm.group(1) == "+" else -d)

    def _arg1(self) -> int | None:
        """First argument of the call if it is a constant: ecx/rcx on x64, the last push on x86."""
        for _a, _z, m, o in reversed(self.recent[-9:-1]):
            if self.x64:
                if m in ("mov", "lea") and o.split(", ")[0] in ("ecx", "rcx", "cl"):
                    v = o.split(", ")[1]
                    return int(v, 16) if v.startswith("0x") else (int(v) if v.isdigit() else None)
                if m == "xor" and o in ("ecx, ecx", "rcx, rcx"):
                    return 0
            elif m == "push":
                return int(o, 16) if o.startswith("0x") else (int(o) if o.isdigit() else None)
            if m == "call":
                return None
        return None

    def _is_protect40(self, m: str, o: str) -> bool:
        # PAGE_EXECUTE_READWRITE = 0x40 as the "protection" argument
        if self.x64:
            return m == "mov" and o in ("r9d, 0x40", "r9, 0x40", "dword ptr [rsp + 0x28], 0x40")
        return (m == "push" and o == "0x40") or (m == "mov" and o.endswith("], 0x40") and "esp" in o)

    def finish(self, iat: dict[int, str]) -> LoaderTraits:
        for addr, target, slot, has40, arg1 in self.calls:
            if not has40 and arg1 not in _HOOKS:
                continue
            if slot is None and target is not None:
                slot = self.thunks.get(target)
            name = iat.get(slot or -1, "")
            if has40 and name.lower() in _ALLOC_APIS:
                self.t.rwx_alloc.append({"va": addr, "api": name})
            if arg1 in _HOOKS and name.lower() in ("setwindowshookexa", "setwindowshookexw"):
                self.t.kbd_hooks.append({"va": addr, "api": name, "hook": _HOOKS[arg1]})
        return self.t
