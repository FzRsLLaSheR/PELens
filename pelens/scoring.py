"""Scoring engine: applies the rules of the YAML file to the extracted information."""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

DEFAULT_RULES = Path(__file__).parent / "rules" / "default.yaml"

CheckFn = Callable[[dict, list[dict], dict], list[str]]
CHECKS: dict[str, CheckFn] = {}


def check(name: str):
    def deco(fn: CheckFn) -> CheckFn:
        CHECKS[name] = fn
        return fn
    return deco


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str
    weight: int
    evidence: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)


@dataclass
class ScoreResult:
    score: int
    verdict: str
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)
    attack: list[dict] = field(default_factory=list)   # ATT&CK techniques with the findings that motivate them

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    with open(path or DEFAULT_RULES, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    ids = [r["id"] for r in cfg.get("rules", [])]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise ValueError(f"duplicate rule ids: {', '.join(sorted(dup))}")
    for r in cfg["rules"]:
        if r["check"] not in CHECKS:
            raise ValueError(f"rule {r['id']}: unknown check '{r['check']}'")
    return cfg


ATTACK_FILE = Path(__file__).parent / "rules" / "attack.yaml"


def load_attack(path: str | Path | None = None) -> dict:
    try:
        with open(path or ATTACK_FILE, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError:
        return {}


def evaluate(info: dict, strings: list[dict], rules: dict[str, Any]) -> ScoreResult:
    findings, errors = [], []
    attack = load_attack()
    amap = attack.get("rules") or {}
    for rule in rules["rules"]:
        if not rule.get("enabled", True):
            continue
        try:
            evidence = CHECKS[rule["check"]](info, strings, rule.get("params") or {})
        except Exception as e:  # a faulty rule must not stop the analysis
            errors.append(f"{rule['id']}: {e}")
            continue
        if evidence:
            findings.append(Finding(rule["id"], rule["title"], rule.get("description", "").strip(),
                                    rule.get("severity", "medium"), int(rule["weight"]), evidence[:20],
                                    list(rule.get("attack") or amap.get(rule["id"]) or [])))
    # YARA matches: one finding per rule, with the weight taken from the rule's metadata
    for m in info.get("yara_matches") or []:
        ev = [f"{h['id']} @ 0x{h['offset']:x}: {h['data']}" for h in m["strings"]][:10] or ["condition matched"]
        desc = m["description"] or "Matched a YARA rule."
        findings.append(Finding(f"yara:{m['rule']}", f"YARA: {m['rule']}",
                                f"{desc} (rule file {m['file']}{', author ' + m['author'] if m['author'] else ''})",
                                m["severity"], m["weight"], ev, m.get("attack") or []))
    findings.sort(key=lambda f: -f.weight)
    score = max(0, min(100, sum(f.weight for f in findings)))
    verdict = next((v["label"] for v in sorted(rules["verdicts"], key=lambda v: -v["min"]) if score >= v["min"]), "")
    names = attack.get("techniques") or {}
    techs: dict[str, dict] = {}
    for f in findings:
        for t in f.attack:
            techs.setdefault(t, {"id": t, "name": names.get(t, ""), "findings": []})["findings"].append(f.id)
    return ScoreResult(score, verdict, findings, errors, sorted(techs.values(), key=lambda t: t["id"]))


# --- Check -------------------------------------------------------------------------------------

def _sec_label(s: dict) -> str:
    return f"{s['name'] or '<empty>'} [{s['flags']}] entropy {s['entropy']:.2f}"


@check("rwx_section")
def _rwx(info, strings, p):
    return [_sec_label(s) for s in info["sections"] if s["executable"] and s["writable"]]


@check("exec_unexpected_section")
def _exec_unexpected(info, strings, p):
    names = {n.lower() for n in p.get("names", [])}
    return [_sec_label(s) for s in info["sections"] if s["executable"] and s["name"].lower() in names]


@check("exec_section_count")
def _exec_count(info, strings, p):
    ex = [s for s in info["sections"] if s["executable"]]
    return [", ".join(_sec_label(s) for s in ex)] if len(ex) >= p.get("min", 2) else []


@check("high_entropy_section")
def _high_entropy_section(info, strings, p):
    if info.get("is_dotnet") and p.get("executable_only"):
        return []   # in .NET, resources live in .text: high entropy does not mean packed code
    th, min_size = p.get("threshold", 7.2), p.get("min_size", 0)
    only_x, skip_x = p.get("executable_only", False), p.get("skip_executable", False)
    skip_names = set(p.get("skip_names", []))
    return [_sec_label(s) for s in info["sections"]
            if s["entropy"] >= th and s["raw_size"] >= min_size and s["name"] not in skip_names
            and not (only_x and not s["executable"]) and not (skip_x and s["executable"])]


@check("virtual_only_section")
def _virtual_only(info, strings, p):
    ratio, min_vs = p.get("ratio", 10), p.get("min_virtual_size", 4096)
    out = []
    for s in info["sections"]:
        if p.get("executable_only") and not s["executable"]:
            continue  # e.g. .bss: empty on disk by definition
        if s["virtual_size"] >= min_vs and (s["raw_size"] == 0 or s["virtual_size"] / s["raw_size"] >= ratio):
            out.append(f"{s['name']}: {s['raw_size']} bytes on disk, {s['virtual_size']} in memory")
    return out


@check("section_names")
def _section_names(info, strings, p):
    names = {n.lower() for n in p.get("names", [])}
    return [s["name"] for s in info["sections"] if s["name"].lower() in names]


@check("weird_section_names")
def _weird_names(info, strings, p):
    return [repr(s["name"]) for s in info["sections"] if not s["name"] or not s["name"].isprintable()]


@check("ep_outside_sections")
def _ep_outside(info, strings, p):
    if info["entry_point_rva"] and info["entry_point_section"] is None:
        return [f"entry point RVA 0x{info['entry_point_rva']:x}"]
    return []


def _ep_section(info):
    return next((s for s in info["sections"] if s["name"] == info["entry_point_section"]), None)


@check("ep_not_executable")
def _ep_not_exec(info, strings, p):
    s = _ep_section(info)
    return [f"entry point in {_sec_label(s)}"] if s and not s["executable"] else []


@check("ep_in_last_section")
def _ep_last(info, strings, p):
    secs = info["sections"]
    if len(secs) > 1 and info["entry_point_section"] is not None and secs[-1]["name"] == info["entry_point_section"]:
        return [f"entry point in {_sec_label(secs[-1])} (last of {len(secs)})"]
    return []


def _all_imports(info) -> set[str]:
    return {f for imp in info["imports"] for f in imp["functions"]}


@check("import_count")
def _import_count(info, strings, p):
    if info["is_dotnet"] or info["kind"] == "driver":
        return []  # .NET assemblies import only _CorExeMain: not an indicator
    n = len(_all_imports(info))
    if p.get("min", 0) <= n <= p.get("max", 0):
        return [f"{n} imported functions"]
    return []


def _api_hits(info, strings, apis) -> list[str]:
    wanted = {a.lower() for a in apis}
    found = sorted(f for f in _all_imports(info) if f.lower() in wanted)
    # strings with API names (e.g. resolved with GetProcAddress) count too
    found_str = sorted({s["value"] for s in strings if s["value"].lower() in wanted} - set(found))
    return found + [f"{f} (string)" for f in found_str]


# APIs that the C runtime (MSVC/MinGW) loads by itself with GetProcAddress: they mean nothing
_CRT_DYNAMIC = {x.lower() for x in """
FlsAlloc FlsFree FlsGetValue FlsSetValue InitializeCriticalSectionEx AreFileApisANSI LCMapStringEx LocaleNameToLCID
AppPolicyGetProcessTerminationMethod CorExitProcess InitOnceExecuteOnce CreateEventExW CreateSemaphoreExW
SetThreadStackGuarantee CreateThreadpoolTimer SetThreadpoolTimer WaitForThreadpoolTimerCallbacks CloseThreadpoolTimer
CreateThreadpoolWait SetThreadpoolWait CloseThreadpoolWait FlushProcessWriteBuffers FreeLibraryWhenCallbackReturns
GetCurrentProcessorNumber CreateSymbolicLinkW GetCurrentPackageId GetTickCount64 GetFileInformationByHandleEx
SetFileInformationByHandle GetSystemTimePreciseAsFileTime InitializeConditionVariable WakeConditionVariable
WakeAllConditionVariable SleepConditionVariableCS InitializeSRWLock AcquireSRWLockExclusive TryAcquireSRWLockExclusive
ReleaseSRWLockExclusive SleepConditionVariableSRW CompareStringEx GetDateFormatEx GetLocaleInfoEx GetTimeFormatEx
GetUserDefaultLocaleName IsValidLocaleName LCIDToLocaleName GetEnabledXStateFeatures GetXStateFeaturesMask
LocateXStateFeature MessageBoxA MessageBoxW GetActiveWindow GetLastActivePopup GetUserObjectInformationW
GetProcessWindowStation RoInitialize RoUninitialize SystemFunction036 EnumSystemLocalesEx GetSystemDefaultLocaleName
GetDynamicTimeZoneInformation AddVectoredExceptionHandler RemoveVectoredExceptionHandler IsWow64Process
SetDefaultDllDirectories GetModuleHandleExW GetProcAddress LoadLibraryExW LoadLibraryW LoadLibraryA FreeLibrary
""".split()}
_API_NAME = re.compile(
    r"^(?:(?:Nt|Zw|Rtl|Ldr|K32)[A-Z]\w{3,45}|(?:Get|Set|Create|Open|Close|Read|Write|Query|Enum|Virtual|Load|Free|"
    r"Find|Reg|Crypt|Internet|Http|Process32|Module32|Thread32|Lookup|Shell|SH|WSA|Heap|Local|Global|Map|Unmap|"
    r"Terminate|Resume|Suspend|Wait|Delete|Copy|Move|Adjust|Duplicate|Impersonate|Connect|Send|Recv|Url|Win|Str|"
    r"Ver|Wnet|Net|Cert|BCrypt|NCrypt|Is|Sleep|Exit|Disconnect|Shut|Inject|Allocate)[A-Z0-9]?\w{2,45}|"
    r"lstr\w{3,12}|wsprintf[AW]|socket|connect|recv|send|gethostbyname|inet_addr)$")


# APIs that are suspicious to hide: other processes and their memory, injection, network, crypto, tokens, hooks, desktops
_SENSITIVE_API = re.compile(
    r"^(?:OpenProcess|ReadProcessMemory|WriteProcessMemory|VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|VirtualQueryEx|"
    r"CreateRemoteThread(?:Ex)?|QueueUserAPC|(?:Nt|Zw)(?:AllocateVirtualMemory|WriteVirtualMemory|ReadVirtualMemory|"
    r"ProtectVirtualMemory|CreateThreadEx|QueueApcThread|UnmapViewOfSection|MapViewOfSection|CreateSection|OpenProcess|"
    r"QueryInformationProcess|SetInformationThread|ResumeThread|GetContextThread|SetContextThread|QuerySystemInformation|"
    r"TerminateProcess|CreateUserProcess)|Rtl(?:CreateUserThread|DecompressBuffer)|CreateToolhelp32Snapshot|"
    r"Process32(?:First|Next)W?|Module32(?:First|Next)W?|Thread32(?:First|Next)|K32\w+|EnumProcess\w*|"
    r"Internet\w+|Http\w+|WinHttp\w+|URLDownloadToFile\w*|WSAStartup|socket|connect|send|recv|gethostbyname|"
    r"Crypt(?:AcquireContext|Decrypt|Encrypt|ImportKey|GenKey|DeriveKey|CreateHash|HashData|UnprotectData|ProtectData|"
    r"StringToBinary|BinaryToString)[AW]?|BCrypt(?:Decrypt|Encrypt|GenerateSymmetricKey|ImportKey|OpenAlgorithmProvider)|"
    r"CreateProcess\w*|ShellExecute\w*|WinExec|OpenProcessToken|AdjustTokenPrivileges|"
    r"LookupPrivilegeValue\w*|DuplicateToken\w*|ImpersonateLoggedOnUser|SetWindowsHookEx\w*|GetAsyncKeyState|"
    r"GetKeyState|CreateDesktop\w*|OpenDesktop\w*|SetThreadContext|GetThreadContext|ResumeThread|"
    r"IsDebuggerPresent|CheckRemoteDebuggerPresent|RegSetValueEx\w*|RegCreateKeyEx\w*|"
    r"CredEnumerate\w*|CryptUnprotectData|LsaEnumerate\w*|SamConnect)$")


@check("runtime_api_strings")
def _runtime_apis(info, strings, p):
    """Many API names as strings, not imported: resolved at runtime with GetProcAddress to hide them."""
    imports = {f.lower() for f in _all_imports(info)}
    resolver = {"getprocaddress", "ldrgetprocedureaddress"} & (imports | {s["value"].lower() for s in strings})
    traits = info.get("code_traits") or {}
    if not resolver and not traits.get("export_parsing"):
        return []
    names = []
    for s in strings:
        v = s["value"]
        if s["source"] != "static" or not _API_NAME.match(v) or v.lower() in imports or v.lower() in _CRT_DYNAMIC:
            continue
        if not any(c.islower() for c in v) or sum(c.isupper() for c in v) < 2 and not v.startswith(("lstr", "wsprintf")):
            continue
        names.append(v)
    names = list(dict.fromkeys(names))
    sensitive = [n for n in names if _SENSITIVE_API.match(n)]
    if len(names) < p.get("min", 12) or len(sensitive) < p.get("min_sensitive", 3):
        return []
    rest = [n for n in names if n not in sensitive]
    shown = sensitive + rest
    return [f"{len(names)} API names resolved at runtime, {len(sensitive)} sensitive: "
            + ", ".join(shown[:25]) + (" …" if len(shown) > 25 else "")]


# user-writable folders: %VARIABLE% (lowercase too), the bare name only in uppercase (as it is
# passed to GetEnvironmentVariable) and the typical paths
_USER_DIRS = re.compile(r"(?i:%(?:LOCALAPPDATA|APPDATA|TEMP|TMP|PROGRAMDATA|PUBLIC|USERPROFILE)%)|"
                        r"\b(?:LOCALAPPDATA|APPDATA|PROGRAMDATA|USERPROFILE)\b|"
                        r"(?i:\\AppData\\(?:Local|Roaming)|\\Local\\Temp\\|\\ProgramData\\|\\Users\\Public\\|"
                        r"\\Start Menu\\Programs\\Startup)")


@check("impersonated_library")
def _impersonated(info, strings, p):
    """A file that claims to be from a known vendor (version info) but is not validly signed and contains loader
    code: the trojanized copy of a library used for DLL side-loading."""
    vi = info.get("version_info") or {}
    claim = " / ".join(x for x in (vi.get("CompanyName", ""), vi.get("ProductName", "")) if x)
    vendors = re.compile(p.get("vendors", r"$^"), re.I)
    if not claim or not vendors.search(claim):
        return []
    sig = (info.get("signature") or {}).get("verification") or {}
    if sig.get("verified"):
        return []
    ev = []
    t = info.get("code_traits") or {}
    if t.get("rwx_alloc"):
        ev.append(f"allocates executable+writable memory ({t['rwx_alloc'][0].get('api', '')})")
    if t.get("api_hashes") or t.get("hash_loops"):
        ev.append("resolves APIs by hash")
    if any(h["encrypted"] for h in info.get("hidden_pe") or []):
        ev.append("carries an encrypted executable")
    if any(h["algorithm"] == "Payload decryption" for h in info.get("crypto", [])):
        ev.append("decrypts embedded data")
    tags = sorted({tg for s in strings for tg in s["tags"] if tg in ("deaddrop", "ip_url", "browser_abuse")})
    if tags:
        ex = next(s["value"][:60] for s in strings if set(s["tags"]) & set(tags))
        ev.append(f"strings: {', '.join(tags)} (e.g. {ex})")
    strict = re.compile(p.get("strict_vendors", r"$^"), re.I).search(claim)
    if len(ev) < (2 if strict else 1):
        return []
    state = "signature not valid" if sig else "not signed"
    return [f"claims to be '{claim}' ({vi.get('OriginalFilename', '?')}) but is {state}"] + ev


@check("dropper")
def _dropper(info, strings, p):
    """Embedded payload + file writing + process start + a user folder: writes the payload
    to disk and runs it."""
    payload = []
    if info.get("hidden_pe"):
        payload.append(f"{len(info['hidden_pe'])} embedded executable(s)")
    if any(h["algorithm"] == "Payload decryption" for h in info.get("crypto", [])):
        payload.append("decryption loop over embedded data")
    big = [s for s in info["sections"] if not s["executable"] and s["entropy"] >= 7.2 and s["raw_size"] >= 65536
           and s["name"] != ".rsrc"]   # resources (icons, images) are judged by the resource rule
    if big:
        payload.append(f"encrypted block in {big[0]['name']} ({big[0]['raw_size']:,} bytes)")
    if not payload:
        return []
    write = _api_hits(info, strings, ["CreateFileA", "CreateFileW", "WriteFile", "NtWriteFile", "fwrite", "_wfopen",
                                      "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW"])
    run = _api_hits(info, strings, ["CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                                    "ShellExecuteExA", "ShellExecuteExW", "WinExec", "CreateProcessAsUserA",
                                    "CreateProcessAsUserW", "_wsystem", "system"])
    where = sorted({s["value"][:60] for s in strings if _USER_DIRS.search(s["value"])})
    if not (write and run and where):
        return []
    return payload + [f"writes with {', '.join(write[:3])}", f"runs with {', '.join(run[:3])}",
                      "user-writable location: " + ", ".join(where[:4])]


@check("api_group")
def _api_group(info, strings, p):
    if "max_imports" in p and len(_all_imports(info)) > p["max_imports"]:
        return []
    hits = _api_hits(info, strings, p.get("apis", []))
    return hits if len(hits) >= p.get("min", 1) else []


@check("api_combo")
def _api_combo(info, strings, p):
    """Fires only if every API group has at least one match.
    hidden_only: only APIs present as strings and not imported (resolved at runtime) count."""
    per_group = [_api_hits(info, strings, g) for g in p.get("groups", [])]
    if p.get("hidden_only"):
        per_group = [[h for h in g if h.endswith(" (string)")] for g in per_group]
    if not per_group or not all(per_group):
        return []
    return [h for g in per_group for h in g]


@check("embedded_pe")
def _embedded_pe(info, strings, p):
    out = [f"resource {r['type']}/{r['name']} ({r['size']} bytes)" for r in info["resources"] if r["embedded_pe"]]
    ov = info.get("overlay")
    if ov and ov["embedded_pe"]:
        out.append(f"overlay at offset 0x{ov['offset']:x} ({ov['size']} bytes)")
    return out


@check("hidden_pe")
def _hidden_pe(info, strings, p):
    """PEs hidden in the file (pelens.hidden): XOR-encrypted, or in clear outside resources and overlay."""
    out = []
    for h in info.get("hidden_pe") or []:
        if bool(h["encrypted"]) != p.get("encrypted", True):
            continue
        if not h["encrypted"] and not h["region"].startswith(tuple(p.get("plain_regions") or ("section",))):
            continue
        what = " ".join(x for x in (h.get("machine"), ".NET" if h.get("dotnet") else "", h.get("kind")) if x)
        size = f", {h['size']:,} bytes" if h.get("size") else ""
        how = f" encrypted with a {h['key_length']}-byte XOR key {h['key']}" if h["encrypted"] else ""
        out.append(f"{what or 'PE'}{how} at offset 0x{h['offset']:x} ({h['region']}{size})")
    return out


@check("signature")
def _signature(info, strings, p):
    """Authenticode signature: problem requested by p["problem"] (mismatch | invalid | untrusted)."""
    sig = info.get("signature") or {}
    v = sig.get("verification")
    if not v:
        return []
    who = f"signer '{v.get('signer', '?')}', issued by '{v.get('issuer', '?')}'"
    want = p.get("problem")
    if want == "mismatch" and v.get("digest_ok") is False:
        return [f"Authenticode hash does not match the file ({who})"]
    if want == "invalid" and v.get("digest_ok") and v.get("signature_ok") is False:
        return [f"invalid signer signature ({who})"]
    if want == "untrusted" and v.get("signature_ok") and (v.get("self_signed") or v.get("trusted_root") is False):
        return [f"{'self-signed certificate' if v.get('self_signed') else 'chain not trusted'}: {who}"]
    return []


@check("overlay")
def _overlay(info, strings, p):
    ov = info.get("overlay")
    if not ov:
        return []
    if "min_ratio" in p and ov["ratio"] < p["min_ratio"]:
        return []
    if "min_entropy" in p and ov["entropy"] < p["min_entropy"]:
        return []
    if ov["size"] < p.get("min_size", 0):
        return []
    return [f"offset 0x{ov['offset']:x}, {ov['size']} bytes ({ov['ratio']:.0%} of the file), entropy {ov['entropy']:.2f}"]


@check("high_entropy_resource")
def _high_entropy_res(info, strings, p):
    ignore = set(p.get("ignore_types", []))
    return [f"{r['type']}/{r['name']}: {r['size']} bytes, entropy {r['entropy']:.2f}" for r in info["resources"]
            if r["type"] not in ignore and r["size"] >= p.get("min_size", 0) and r["entropy"] >= p.get("threshold", 7.4)]


@check("file_entropy")
def _file_entropy(info, strings, p):
    return [f"entropy {info['entropy']:.2f}"] if info["entropy"] >= p.get("threshold", 7.2) else []


@check("tls_callbacks")
def _tls(info, strings, p):
    return [f"0x{va:x}" for va in info["tls_callbacks"]]


@check("timestamp")
def _timestamp(info, strings, p):
    ts = info["timestamp"]
    if info["is_dotnet"]:
        return []  # recent .NET compilers put a hash instead of the date (reproducible builds)
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    if ts == 0:
        return ["timestamp is zero"]
    if ts > now + 86400:
        return [f"date in the future: {info['timestamp_utc']}"]
    if ts < 788918400:  # 1995-01-01
        return [f"date too old: {info['timestamp_utc']}"]
    return []


@check("checksum")
def _checksum(info, strings, p):
    c = info["checksum"]
    if c["stored"] and c["computed"] is not None and c["stored"] != c["computed"]:
        return [f"header 0x{c['stored']:x}, computed 0x{c['computed']:x}"]
    return []


@check("consistency")
def _consistency(info, strings, p):
    return [f"{c['what']}: {c['detail']}" for c in info.get("consistency") or []]


@check("rich_removed")
def _rich_removed(info, strings, p):
    if not info.get("rich_removed"):
        return []
    lf = info["headers"]["dos"].get("e_lfanew", 0)
    return [f"Microsoft DOS stub with {lf - 0x80} zeroed bytes before the PE header, where the Rich header goes"]


@check("rich_checksum")
def _rich_checksum(info, strings, p):
    rh = info.get("rich") or {}
    return ["checksum of the Rich header does not match its contents"] if rh.get("checksum_ok") is False else []


@check("parser_warnings")
def _warnings(info, strings, p):
    ignore = p.get("ignore", ["UNWIND_INFO"])
    # warnings from PELens itself ("could not read …") say nothing about the file
    w = [x for x in info["parser_warnings"] if not any(i in x for i in ignore) and not x.startswith("PELens ")]
    return w if len(w) >= p.get("min", 1) else []


@check("hidden_strings")
def _hidden(info, strings, p):
    min_len = p.get("min_length", 8)
    hidden = [s for s in strings if s["source"] != "static" and (len(s["value"]) >= min_len or s["tags"])]
    if len(hidden) < p.get("min", 1):
        return []
    return [f"[{s['source']}] {s['value'][:120]}" for s in hidden]


@check("string_tags")
def _string_tags(info, strings, p):
    sources, tags = set(p.get("sources", [])), set(p.get("tags", []))
    max_words = p.get("max_words")
    hits = [s for s in strings if s["source"] in sources and tags & set(s["tags"])
            and (max_words is None or len(s["value"].split()) <= max_words)]
    if len(hits) < p.get("min", 1):
        return []
    return [f"[{s['source']}] {s['value'][:120]}  ({', '.join(sorted(tags & set(s['tags'])))})" for s in hits]


# --- Cryptography --------------------------------------------------------------------------

_CONF = {"low": 0, "medium": 1, "high": 2}


def _crypto_library(info) -> bool:
    """A real crypto library (archiver, browser, TLS): it uses the AES-NI/SHA-NI hardware instructions.
    There a standard RC4 or a "home-made" AES are normal."""
    return any("hardware instruction" in h["signature"] for h in info.get("crypto", []))


def _crypto_hits(info, p) -> list[dict]:
    min_conf = _CONF[p.get("min_confidence", "medium")]
    cats, algos = set(p.get("categories", [])), set(p.get("algorithms", []))
    hits = [h for h in info.get("crypto", [])
            if _CONF[h["confidence"]] >= min_conf
            and (not cats or h["category"] in cats) and (not algos or h["algorithm"] in algos)]
    if p.get("skip_library") and _crypto_library(info):
        # in a crypto library only certain detections count (e.g. modified RC4 variants)
        hits = [h for h in hits if h["confidence"] == "high" and h["category"] != "block_cipher"]
    return hits


def _crypto_label(h: dict) -> str:
    where = f" @ 0x{h['va']:x}" if h.get("va") else (f" offset 0x{h['offset']:x}" if h.get("offset") is not None else "")
    sec = f" ({h['section']})" if h.get("section") else ""
    return f"{h['algorithm']}: {h['signature']}{where}{sec}"


@check("crypto_algorithms")
def _crypto_algorithms(info, strings, p):
    return [_crypto_label(h) for h in _crypto_hits(info, p)]


@check("crypto_without_api")
def _crypto_without_api(info, strings, p):
    """Algorithms implemented in the program without using the Windows crypto APIs."""
    hits = _crypto_hits(info, p)
    if not hits or _api_hits(info, strings, p.get("apis", [])):
        return []
    if p.get("skip_library") and _crypto_library(info):
        return []
    return sorted({f"{h['algorithm']} implemented in the program" for h in hits})


@check("crypto_and_apis")
def _crypto_and_apis(info, strings, p):
    """Cryptography (recognized algorithms or APIs) + every listed API group: e.g. ransomware profile."""
    crypto_ev = [_crypto_label(h) for h in _crypto_hits(info, p)]
    crypto_ev += _api_hits(info, strings, p.get("crypto_apis", []))
    if not crypto_ev:
        return []
    groups = [_api_hits(info, strings, g) for g in p.get("api_groups", [])]
    if not all(groups):
        return []
    # require_tags: a specific sign is needed too (ransom note, backup deletion...): cryptography and
    # file access alone describe any archiver or backup program
    marks = []
    if p.get("require_tags"):
        want = set(p["require_tags"])
        marks = [f"[{s['source']}] {s['value'][:100]}" for s in strings if want & set(s["tags"])]
        if not marks:
            return []
    return marks[:5] + crypto_ev + [h for g in groups for h in g]


# --- Loader techniques in the code --------------------------------------------------------------

def _traits(info) -> dict:
    return info.get("code_traits") or {}


@check("code_trait")
def _code_trait(info, strings, p):
    t = _traits(info)
    items = t.get(p["trait"], [])
    if len(items) < p.get("min", 1):
        return []
    # requires_any: the technique counts only together with at least one of these (e.g. export parsing + PEB/hashing)
    if p.get("requires_any") and not any(t.get(r) for r in p["requires_any"]):
        return []
    out = []
    for it in items[:10]:
        if isinstance(it, dict):
            out.append(f"0x{it['va']:x}" + (f" {it.get('api', '')}" if it.get("api") else "")
                       + (f" ({it['op']})" if it.get("op") else ""))
        else:
            out.append(f"0x{it:x}")
    return out


@check("api_hashing")
def _api_hashing(info, strings, p):
    t = _traits(info)
    hashes, loops = t.get("api_hashes", []), t.get("hash_loops", [])
    out = [f"hash 0x{h['value']:08x} = {h['api']} @ 0x{h['va']:x}" for h in hashes[:10]]
    if len(hashes) >= p.get("min_known", 2):
        return out
    # or: hashing loop over names + manual way of finding modules/exports
    if loops and (t.get("peb_access") or t.get("export_parsing")):
        return out + [f"hashing loop @ 0x{lp['va']:x} ({lp['op']})" for lp in loops[:5]]
    return []


# --- DLL side-loading ----------------------------------------------------------------------------

@check("sideload_name")
def _sideload_name(info, strings, p):
    """DLL with the name of a Windows system DLL but no signature: candidate for side-loading/hijacking."""
    name = (info.get("file_name") or "").lower()
    if info["kind"] != "dll" or info.get("signature") or name not in {n.lower() for n in p.get("names", [])}:
        return []
    ev = [f"file name {name} matches a Windows system DLL, but the file is not signed"]
    exp = info.get("exports") or {}
    internal = (exp.get("name") or "").lower()
    if internal and internal != name:
        ev.append(f"internal export name is {internal}")
    return ev


@check("proxy_dll")
def _proxy_dll(info, strings, p):
    """Exports that point to another DLL (forwarders) or many exports at the same addresses: proxy DLL."""
    exp = info.get("exports") or {}
    syms = exp.get("symbols") or []
    if info["kind"] != "dll" or len(syms) < p.get("min_exports", 10):
        return []
    fwd = [s for s in syms if s.get("forwarder")]
    distinct = len({s["rva"] for s in syms if not s.get("forwarder")})
    ev = []
    if len(fwd) / len(syms) >= 0.5:
        ev.append(f"{len(fwd)} of {len(syms)} exports are forwarded, e.g. {fwd[0]['name']} -> {fwd[0]['forwarder']}")
    elif distinct and distinct / len(syms) < 0.5:
        ev.append(f"{len(syms)} exports point to only {distinct} distinct addresses (stubs)")
    return ev


# --- .NET -------------------------------------------------------------------------------------------

def _dn(info) -> dict:
    return info.get("dotnet") or {}


@check("dotnet_api")
def _dotnet_api(info, strings, p):
    """All categories in all_of, and at least one of any_of (if given)."""
    cats = _dn(info).get("api_categories") or {}
    need_all, need_any = p.get("all_of", []), p.get("any_of", [])
    if not all(c in cats for c in need_all):
        return []
    if need_any and not any(c in cats for c in need_any):
        return []
    used = need_all + [c for c in need_any if c in cats]
    return [f"{cats[c]['title']}: {', '.join(cats[c]['hits'][:4])}" for c in used]


@check("dotnet_obfuscator")
def _dotnet_obfuscator(info, strings, p):
    types = set(p.get("types", []))
    return [f"{o['name']} ({o['type']}) — {o['evidence']}" for o in _dn(info).get("obfuscators", [])
            if not types or o["type"] in types]


@check("dotnet_obfuscated_names")
def _dotnet_obf_names(info, strings, p):
    on = _dn(info).get("obfuscated_names") or {}
    if on.get("total", 0) >= p.get("min_names", 10) and on.get("ratio", 0) >= p.get("ratio", 0.5):
        return [f"{on['ratio']:.0%} of {on['total']} type/method names are unreadable, e.g. {', '.join(on['examples'][:3])}"]
    return []


def _dn_resource_items(info):
    """The single .NET resources: the elements of .resources files, or the manifest resource itself."""
    for r in _dn(info).get("resources", []):
        if r.get("entries"):
            for e in r["entries"]:
                yield f"{r['name']} → {e['name']} ({e['type']})", e
        elif r.get("format") != ".resources":
            yield r["name"], r


@check("dotnet_resource_payload")
def _dotnet_resource(info, strings, p):
    out = []
    for label, r in _dn_resource_items(info):
        hp = r.get("hidden_pe")
        if hp and hp["encrypted"]:
            out.append(f"resource {label} contains a PE file encrypted with a {hp['key_length']}-byte XOR key "
                       f"{hp['key']} ({r['size']} bytes)")
        elif r.get("embedded_pe") and not r.get("image"):
            out.append(f"resource {label} contains a PE file ({r['size']} bytes)")
        elif r.get("image"):
            continue   # images are compressed by nature: dotnet_stego_image judges them from the pixels
        elif r["size"] >= p.get("min_size", 16384) and r["entropy"] >= p.get("min_entropy", 7.5):
            out.append(f"resource {label}: {r['size']} bytes, entropy {r['entropy']:.2f}")
    return out


@check("dotnet_string_decryptor")
def _dotnet_strdec(info, strings, p):
    il = _dn(info).get("il") or {}
    out = []
    for d in il.get("string_decryptors") or []:
        xor = ", contains an XOR loop" if d.get("xor_loop") else ""
        out.append(f"{d['method']}({'int, ' * (d['params'] - 1)}int) → {d['returns']}: {d['calls']} calls from "
                   f"{d['callers']} methods, {d['constant_args']:.0%} with a constant argument{xor}")
    return out


@check("dotnet_stego_image")
def _dotnet_stego(info, strings, p):
    out = []
    for label, r in _dn_resource_items(info):
        img = r.get("image") or {}
        hp = img.get("hidden_pe")
        if hp:
            how = (f"encrypted with a {hp['key_length']}-byte XOR key {hp['key']}" if hp["encrypted"] else "unencrypted")
            extra = f" after a {hp['offset']}-byte header" if hp["offset"] else ""
            if hp.get("length_header"):
                extra += f" (length {hp['length_header']:,})"
            out.append(f"{label}: {img['format']} {img['width']}x{img['height']} hides a PE file {how}, pixels read "
                       f"by {hp['layout']}{extra}")
        elif img.get("embedded_pe"):
            out.append(f"{label}: {img['format']} {img.get('width')}x{img.get('height')} with a PE file in its pixels")
        elif img.get("noise"):
            out.append(f"{label}: {img['format']} {img['width']}x{img['height']}, {img['pixel_bytes']:,} pixel bytes "
                       f"that do not compress (ratio {img['compress_ratio']:.2f}, entropy {img['pixel_entropy']:.2f})")
    return out


# --- Identification -----------------------------------------------------------------------------

@check("identified")
def _identified(info, strings, p):
    types = set(p.get("types", []))
    return [f"{i['name']} ({i['type']}) — {i['evidence']}" for i in info.get("identification", [])
            if i["type"] in types]


@check("dotnet_metadata_tampering")
def _dotnet_tampering(info, strings, p):
    return list(_dn(info).get("metadata_anomalies") or [])


@check("dotnet_no_user_strings")
def _dotnet_no_strings(info, strings, p):
    """Large assembly without string literals: the strings were encrypted by a protector."""
    dn = _dn(info)
    c = dn.get("counts") or {}
    size = c.get("methods") or c.get("heap_names") or 0
    if size >= p.get("min_names", 300) and c.get("user_strings", 0) <= p.get("max_strings", 3):
        return [f"{c.get('user_strings', 0)} user strings for {size} methods/names"]
    return []
