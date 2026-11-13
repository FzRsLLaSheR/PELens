"""Extraction of static strings (ASCII/UTF-16), classification and noise filtering.

Stack strings (built character by character in the code) are in codescan.py.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

MIN_LEN = 5

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass
class FoundString:
    value: str
    source: str            # static | stack
    encoding: str          # ascii | utf-16le
    offset: int | None = None       # offset in the file (static strings)
    va: int | None = None           # virtual address (for stack strings: where the construction starts)
    section: str = ""               # section that contains the string ("" = header or overlay)
    tags: list[str] = field(default_factory=list)

    @property
    def ida_type(self) -> str:
        """Type as in IDA's Strings window: C = ASCII, C16 = Unicode (UTF-16LE)."""
        if self.encoding == "base64":
            return "B64"      # text obtained by decoding a Base64 string
        return "C16" if self.encoding == "utf-16le" else "C"

    def to_dict(self):
        d = asdict(self)
        d["length"] = len(self.value)
        d["type"] = self.ida_type
        return d


# --- Classification -------------------------------------------------------------------------

_CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("url", re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("registry", re.compile(r"\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U)\b|SOFTWARE\\|SYSTEM\\CurrentControlSet)", re.I)),
    ("autorun", re.compile(r"\\CurrentVersion\\(?:Run|RunOnce|Winlogon|Policies\\Explorer\\Run)\b|\\Image File Execution Options", re.I)),
    ("shell", re.compile(
        r"\bcmd(?:\.exe)?\s+/[ckr]\b|\b(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-z]+\b.*){1,}|"
        r"-(?:enc|encodedcommand|ExecutionPolicy\s+bypass|windowstyle\s+hidden|w\s+hidden|nop)\b|"
        r"\bIEX\s*\(|Invoke-Expression|\.DownloadString\(|\.DownloadFile\(|Invoke-WebRequest|\]::FromBase64String\(|"
        r"\bschtasks(?:\.exe)?\s+/create|\bvssadmin(?:\.exe)?\s+delete|\bwmic(?:\.exe)?\s+shadowcopy|"
        r"\bbcdedit(?:\.exe)?\s+/set|\bwevtutil(?:\.exe)?\s+cl\b|\bcertutil(?:\.exe)?\s+-(?:urlcache|decode)|"
        r"\bbitsadmin(?:\.exe)?\s+/transfer|\b(?:mshta|regsvr32|rundll32)(?:\.exe)?\s+\S*(?:https?:|javascript:|/i:)|"
        r"\bnet(?:\.exe)?\s+(?:user|localgroup)\s+\S+.*\s/add|\breg(?:\.exe)?\s+add\s", re.I)),
    ("filepath", re.compile(r"\b[A-Z]:\\[^\s\"*?<>|]{3,}|%(?:APPDATA|TEMP|TMP|PROGRAMDATA|USERPROFILE|WINDIR|SYSTEMROOT)%", re.I)),
    ("executable", re.compile(r"\b[\w-]+\.(?:exe|dll|sys|scr|bat|ps1|vbs|js|hta|lnk)\b", re.I)),
    ("crypto", re.compile(r"\b(?:AES|RSA|RC4|ChaCha|Salsa20|CryptEncrypt|CryptDecrypt|BCrypt\w+|-----BEGIN [A-Z ]+-----)", re.I)),
    ("ransom", re.compile(r"\b(?:btc wallet|bitcoin (?:address|wallet)|(?:pay|send|transfer)\b[^\n]{0,40}\b(?:bitcoin|btc|monero|xmr)\b|"
                          r"your (?:files|data|network) (?:have been|has been|are|were) (?:encrypted|locked|stolen)|"
                          r"all (?:of )?your (?:important )?files|decrypt(?:or|ion key)|ransom|\.onion\b)", re.I)),
    # deletion of shadow copies and backups: typical of ransomware before encrypting
    ("backup_delete", re.compile(
        r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|Win32_ShadowCopy|"
        r"bcdedit(?:\.exe)?\s+/set\s+\{?default\}?\s+(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|"
        r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)", re.I)),
    ("useragent", re.compile(r"Mozilla/\d\.\d|User-Agent:", re.I)),
    ("antianalysis", re.compile(r"\b(?:vmware|virtualbox|vbox|qemu|sandboxie|wireshark|procmon|procexp|ollydbg|x64dbg|"
                                r"idaq(?:64)?|immunity|sbiedll|vmtoolsd|vboxservice|prl_tools|joebox|cuckoo)\b", re.I)),
    # services used as a "dead drop resolver" (the C2 is written in a profile/post) or to host payloads
    ("deaddrop", re.compile(
        r"\bt\.me/|telegram\.me/|api\.telegram\.org/bot|steamcommunity\.com/(?:profiles|id)/|"
        r"pastebin\.com/raw|paste\.ee/|rentry\.(?:co|org)/|ghostbin\.|hastebin\.|"
        r"cdn\.discordapp\.com/attachments|discord(?:app)?\.com/api/webhooks|"
        r"raw\.githubusercontent\.com/|gist\.githubusercontent\.com/|bitbucket\.org/[^/\s]+/[^/\s]+/downloads|"
        r"transfer\.sh|ngrok(?:-free)?\.(?:io|app)|trycloudflare\.com|\.workers\.dev|"
        r"drive\.google\.com/uc|docs\.google\.com/uc\?|dropbox\.com/s/|dl\.dropboxusercontent|"
        r"mega\.nz/|gofile\.io|file\.io/|0x0\.st|temp\.sh|anonfiles|ipfs\.io/ipfs", re.I)),
    ("ip_lookup", re.compile(
        r"api\.ipify\.org|ip-api\.com|ipinfo\.io|icanhazip\.com|checkip\.amazonaws\.com|ifconfig\.me|"
        r"wtfismyip\.com|myexternalip\.com|ipwho\.is|geoplugin\.net|ip\.sb\b", re.I)),
    ("ip_url", re.compile(r"\b(?:https?|ftp)://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", re.I)),
    # data that infostealers look for on disk (browsers, wallets, messaging, FTP clients...)
    ("stealer", re.compile(
        r"\\User Data\\|\bLogin Data\b|\bWeb Data\b|\bLocal State\b|\blogins\.json\b|\bkey[34]\.db\b|"
        r"cookies\.sqlite|formhistory\.sqlite|\bwallet\.dat\b|\\Exodus\\|\\Electrum\\|\\atomic\\|"
        r"Ethereum\\keystore|nkbihfbeogaeaoehlefnkodbefgpgknn|Telegram Desktop\\tdata|\btdata\b|"
        r"discord\\Local Storage|\bencrypted_key\b|password_value|username_value|origin_url|\bmoz_cookies\b|"
        r"FileZilla\\(?:recentservers|sitemanager)\.xml|loginusers\.vdf|\bssfn|Mozilla\\Firefox\\Profiles|"
        r"BraveSoftware|Opera Software|YandexBrowser|\\Coinomi\\|\\Armory\\|Jaxx|\\Guarda\\|"
        r"Authy Desktop|\.purple\\accounts\.xml|Outlook\\Profiles", re.I)),
    # names used only to recognize sandboxes and VMs (more specific than the generic names in "antianalysis")
    ("sandbox", re.compile(
        r"\b(?:sbiedll|cuckoomon|snxhk|api_log|dir_watch|pstorec|vmcheck|wpespy|cmdvrt(?:32|64)|SxIn|Sf2|"
        r"VBoxHook|avghook[xa]|dbghelp_x)\.dll\b|HARDWARE\\ACPI\\(?:DSDT|FADT|RSDT)\\VBOX|"
        r"\\Services\\VBox(?:Guest|Mouse|Service|SF)|\bHAL9TH\b|\bJohnDoe\b|\bWDAGUtilityAccount\b|"
        r"\bvmtoolsd\.exe\b|\bvboxservice\.exe\b|\bvboxtray\.exe\b|\bprl_tools|\bqemu-ga\b|\bxenservice", re.I)),
    # self-deletion: a wait (timeout/ping/choice) followed by del, the classic trick to delete
    # the executable after it has exited
    ("self_delete", re.compile(
        r"(?:\btimeout(?:\.exe)?\s+/t\s+\d+|\bping(?:\.exe)?\s+(?:-n\s+\d+\s+)?127\.0\.0\.1[^&|]*|"
        r"\bchoice(?:\.exe)?\s+/c\s+\w+\s+/n[^&|]*)\s*(?:>\s*nul\s*)?[&|]+\s*del\b", re.I)),
    # abuse of Chromium browsers to steal cookies and tokens (bypassing App-Bound Encryption): network service
    # to read in memory, remote debugging, elevation service, app-bound key
    ("browser_abuse", re.compile(
        r"network\.mojom\.NetworkService|--remote-debugging-(?:port|pipe)\b|\bapp_bound_encrypted_key\b|"
        r"\bIElevator\b|Elevation_?Service|Network\\Cookies\b|--utility-sub-type=", re.I)),
    ("pe_header", re.compile(r"This program (?:cannot|must) be run", re.I)),
    ("base64", re.compile(r"^(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")),
]

# Categories that indicate potentially malicious activity (used by the score)
SUSPICIOUS_TAGS = {"url", "ip", "autorun", "shell", "ransom", "antianalysis", "crypto",
                   "deaddrop", "ip_lookup", "ip_url", "stealer", "sandbox", "self_delete", "browser_abuse", "backup_delete",
                   "code_pattern"}

# code byte patterns written in hex (wildcards too), used to look for functions in the memory
# of another module: they must decode to recognizable x86/x64 instructions
_HEX_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}|\?\?){16,}$")
_CODE_MARKS = (bytes.fromhex("4883ec"), bytes.fromhex("48895c24"), bytes.fromhex("4889742418"),
               bytes.fromhex("558bec"), bytes.fromhex("4c8bdc"), bytes.fromhex("4055"), bytes.fromhex("4053"),
               bytes.fromhex("cccccccc"), bytes.fromhex("c3cc"), bytes.fromhex("e8"), bytes.fromhex("ff15"),
               bytes.fromhex("488b"), bytes.fromhex("4889"))


def _is_code_pattern(value: str) -> bool:
    if len(value) < 32 or len(value) % 2 or not _HEX_PATTERN.match(value):
        return False
    b = bytes(int(value[i:i + 2], 16) if value[i] != "?" else 0xAA for i in range(0, len(value), 2))
    return sum(1 for m in _CODE_MARKS if m in b) >= 3


def classify(value: str) -> list[str]:
    tags = [name for name, rx in _CATEGORIES if rx.search(value)]
    if _is_code_pattern(value):
        tags = [t for t in tags if t != "base64"] + ["code_pattern"]
    return tags


_HEXISH_RE = re.compile(r"^[0-9a-fA-Fx\s,.:-]+$")


def is_noise(value: str) -> bool:
    """Heuristic to discard meaningless recovered strings (e.g. 'EFEFEFEF', '476,670,838')."""
    v = value.strip()
    if len(v) < 6:
        return True
    if _HEXISH_RE.match(v):
        return True
    letters = sum(c.isalpha() for c in v)
    if letters < 3 or letters / len(v) < 0.3:
        return True
    if len(set(v.lower())) < max(4, len(v) // 6):
        return True
    return False


# --- Static strings ----------------------------------------------------------------------

def extract_static(data: bytes, limit: int = 50000) -> list[FoundString]:
    out: list[FoundString] = []
    ascii_spans: list[tuple[int, int]] = []
    for m in _ASCII_RE.finditer(data):
        ascii_spans.append(m.span())
        value = m.group().decode("ascii")
        out.append(FoundString(value, "static", "ascii", offset=m.start(), tags=classify(value)))
        if len(out) >= limit:
            break
    ascii_ends = {end - 1 for _, end in ascii_spans}  # last character of each ASCII string
    for m in _UTF16_RE.finditer(data):
        start = m.start()
        # "abc\0" followed by a UTF-16 string: the 'c' is not part of the Unicode string
        if start in ascii_ends:
            start += 2
        raw = data[start:m.end()]
        if len(raw) < MIN_LEN * 2:
            continue
        value = raw.decode("utf-16le", errors="replace")
        out.append(FoundString(value, "static", "utf-16le", offset=start, tags=classify(value)))
        if len(out) >= limit:
            break
    out.sort(key=lambda s: s.offset or 0)
    return out


def decode_base64_strings(strings: list[FoundString]) -> list[FoundString]:
    """Base64 strings that decode to text with suspicious content (Run keys, commands, URLs...):
    a common way of hiding them. They are returned as new strings (type "B64") at the same place."""
    import base64
    import binascii
    out = []
    for s in strings:
        if "base64" not in s.tags or len(s.value) < 16:
            continue
        v = s.value.strip()
        try:
            raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        text = None
        for enc in ("utf-8", "utf-16-le"):
            try:
                t = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if t and sum(ch.isprintable() or ch in "\r\n\t" for ch in t) / len(t) >= 0.95:
                text = t
                break
        if not text or len(text) < 6:
            continue
        tags = [t for t in classify(text) if t != "base64"]
        if not tags:
            continue
        out.append(FoundString(text, s.source, "base64", s.offset, s.va, s.section, tags + ["decoded_base64"]))
    return out
