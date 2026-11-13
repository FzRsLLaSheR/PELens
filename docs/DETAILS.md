# PELens — full documentation

Static analyzer of PE files (exe, dll, sys) for malware triage. It never runs or emulates the file:
it reads the structure, the strings and the code and computes a **suspicion score from 0 to 100**.

Besides the PE structure (headers, Rich header, protections, sections, imports/exports, resources, TLS, overlay,
signature):

- **IDA-style strings**: address, section, length, type (`C` / `C16`), classified by category
  (URLs, IPs, commands, autorun keys, anti-VM, ransomware…);
- **stack strings** rebuilt from the code (strings built character by character with `mov`);
- **recognition of cryptographic algorithms** without decrypting anything:
  AES, ChaCha20/Salsa20, RC4, DES, Blowfish, TEA, RSA (embedded keys), MD5, SHA-1/256/512, CRC32,
  AES-NI/SHA instructions, custom Base64 alphabets and XOR decryption routines;
- **compression and non-cryptographic hashes**: aPLib (decompressor, AP32 blocks), zlib/Deflate (tables and
  strings), 7z/XZ, LZ4 and Zstandard signatures, the Windows decompression APIs (RtlDecompressBuffer, also resolved
  at runtime, and the Compression API); MurmurHash2/3, xxHash, SipHash and FNV-1a constants. They are shown in the
  Cryptography page and do not raise the score, except aPLib, which is rare in legitimate software today;
- **loader techniques in the code**: direct PEB access, manual parsing of the export table,
  API hashing (hashing loops over names and known ROR13/djb2/FNV-1a/MurmurHash3 hashes of the most used APIs), direct syscalls
  (real stubs only: `mov r10, rcx` / `mov eax, N` / `syscall`), RWX memory allocations, `rdtsc`;
- **encrypted payloads**: large near-random data blocks and the decryption loops (XOR or RC4) that read them,
  directly or through a pointer passed by the caller (the loader decrypting the next stage);
- **DLL side-loading**: unsigned DLLs named like a Windows system DLL, proxy DLLs with exports
  forwarded to the original library;
- **.NET assemblies** (metadata, signatures in `rules/dotnet.yaml`): APIs grouped by capability
  (in-memory loading, decryption, download, P/Invoke for native memory and injection, credential theft,
  AMSI/ETW…), `#US` user strings, encrypted resources or resources holding a PE, known obfuscators (ConfuserEx,
  .NET Reactor, SmartAssembly, Eazfuscator, Dotfuscator, Babel, Agile.NET, KoiVM…) and unreadable names;
- **identification** of packers and protectors (UPX, MPRESS, ASPack, PECompact, Themida, VMProtect, Enigma…),
  installers (NSIS, Inno Setup, SFX) and languages/bundlers (Go, Rust, Nim, Delphi, VB6, AutoIt, PyInstaller…),
  with signatures in `rules/identify.yaml` (entry point bytes, sections, strings, overlay);
- **entropy** of the file, sections, resources and overlay, plus the points for the chart;
- a **score** based on YAML rules, each with an explanation and evidence.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -e .            # engine + command line
pip install -e ".[gui]"     # the graphical interface too (PySide6)
```

On Windows, `build_exe.bat` builds two standalone executables, `dist\pelens.exe` (command line) and
`dist\pelens-gui.exe` (graphical interface, no console).

## Usage

```bash
pelens sample.exe                      # full analysis
pelens sample.exe --all-strings        # all strings (not only the interesting ones)
pelens sample.exe --json report.json   # also save the full report
pelens sample.exe --json -             # JSON only, on stdout
pelens sample.exe --no-code            # skip disassembly (faster on huge files)
pelens sample.exe --rules my.yaml      # custom scoring rules
pelens folder/ other.exe --csv summary.csv   # several files (-r for subfolders too), summary table and CSV
pelens --compare a.exe b.exe           # compare two files (also with --json)
```

## .NET resources and steganography

Many .NET loaders (AgentTesla, Formbook, Remcos…) hide the next stage in the pixels of an image in the
resources and rebuild it with `GetPixel`/`LockBits`. PELens:

- opens `.resources` files (ResourceReader format) and lists the single elements with type, size and offset;
- extracts the images (PNG, BMP, also inside the BinaryFormatter blob of a `System.Drawing.Bitmap`) and analyzes
  their pixels: a real image has pixels similar to their neighbours (residual entropy ~3-5), encrypted data does
  not (~8);
- looks for a **PE hidden in the pixels**, in clear or encrypted with a repeating-key XOR of up to 32 bytes, trying
  the common reading orders (by rows or by columns; R,G,B,A / B,G,R,A as `Color.ToArgb()` / A,R,G,B …) and a
  header of up to 16 bytes (e.g. the length). It uses the DOS header as known plaintext: XOR between pixels and
  header gives the key, and the confirmation is the `PE\0\0` signature at `e_lfanew`. The payload is neither
  extracted nor decrypted;
- recognizes the decoder: `Bitmap.GetPixel`/`LockBits` + `Color.R/G/B` together with `Assembly.Load` or reflection.

## Other analyses

- **PEs hidden in the file**: anywhere (sections, resources, overlay), in clear or encrypted with a repeating-key
  XOR of up to 32 bytes. Bytes 0x1C-0x3B of the DOS header are zero: in an encrypted PE that area contains the
  repeated key, so XORing the file with itself shifted by p bytes turns it into a run of zeros. Only those spots
  are checked (`PE\0\0` signature at `e_lfanew`). Offset, key, type and size are reported.
- **MITRE ATT&CK**: each rule is mapped to techniques in `rules/attack.yaml` (editable); the report and the
  GUI list the techniques suggested by the findings.
- **YARA rules** (`yara-python`): `--yara <file or folder>` (repeatable), the `PELENS_YARA` variable, or a
  `yara` folder next to `pelens.exe`/`pelens-gui.exe`; in the GUI *Options → YARA rules folder*. Each match is
  a finding; the weight comes from the `weight` meta, or from `score` (0-100, as in signature-base) halved,
  otherwise 25. ATT&CK techniques come from the `mitre_att` meta. A rule file that does not compile is skipped
  and reported.
- **Verified Authenticode signature**: Authenticode hash recomputed (file modified after signing, or signature
  copied from another file, e.g. SigThief), signer's signature, chain up to the Microsoft roots (`mscerts`
  package), self-signed or expired certificates, timestamp. No network access: revocation is not checked.
- **Several files at once**: `pelens folder/ other.exe --csv summary.csv` (with `-r` subfolders too) prints
  a summary table; in the GUI *File → Open folder* and the *Summary* page (exportable to CSV).
- **Binary protections**: ASLR (also "weak" when relocations were stripped), high-entropy ASLR, DEP, CFG,
  SafeSEH (32 bit), /GS stack cookies, CET shadow stack, Force Integrity, AppContainer. In Overview, Headers and
  the CLI.
- **Decoded Rich header** (`rules/rich.yaml`): tool (linker, C/C++ compiler, MASM, LTCG…) and Visual Studio
  version of each entry, plus a summary ("linker VS2022 v17.10"). The Rich header checksum is recomputed: if it
  does not match, the Rich header was copied or edited (finding *Forged Rich header*). If it is missing but the
  DOS header is Microsoft's with a zeroed gap before the PE header, it was wiped after linking (finding
  *Rich header removed*). .NET, Go, MinGW and Delphi never have a Rich header.
- **Resource preview** (GUI, Resources page): selecting a resource shows on the right icons and cursors
  (rebuilt from RT_GROUP_ICON/RT_ICON), bitmaps, PNG/JPEG/GIF, manifests (with the requested privilege level),
  version info, string tables, text, otherwise the first bytes in hex. It works for images in .NET resources too.
- **Consistent dates and versions**: the header date is compared with the debug directory, the export directory,
  the signing date and the release of the Visual Studio named by the Rich header; the optional header linker
  version is compared with the Rich header's. Reproducible builds (date replaced by a hash) and .NET are excluded.
- **Imports by ordinal**: for ws2_32, wsock32 and oleaut32 the function name is rebuilt (e.g. ordinal 23
  = `socket`), so the API rules work even when malware imports by number.
- **Comparing two files**: ssdeep of the whole file and of every section, imphash, Rich header, toolchain,
  compile date, entry point, signature, imports, resources, interesting strings and findings, side by side.
  Useful to tell variants of the same program or samples from the same builder/crypter. For two Go binaries it also compares the
  function names of the program itself (package `main` and third-party modules, without runtime and standard
  library), which Go keeps in the binary. The ssdeep of the file
  is also shown in Overview (computed during the analysis for files up to 4 MB; pure Python, ~0.5 s per MB).
- **.NET IL code**: opcode decoder; finds the method that decrypts the strings (static, takes integers and
  returns a string or a generic, called from many places with constant arguments) and XOR loops over bytes.

## Unmapper (PE dumped from memory)

It takes a dump (x64dbg, Process Hacker…) and rebuilds a PE that IDA and PELens read like a normal file.

- recognizes the layout of the dump (mapped or raw) and the load base, derived from the relocated pointers
  (it works even if the header still contains the original ImageBase);
- **unmap** mode (sections at the raw offsets of the headers), **realign** (raw = virtual, robust with dirty
  headers) or **auto**;
- base of the rebuilt file: the load base (addresses match the debugger) or another one, applying the
  relocations;
- restores the IAT from the INT (OriginalFirstThunk); if it is missing, it suggests using Scylla;
- wiped headers (anti-dump): they can be taken from another file, e.g. the original on disk.

```bash
pelens dump.bin --unmap rebuilt.exe [--mode realign] [--load-base 7FF6A1230000] [--base 140000000]
```

In the GUI: menu **Unmapper → Rebuild PE from memory dump** (Ctrl+U), then *Save and analyze*.

## Graphical interface

```bash
pelens-gui                     # or: pelens-gui sample.exe other.dll
```

- **several files at once**: open them from *File → Open*, *File → Open folder*, the recent files list or by
  dragging them into the window; they are analyzed one at a time in the background and appear on the left with
  their score;
- **pages** for each file: Overview (score gauge, hashes, identification, toolchain, protections, indicators,
  entropy chart), Findings (rules that fired with evidence and explanation), MITRE ATT&CK, .NET, Cryptography
  (with the JSON details of each detection), YARA, Code techniques, Strings (IDA-style view with tag filters,
  search and regex), Sections (with chart), Imports (APIs used by the rules highlighted), Exports, Resources
  (with preview), Hex, Headers, JSON;
- **entropy chart** with the sections as colored bands (blue = executable, green = writable,
  red = RWX, orange = overlay, purple = signature); hovering shows offset, entropy and section;
- **HxD-style hex view**: offset/bytes/text with colored regions (headers, sections, overlay, signature),
  *Go to* an offset, RVA or VA (Ctrl+G), search for bytes with `??` wildcards or ASCII/UTF-16 text (Ctrl+F, F3),
  data inspector (integers, floats, pointers interpreted as VAs, strings), copy of the selection as hex, text,
  C array or Python bytes, saving the selection to a file;
- **jumps into the hex view**: double-click on sections, resources, exports, strings, Cryptography rows and
  Code techniques addresses, or click on the entropy chart;
- **compare**: *View → Compare* (Ctrl+D), or right-click on a file → *Compare with*;
- **right-click on a file** in the list: re-analyze, compare with another open file, copy path / SHA-256 /
  ssdeep, open the containing folder, export, close, close all (Ctrl+Shift+W);
- **copy**: Ctrl+C or right-click on any table copies the selected rows (tab-separated);
- **export**: full JSON (Ctrl+S) and HTML report (Ctrl+E); a saved JSON report can be reopened;
- dark/light theme from *View*, *Code analysis* option in the toolbar for a faster analysis.

From Python:

```python
from pelens.analyzer import analyze
report = analyze("sample.exe")
print(report["score"]["score"], report["score"]["verdict"])
for h in report["crypto"]:
    print(h["algorithm"], h["signature"], hex(h["va"] or 0), h["confidence"])
```

> For .NET assemblies the x86 code analysis is skipped (the code is IL bytecode): instead PELens reads the
> metadata with [dnfile](https://github.com/malwarefrank/dnfile) and decodes the IL itself.

> ⚠️ Analyze real malware only in an isolated virtual machine. PELens does not run the file,
> but it is good practice not to keep samples on your own PC.

## Cryptography recognition

The signatures are in `pelens/rules/crypto.yaml`. Signature types:

| type | what it looks for | example |
|---|---|---|
| `bytes` | hex sequence | AES S-box, DES S-box |
| `string` | text | `expand 32-byte k` (ChaCha20), `-----BEGIN PUBLIC KEY-----` |
| contiguous `dwords` | table of 32-bit values, little or big endian | AES T-tables, CRC32, Blowfish P-array |
| non-contiguous `dwords` | values all present within `window` bytes | constants as immediates in code (MD5, SHA-1, ChaCha) |
| `qwords` | table of 64-bit values | SHA-512 K constants |

Each signature has a `confidence` (high / medium / low): a full S-box is strong evidence, a single
32-bit constant is not (for example TEA's `0x9E3779B9` is also used in hash functions).

The disassembled code (Capstone) provides instead:
- **hardware instructions** AES-NI (`aesenc`, `aeskeygenassist`…) and SHA (`sha256rnds2`…);
- **RC4 (custom variants too)**, recognized by its structure since it has no constants: the initialization of a
  256-byte array followed by `S[i] <-> S[j]` swap loops with 8-bit indexes. It works on optimized and
  unoptimized code (MSVC `/Od`, GCC `-O0`), with inlined copies, and ignores junk code.
  The table has a single row ("N implementations, non-standard variant, called from M places"); the JSON has,
  for each implementation, address, number of calls and changes from the standard
  (`ksa_init_xor` for `S[i] = i ^ c`, `drop` for dropped bytes, `extra_xor` for an extra XOR on the output);
- **encrypted stack strings**: `mov [rsp+…], constant` sequences with non-printable data followed by an
  XOR loop with the key in a register, also with variable state (`state += plain`, "rolling-key XOR");
- **"home-made" XOR decryption routines**, typical of infostealers (Vidar, StealC…). An XOR loop alone
  is not enough, because big programs are full of them (hashes, character conversions). The usage pattern of a
  string decryptor is needed too:
  - *high*: the function is called from 8+ places and in at least half of the calls receives 2+ pointers to data
    in the file (key and ciphertext, e.g. Vidar's `push len / pop reg / push key / push data / call`);
  - *medium*: multi-byte key, 8+ calls, almost all with a pointer to data (key embedded by the compiler);
  - *low*: all other XOR loops (shown but not counted in the score).

Long tables are generated by code, not copied by hand.

## How the score works

The rules are in `pelens/rules/default.yaml`. Each rule calls a *check* in
`pelens/scoring.py` and, if it fires, adds its `weight` (total capped at 100):

```yaml
- id: stream_cipher
  check: crypto_algorithms
  weight: 15
  severity: high
  title: "Stream cipher in the code (RC4, ChaCha20, Salsa20)"
  params: {categories: [stream_cipher], min_confidence: medium}
```

You can change weights and thresholds, disable a rule (`enabled: false`) or create new ones reusing the
existing checks. A new check is just a function decorated with `@check("name")` in `scoring.py`.

Rule categories:
- **sections**: RWX, executable data, entropy, packer names, virtual-only sections;
- **entry point**: outside any section, not executable, in the last section;
- **imports**: few or none, injection (write + execute in another process), anti-debug,
  keylogging, persistence, network;
- **overlay and resources**: embedded PEs, encrypted data;
- **strings**: stack strings, full commands, autorun keys, ransomware texts,
  dead drop resolvers (Telegram, Steam, Pastebin, Discord, GitHub raw, tunnels…), URLs with a bare IP, public-IP
  lookup services, infostealer targets (browser credentials, wallets, Telegram/Discord sessions),
  names used to recognize sandboxes and VMs;
- **loaders**: PEB, export parsing (counts only together with PEB or hashing), API hashing, direct syscalls,
  RWX memory, timing checks;
- **cryptography**: stream ciphers (custom RC4 variants too), XOR decryption routines and encrypted stack
  strings, hand-made cryptography without Windows APIs, embedded RSA keys, custom Base64, ransomware profile
  (cryptography + a ransom note or backup deletion);
- **structure**: forged or removed Rich header, inconsistent dates and versions, wrong checksum, invalid,
  untrusted or stolen signatures.

The rules were calibrated on legitimate software (7-Zip, Notepad++, the Program Files folder of a
Windows machine, MinGW runtimes, Go and Rust tools…): almost everything scores between 0 and 20.

## Layout

```
pelens/
  pe_info.py          PE structure: headers, Rich, protections, sections, imports/exports, resources, TLS, overlay, signature
  resdata.py          resource preview: icons, bitmaps, manifests, string tables
  entropy.py          Shannon entropy and sliding windows
  strings.py          static strings (IDA-style) and classification
  hidden.py           PEs hidden in the file (in clear or XOR-encrypted)
  authenticode.py     Authenticode signature verification
  dotnet.py           .NET metadata (dnfile): APIs, P/Invoke, #US, resources, obfuscators
  dotnet_resources.py .resources parser, image analysis, PEs hidden in pixels
  dotnet_il.py        IL decoder: string decryptors and XOR loops
  identify.py         packers, protectors, installers, compilers
  loader_traits.py    loader techniques in the code (PEB, exports, hashing, syscalls, RWX, rdtsc)
  codescan.py         single pass with Capstone: stack strings, RC4, XOR loops, call arguments, AES-NI/SHA
  crypto.py           cryptographic algorithm recognition
  scoring.py          rule engine and checks
  yara_scan.py        user YARA rules
  unmapper.py         rebuilding of PEs dumped from memory
  batch.py            several files, summary and CSV
  compare.py          comparison of two files (ssdeep via ppdeep, sections, imports, resources, strings)
  analyzer.py         orchestration: produces a JSON report (used by the CLI and the GUI)
  cli.py              command line
  gui/                graphical interface (PySide6): window, pages, hex view, resource preview, summary, compare, unmapper
  rules/default.yaml   scoring rules
  rules/attack.yaml    rule -> MITRE ATT&CK techniques
  rules/crypto.yaml    cryptographic signatures
  rules/dotnet.yaml    .NET APIs by capability and obfuscators
  rules/identify.yaml  packers, installers, compilers
  rules/rich.yaml      Rich header product ids and builds -> tool and Visual Studio version
```

License: Apache-2.0. The GUI bundles the Inter and JetBrains Mono fonts (SIL Open Font License 1.1, license texts in
`pelens/gui/fonts/`); the icons are drawn for PELens.
