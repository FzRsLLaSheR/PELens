# PELens MCP server

Lets **Claude Desktop** or **Claude Code**, running on a different machine from the analysis VM, use what PELens
found: it can validate the findings, explain what the sample does, look at strings, imports, bytes and disassembly,
and write its conclusions back into PELens as **AI notes**.

```
Analysis VM                                   AI machine (your AI account / API keys)
┌───────────────────────────────┐             ┌──────────────────────────────────────┐
│ PELens → AI → Start AI bridge │  Host-only  │ Claude Desktop / Claude Code         │
│ read-only HTTP API + token    │◄────────────┤  └ pelens_mcp.py (this MCP server)   │
└───────────────────────────────┘   network   └──────────────────────────────────────┘
```

Nothing of the AI side (accounts, API keys, chats) ever reaches the analysis VM, and the samples never leave it:
the AI machine only receives what PELens extracted.

## Setup

**In the analysis VM**

1. Open the files in PELens.
2. **AI → Start AI bridge…**: choose the address of the network shared with the AI machine (a Host-only network),
   optionally the address of the AI machine as the only allowed client, and start.
   Windows asks whether PELens may accept connections: allow it for that network.
3. **AI → Save MCP server for the AI machine…** writes `pelens_mcp.py`, this README and `pelens-mcp.json` (address
   and token) into a folder: copy that folder to the AI machine (shared folder, USB…).

**On the AI machine** (Python 3.10+):

```bat
pip install mcp
python C:\PELens-MCP\pelens_mcp.py --check
```

`--check` must list the files open in PELens. Then add the server to your client:

- **Claude Desktop**: Settings → Developer → Edit config, add to `claude_desktop_config.json` and restart:

  ```json
  {
    "mcpServers": {
      "pelens": { "command": "python", "args": ["C:\\PELens-MCP\\pelens_mcp.py"] }
    }
  }
  ```

- **Claude Code**:

  ```bat
  claude mcp add --scope user --transport stdio pelens -- python "C:\PELens-MCP\pelens_mcp.py"
  ```

  then `/mcp` inside Claude Code to check that `pelens` is connected.

Instead of `pelens-mcp.json` you can set the environment variables `PELENS_URL` (e.g.
`http://192.168.30.128:47011`) and `PELENS_TOKEN`.

## Tools

| Tool | What it reads |
|---|---|
| `list_files` | files open in PELens, with their id, score and verdict |
| `get_summary` | hashes, type, protections, packer/compiler, score, findings with evidence |
| `get_findings` | every finding with description, weight, evidence and ATT&CK |
| `get_sections`, `get_imports` | sections with entropy; imports filtered by DLL / function |
| `search_strings` | strings by regular expression or tag (url, ip, registry, command, crypto…) |
| `get_details` | ATT&CK, exports, resources, crypto, YARA, loader techniques, .NET, hidden PEs, headers, version info, signature, overlay |
| `read_bytes`, `disassemble` | hex dump and x86/x64 disassembly at an offset, RVA or VA |
| `compare_files` | similarity of two open files |
| `list_notes`, `add_note` | the AI notes of a file; `add_note` is the only tool that writes |

Try for example: *"Look at the files open in PELens, validate the findings of the highest-scoring one and write
your conclusions as a note."*

## Security

- The bridge is **read-only**: no command execution, no file upload or download, no access outside the open files.
  The only write is a note, stored by PELens as text.
- It listens on **one address** only (not on all interfaces), and every request needs the **token**. Use a new
  token (in the start dialog) whenever you like; the old one stops working.
- Everything extracted from a sample is **untrusted data**: malware can carry text written to mislead an AI
  ("ignore previous instructions…"). The server labels it as such and tells the assistant never to follow it; do
  not give the same AI session tools that act on your machine when you work on samples.
- Use a Host-only (or otherwise isolated) network between the two machines, as for the rest of the analysis.
