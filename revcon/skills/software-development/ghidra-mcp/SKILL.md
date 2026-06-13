---
name: ghidra-mcp
description: >
  Reverse engineering workflows through a locally configured Ghidra MCP server.
  Covers server-side tool discovery from the bridge script when Hermes shows
  truncated MCP tool output, plus concrete flag-hunting and binary analysis
  procedures.
version: 0.1.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [mcp, ghidra, reverse-engineering, binary-analysis, crackme]
    related_skills: [hermes-agent]
---

# Ghidra MCP

Use when a `ghidra` server is configured under `mcp_servers:` in `config.yaml`
and the task is to analyze a Windows PE / .NET binary for keys, flags, logic,
or vulnerabilities. Complements the generic MCP guidance in `hermes-agent`
by adding Ghidra-specific tool patterns and recovery steps.

## When to Use

- User points to a binary in `incoming_binaries/` or elsewhere and asks to
  “find the flag / key / password / check logic”.
- The MCP server is already running against a local Ghidra instance.
- `hermes mcp list` reports the server as `all` without enumerating tools.

## Tool Discovery

### Preferred: MCP runtime discovery

If the `mcp` Python package is installed, startup tool discovery should expose
`mcp_ghidra_*` tools directly.

### Fallback: bridge-script extraction

When `hermes mcp list` shows `all` and the Python `mcp` package is missing,
enumerate tools by reading the bridge script defined in `config.yaml` and
extracting decorated methods:

```text
@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    ...
```

Server config location:
```bash
grep -n "ghidra" ~/.hermes/config.yaml ~/.hermes/profiles/*/config.yaml
```

Typical bridge path on the user's machine:
```text
mnt/c/Users/<user>/Downloads/GhidraMCP-release-1-4/.../bridge_mcp_ghidra.py
```

## Base Toolset

Expect these tools; prefix them with `mcp_ghidra_` when calling via Hermes:

- **Enumeration:** `list_methods`, `list_classes`, `list_namespaces`,
  `list_segments`, `list_imports`, `list_exports`, `list_data_items`,
  `list_functions`, `list_strings`
- **Search:** `search_functions_by_name`, `get_function_by_address`,
  `get_current_function`, `get_current_address`
- **Code:** `decompile_function`, `decompile_function_by_address`,
  `disassemble_function`
- **Rename / annotate:** `rename_function`, `rename_data`,
  `rename_variable`, `rename_function_by_address`
- **Comments / typing:** `set_decompiler_comment`, `set_disassembly_comment`,
  `set_function_prototype`, `set_local_variable_type`
- **Cross-refs:** `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`

## Recommended Analysis Workflow

1. **Adjacent source file check.** Before any MCP calls, look for a same-named
   `.c`, `.cs`, `.cpp`, or `.rs` next to the binary. If present, read it first —
   it often exposes the flag or decoding logic directly and avoids unnecessary
   MCP dependency. This is especially important if the Ghidra MCP server may not
   be running.
2. **Strings first.** Run `list_strings` and filter for suspicious literals
   (`flag`, `KEY`, `license`, `password`, `CTF`, URLs, base64 blobs).
3. **Imports / exports.** Review `list_imports` and `list_exports` for
   crypto, network, or validation entry points.
4. **Function search.** Use `search_functions_by_name` for likely names
   (`check`, `validate`, `decrypt`, `main`, `flag`, `key`).
5. **Decompile entry points.** Decompile `Main` and high-level handlers with
   `decompile_function`.
6. **Xref tracing.** From interesting strings or functions, follow
   `get_xrefs_to` / `get_xrefs_from` to locate validation logic.
7. **Address-driven inspection.** When you have an address, use
   `decompile_function_by_address` and `disassemble_function`.
8. **Confirm in Ghidra UI.** If the API proxy may have failed, open the
   same project in the native Ghidra GUI and inspect manually.

## Quick Shortcuts

- Adjacent source file may exist. Before deep MCP work, check for `<name>.c`,
  `.cs`, `.cpp`, or `.rs` next to the binary.
- If the binary is .NET / Mono, the decompiler output is usually enough;
  assembly is rarely necessary.
- For XOR / simple obfuscation, look for:
  - single-byte keys in byte arrays
  - `Encoding.ASCII.GetString` or byte-by-byte transforms
  - loops iterating over a fixed-size array

## .NET / Managed Assembly Note

When `list_imports` shows `_CorExeMain` from `mscoree.dll`, the target is a .NET assembly.
In that case:

1. Do not treat a decompiler failure as proof of obfuscation or a binary problem
   — it usually means Ghidra did not parse the CLI metadata / method bodies cleanly.
2. `list_methods` may only show CLI entry points (`entry`, `.ctor`) plus a few
   token-lifted methods, while real application logic lives in CLI `#~`/`#Strings`
   tables that the current bridge path is not fully exposing.
3. `decompile_function` for `Main` is likely to fail even though the function
   exists, because the body range is small or the method body is not materialized.
4. Rich metadata can still be seen through other pointers:
   - `list_data_items` shows CLI metadata headers and streams
   - `list_strings` shows manifest/resource literals, which confirms .NET
5. Do not loop on failing decompiles. Shift to a .NET-focused workflow:
   - Look for an adjacent `.cs` source file (shortcut 0).
   - If unavailable, use a .NET decompiler / deobfuscator outside Ghidra
     (ILSpy, dnSpy, de4dot, dnGrep, ConfuserEx-Unpacker).
   - Prefer examining raw CLI metadata / method tables when possible, but the
     current Ghidra MCP bridge is usually not the right instrument for that.

Treat "decompilation failed on a .NET entry" as a signal to pivot, not as a
reason to retry the same tool calls.

## Pitfalls

- **Tool list truncation.** `hermes mcp list` can answer with `all`; do not
  trust it as the complete enumeration. Always fall back to the bridge script.
- **Ghidra server not configured.** If `grep -n "ghidra" ~/.hermes/config.yaml ~/.hermes/profiles/*/config.yaml`
  returns no results, the server is not configured and `mcp_ghidra_*` tools
  will not be available. In that case, the adjacent source-file shortcut
  (step 1) becomes the primary path. Tell the user explicitly that MCP was
  bypassed due to missing config, and offer to set it up if they want
  binary-level verification or there may be logic not reflected in source.
- **Ghidra server down.** The bridge will return `Error` or `Request failed`
  strings if `http://127.0.0.1:8080` is unreachable. Verify the Ghidra server
  locally before blaming the MCP layer.
- **WSL path mismatch.** The user stores binaries under `/mnt/d/...` but the
  configured bridge may be a Windows Python path. These run in the WSL
  process, so `/mnt/...` paths are valid.
- **MCP package missing.** Without `python -m pip install mcp`, the Hermes
  MCP client cannot auto-discover tools. Expect bridge-script extraction
  to be the main path.
  
  On modern Ubuntu/Debian systems with PEP 668 enforcement, `pip3 install mcp`
  will fail with `externally-managed-environment`. The fastest fix for dev VMs:
  ```bash
  pip3 install mcp --break-system-packages
  ```
  For persistent systems, use a venv instead:
  ```bash
  python3 -m venv ~/ghidra-mcp-venv
  source ~/ghidra-mcp-venv/bin/activate
  pip install mcp
  ```
  
  **Alternative: `uv run` (if uv is installed).** The bridge script includes PEP 723
  inline metadata declaring `mcp>=1.2.0` as a dependency. If `uv` is available, you can
  run the bridge without pre-installing anything:
  ```bash
  cd ~/Downloads/GhidraMCP-release-1-4
  uv run bridge_mcp_ghidra.py
  ```
  This automatically creates an ephemeral venv and installs the declared dependencies.
  This is often the cleanest option when available.
- **Looping on failing decompiles.** When `decompile_function_by_address` and
  `decompile_function` both return `Decompilation failed` for a .NET entry,
  additional retries are unlikely to add value. Pivot to metadata inspection
  or a .NET decompiler rather than re-issuing the same call types.
- **MCP test handshake fails before any tool call.** When `hermes mcp test ghidra`
  returns `Connection failed (…): Connection closed`, that is a bridge/server
  handshake failure in the MCP layer, not proof that the Ghidra HTTP backend is
  down. Do not infer backend reachability from this alone; it just means tool
  calls through Hermes’ MCP client cannot proceed.
- **Agent terminal access ≠ Hermes tool enable.** When a user runs
  `hermes tools enable terminal`, this enables the tool in the Hermes
  configuration but does not automatically add `terminal` to the agent's
  available function list. The agent can only use tools explicitly provided
  in its toolset. If the agent lacks `terminal` or `execute_code`, it
  cannot run commands directly and must delegate to sub-agents or use
  cronjobs. Do not tell the user to "just run commands yourself" unless
  the agent genuinely cannot execute them.
- **Raw byte extraction not available.** The current Ghidra MCP bridge does not
  support reading raw bytes from arbitrary addresses. `mcp_ghidra_read_resource`
  with `program://<name>/memory/<address>` URIs will return "Unknown resource".
  When you need raw bytes (e.g., encrypted payload in .rdata), do not loop on
  this failing call. Instead, use `mcp_ghidra_disassemble_function` to confirm
  the address and size, then switch to direct binary file parsing or ask the
  user to run a local extraction script. See `vm-binary-analysis` skill for
  PE .rdata extraction scripts.
- **Config file write blocked.** The `patch` and `write_file` tools refuse to
  write to `~/.hermes/config.yaml` and `~/.hermes/profiles/*/config.yaml` with
  "protected system/credential file" or "security-sensitive configuration"
  errors. When updating the Ghidra MCP server path (or any `mcp_servers` config),
  do not attempt to write the YAML directly.

  **Important:** `hermes config set` does NOT correctly handle list-type values.
  Commands like:
  ```bash
  hermes config set mcp_servers.ghidra.args '["/path/to/bridge_mcp_ghidra.py"]'
  ```
  will serialize `args` as a **string** instead of a YAML list, causing Pydantic
  validation errors (`Input should be a valid list [type=list_type]`).

  **Correct approach — manual YAML editing:**
  ```bash
  nano ~/.hermes/config.yaml
  ```
  Edit the `mcp_servers` section to use proper YAML list syntax:
  ```yaml
  mcp_servers:
    ghidra:
      command: python
      args:
        - /home/el-noir/Downloads/GhidraMCP-release-1-4/bridge_mcp_ghidra.py
  ```
  After updating, verify with `hermes mcp test ghidra`, then start a new session
  (`/reset`) for tool discovery to take effect.

## Connectivity Troubleshooting

When a user asks "is Ghidra MCP working?" or `mcp_ghidra_*` tools are missing,
follow the ordered diagnostic checklist in
`references/mcp-connectivity-troubleshooting.md`.

Key points:
- Inspect `config.yaml` for the `ghidra` server entry; watch for relative paths,
  Windows backslashes, or `args` serialized as a string.
- Verify the bridge script exists and the Ghidra HTTP backend is listening.
- Test the bridge manually before blaming the Hermes MCP client.
- Do not use WSL `curl` against a Windows-loopback Ghidra server.

## Verification

After discovering or changing binary state via MCP, verify by:

- Re-running `list_strings` to see renamed labels.
- Re-decompiling the modified function.
- Checking `get_current_function` / `get_current_address` gives consistent
  results with expected names.