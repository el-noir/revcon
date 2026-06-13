---
name: ghidra-triage
description: Perform a structured binary triage using Ghidra MCP tools. Automatically runs imports, strings, finds main, and decompiles it. Use this at the start of every RE session.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, ghidra, binary, triage, mcp]
    category: re
---
# Ghidra Binary Triage Skill
## When to Use
Use this skill whenever you start analyzing a new binary in Ghidra.
Trigger: user says "analyze", "triage", "look at", or "examine" a binary,
or when you need to start a fresh RE session.
## Critical Rules
1. Do NOT run curl or shell commands to test connectivity. The MCP bridge uses
   Windows Python and has direct access to 127.0.0.1:8080. Call MCP tools directly.
2. The binary is already open and auto-analyzed in Ghidra CodeBrowser.
3. If any tool call fails, note the error, skip it, and continue the procedure.
## Triage Procedure
### Phase 0 — Environment Check
Before starting, determine where the binary lives:
- The binary may already be open in Ghidra (MCP tools work against the Ghidra DB).
- The binary file may NOT be accessible from the Linux sandbox filesystem (`/mnt/d/...` paths often do not exist in Modal/WSL bridges).
- **Do NOT waste tool calls searching for the file on disk** unless you specifically need to modify the file (e.g., unpack with `upx -d`). Work with the Ghidra database directly.

### Phase 1 — Binary Fingerprinting
Call these in order:
1. `list_imports` — examine the imported DLLs and functions
   - If you see `mscoree.dll` / `_CorExeMain`: **STOP. This is a .NET assembly.**
     Ghidra cannot decompile .NET IL. Report this immediately and recommend dnSpy or ILSpy.
   - If you see `kernel32.dll`, `ntdll.dll`, `user32.dll`: native Windows PE
   - If you see Linux syscalls or `libc.so`: native Linux ELF
   - Note any crypto-related imports: `CryptEncrypt`, `CryptHashData`, `BCryptEncrypt`, etc.
   - Note any anti-debug imports: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, etc.
2. `list_strings` — scan for embedded strings
   - Look for: flag patterns (`flag{`, `CTF{`, `FLAG`), passwords, error messages,
     encoded blobs, URLs, registry keys
   - If you find a plaintext flag, report it immediately
3. `list_data_items` — scan for data labels and string fragments
   - In packed or stripped binaries, `list_strings` may return nothing but `list_data_items` can reveal fragments like `"o unlock,is file: "` that indicate packed code or hidden messages.
### Phase 2 — Packer/Protector Detection
After fingerprinting, check for packers:
- `list_data_items` may reveal UPX strings like `"$Info: This file is packed with the UPX executable packer"`
- `list_segments` — look for unusually named segments or gaps
- If UPX is detected:
  - The entry point will be the UPX unpacking stub, not the real `main`.
  - `search_functions_by_name("main")` will likely fail.
  - **Decision**: If you have file access, run `upx -d <file>` to unpack and reload in Ghidra.
  - If you do NOT have file access (common in sandboxed environments), state this clearly and pivot to dynamic analysis or ask the user to unpack and re-import.

### Phase 3 — Entry Point Analysis (Unpacked Binary)
3. `search_functions_by_name("main")` — find the main function
   - If found, note the address
   - If not found, try: `search_functions_by_name("entry")`, `search_functions_by_name("start")`
4. `decompile_function(address_of_main)` — get the pseudocode
   - Read carefully. Map the data flow:
     a. Where does user input come in? (scanf, ReadFile, GetWindowText, fgets)
     b. What transformations happen to the input?
     c. Where is the comparison? (strcmp, memcmp, custom loop)
   - Note any obfuscated constants (hex byte arrays, encoded strings)
### Phase 4 — Deep Dive (based on findings)
5. For each suspicious function found in Phase 3:
   - `decompile_function(address)` — read the pseudocode
   - `rename_function(address, descriptive_name)` — label it clearly
   - If it uses a key/constant: decode it immediately (write Python if needed)
6. `get_xrefs(validation_function_address)` — trace who calls the validation function
   - This tells you the full call chain from input to flag check

## Pitfalls & Recovery
- **Terminal/auth failures in sandbox**: If `terminal` fails with `AUTH_ERROR` or similar, stop using it immediately. Do not retry. Pivot to Ghidra MCP tools or ask the user for the correct path.
- **File not found on disk**: The binary may be open in Ghidra but not accessible from the Linux sandbox. Do not loop on `find` or `ls` commands. Work with the Ghidra DB directly.
- **Packed binary with no file access**: If the binary is UPX-packed and you cannot run `upx -d`, state this clearly. Recommend the user unpack it and re-import, or switch to dynamic analysis (e.g., running the binary in a sandbox and dumping memory).
- **Pre-unpacked binary in workspace**: Before asking the user to unpack, quickly check the workspace directory for files named `<original>_unpacked`, `unpacked`, `out_unpacked`, or similar. If one exists, analyze it directly with `objdump`/`nm`/`strings` rather than fighting the packed stub in Ghidra. See `references/upx-packed-workflow.md` for the exact tool sequence and a verification example.
## Reporting Format
After triage, produce a structured report: