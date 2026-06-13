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
Before starting, verify the Ghidra MCP bridge is operational:
1. Run `hermes mcp test ghidra` — if it fails, the bridge is not running or not configured.
2. If the bridge fails, check: Is the `mcp` Python package installed? Is Ghidra running with the MCP server script loaded? See `references/ghidra-mcp-bridge-setup.md` for full setup and troubleshooting.
3. Only proceed with Ghidra analysis once `hermes mcp test ghidra` succeeds.

### Phase 0b — Program State Verification
After confirming the bridge is connected, verify that a program is actually open and analyzed:
1. Run `mcp_ghidra_list_segments` — if this returns empty, no program is open in Ghidra. Stop and tell the user to open a binary in Ghidra CodeBrowser first.
2. Run `mcp_ghidra_list_exports` — if only "Reset -> 0x00000000" appears and nothing else, the binary is likely raw embedded firmware that has not been auto-analyzed.
3. Run `mcp_ghidra_list_functions` — if empty, Ghidra has not defined any functions yet. This happens with:
   - Raw binaries loaded without proper processor specification
   - Embedded firmware / bootloaders / microcontroller images
   - Binaries where auto-analysis was not run or failed
4. If any of the above indicate an unanalyzed binary, tell the user: "The binary is loaded but Ghidra has not analyzed it. Please set the correct processor architecture and run Auto-Analysis (Analysis > Auto Analyze)."
5. **CRITICAL — After auto-analysis, re-verify**: Run `mcp_ghidra_list_functions` again. If it is STILL empty, the binary is likely raw embedded firmware where auto-analysis cannot create functions automatically. In this case, tell the user: "Auto-analysis completed but no functions were defined. This is a raw binary. Please manually create a function at the entry point (address 0x00000000 or the Reset vector) by right-clicking in the Listing view and selecting 'Create Function', then re-run Auto-Analysis if needed."
6. Do NOT continue calling disassembly/decompilation tools on addresses with no defined functions — they will fail with "No function found at or containing address".

After confirming the bridge and program state, determine where the binary lives:
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

**Embedded Firmware / Raw Binary Detection:**
If `list_imports` is empty, `list_strings` is empty, and `list_exports` shows only `Reset -> 0x00000000`:
- This is likely raw embedded firmware or a bootloader
- The binary needs proper processor architecture selection and auto-analysis in Ghidra
- **Do not attempt decompilation yet** — no functions are defined
- Tell the user: "The binary is loaded but Ghidra has not analyzed it. Please set the correct processor architecture and run Auto-Analysis."
- **After auto-analysis, if functions still don't exist**: The binary needs manual function creation at the entry point. Guide the user to create a function at address 0, then re-analyze.
- **Alternative**: If the user provides the binary file path, delegate to `sandbox_runner` for script-based analysis (pwntools, capstone) to determine architecture and extract code without waiting for Ghidra UI steps.
- See `references/raw-binary-embedded-firmware.md` for the full diagnostic and recovery workflow
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
7. **VM-based flag check**: If the decompilation shows an interpreter loop with opcode dispatch via function pointer table, encrypted bytecode, and small handler functions:
   - Switch to the `vm-binary-analysis` skill for detailed VM analysis procedures
   - Look for: `mmap`/`VirtualAlloc` for executable memory, `ptrace` anti-debug, environment variables like `FUSION_PEER_FD`

## Pitfalls & Recovery
- **Terminal/auth failures in sandbox**: If `terminal` fails with `AUTH_ERROR` or similar, stop using it immediately. Do not retry. Pivot to Ghidra MCP tools or ask the user for the correct path.
- **File not found on disk**: The binary may be open in Ghidra but not accessible from the Linux sandbox. Do not loop on `find` or `ls` commands. Work with the Ghidra DB directly.
- **Packed binary with no file access**: If the binary is UPX-packed and you cannot run `upx -d`, state this clearly. Recommend the user unpack it and re-import, or switch to dynamic analysis (e.g., running the binary in a sandbox and dumping memory).
- **Pre-unpacked binary in workspace**: Before asking the user to unpack, quickly check the workspace directory for files named `<original>_unpacked`, `unpacked`, `out_unpacked`, or similar. If one exists, analyze it directly with `objdump`/`nm`/`strings` rather than fighting the packed stub in Ghidra. See `references/upx-packed-workflow.md` for the exact tool sequence and a verification example.
- **Do NOT delegate Ghidra MCP tasks to sub-agents**: Sub-agents spawned via `delegate_task` do NOT have access to MCP tools. They will fail with "invalid tool" errors. Always call `mcp_ghidra_*` tools directly from the orchestrator. If you need parallel work, delegate non-MCP tasks (e.g., Python script writing, OSINT research) to sub-agents while keeping all Ghidra interaction in the main session.
- **Subagent terminal access is unreliable**: Sub-agents may claim they lack `terminal` tool access even when `toolsets=["terminal"]` is specified. They may also fall back to using Ghidra MCP tools (`mcp_ghidra_*`) instead of the requested terminal tool. Do not rely on sub-agents for code execution. Use `cronjob` with `no_agent=True` for script execution, or ask the user to run scripts directly. See `references/subagent-terminal-limitations.md` for the full diagnostic and recovery workflow.
- **Raw data extraction from Ghidra**: `mcp_ghidra_read_resource` fails for arbitrary address reads, and `mcp_ghidra_list_data_items` only shows the first byte of each data item. To verify architecture and see immediate operands, use `mcp_ghidra_disassemble_function` on the entry point — the assembly reveals x86-64 vs AARCH64 instructions and hardcoded constants. For bulk data extraction, write a Python script and execute it via `cronjob` with `no_agent=True` or ask the user to run it.
- **When you cannot execute code directly**: If `cronjob` fails, sub-agents lack terminal access, and `read_file` cannot read the binary (e.g., `.exe` files are blocked), do NOT get stuck in loops trying alternative execution paths. The correct action is:
  1. Write a complete, self-contained Python script to a known path (e.g., `/mnt/c/Users/<user>/extract.py`)
  2. Tell the user the exact command to run: `python3 /mnt/c/Users/<user>/extract.py`
  3. Ask them to paste the output back into the chat
  4. Do NOT waste turns on `send_message`, `vision_analyze` on binaries, or repeated `search_files` — these will hit tool loop guardrails and fail
- **CRITICAL: If the user says "run the extraction script" or similar, and you have already written the script but cannot execute it**: STOP trying alternative execution methods. The user is asking you to do something you cannot do in this environment. Immediately tell the user: "I have written the extraction script at [path]. Please run it with: python3 [path] and paste the output back." Do NOT try cronjobs, sub-agents, or other workarounds — they will fail and waste turns.
- **When the user asks you to run a script and you cannot**: Do NOT ask the user to choose between options or use `clarify`. The user already told you what they want. Just state clearly that you cannot execute scripts in this environment and provide the exact command for them to run.
- **User preference: direct execution over verbose explanations**: When the user asks to run a script, they expect immediate execution, not a detailed explanation of why it might not work. If execution is blocked, provide a single clear command for the user to run, not a list of alternatives or workarounds.
- **Tool loop guardrails — STOP repeating failed calls**: The Hermes runtime enforces progressive blocking on repeated identical tool calls that produce no new information. Hitting these guardrails wastes turns and breaks flow.
  - `idempotent_no_progress_warning`: After ~2 identical searches with the same result, you get a warning. **Action**: use the result you already have.
  - `BLOCKED`: After ~4 identical searches, the tool is blocked with "You already have this information. STOP re-searching and proceed with your task." **Action**: change strategy — ask the user, use a different tool, or proceed with what you know.
  - `same_tool_failure_halt`: After ~4 repeated failures of the same tool call (e.g., `read_file` on a path that doesn't exist or is unchanged), the tool is hard-stopped. **Action**: immediately pivot to a different approach. Do NOT retry the same call — the system will not allow it.
  - **General rule**: If a tool call fails or returns identical results twice, stop repeating it. Formulate a new plan rather than hammering the same endpoint.
  - **CRITICAL**: If you hit `same_tool_failure_halt`, you have ~4 wasted turns and the tool is now completely unavailable. You MUST change your approach entirely. Do not try to work around the halt by calling the same tool with slightly different arguments — the system will detect this as a variant of the same loop.
  - **Example of what NOT to do**: `read_file` on `/mnt/c/Users/el-noir/extraction_result.txt` fails 3 times because the file doesn't exist. Do NOT try `read_file` on `/mnt/c/Users/el-noir/Desktop/extraction_result.txt` or `search_files` for the same file. Instead, ask the user to run the script or pivot to pure Ghidra analysis.
## Reporting Format
After triage, produce a structured report:

## Related Skills
- `vm-binary-analysis` — For custom VM interpreters found in packed binaries
- `advanced_decoder` — Multi-layered string decoding (XOR, Base64, bit-scramble)
- `re-report` — Generate structured final report

## References
- `references/ghidra-mcp-bridge-setup.md` — Ghidra MCP bridge installation, PEP 668 workarounds, and troubleshooting
- `references/upx-packed-workflow.md` — UPX unpacking and verification
- `references/rust-embedded-python-bytecode.md` — Rust binaries that embed XOR-encrypted Python .pyc payloads
- `references/user-assisted-script-execution.md` — When sandbox execution fails: how to write scripts and ask the user to run them
- `references/raw-binary-embedded-firmware.md` — Diagnosing and handling raw binaries / embedded firmware with no auto-analysis
- `references/subagent-terminal-limitations.md` — Subagent `delegate_task` may fail to use terminal tools even when explicitly granted; use `cronjob` with `no_agent=True` instead