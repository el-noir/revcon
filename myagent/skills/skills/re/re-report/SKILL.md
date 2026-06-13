---
name: re-report
description: Generate a complete, structured reverse engineering report for the currently analyzed binary and save it as a Markdown document file. Triggers when user asks for a "report", "writeup", "document", or "summary" of their analysis.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, ghidra, report, writeup, documentation, mcp]
    category: re
---

# RE Report Generator Skill

## When to Use

Activate this skill whenever the user asks for:
- "make a report"
- "write a writeup"
- "create a document"
- "generate a report on the binary"
- "summarize the analysis"
- "save the findings"

## Output

This skill produces a **Markdown `.md` file** saved to the reports directory.
The path to the saved file is printed at the end so the user can open it.

## Critical Rules

1. **Do NOT ask the user for information you can get from Ghidra tools.** Call the
   MCP tools directly to gather data. The binary is already open in Ghidra.
2. **Do NOT skip sections.** Every section of the report template must be filled in
   with real data, not placeholders.
3. **If a Ghidra tool call fails**, note the failure in that section and continue.
4. **Do NOT verify MCP connectivity with curl/shell.** Call tools directly.

## Report Generation Procedure

### Step 1 — Create the report directory

Use the `terminal` tool to create the output directory if it doesn't exist:

```bash
mkdir -p /mnt/c/Users/el-noir/Downloads/reports
```

### Step 2 — Gather all data from Ghidra

Run these MCP tool calls in sequence and collect all results:

1. `list_imports` — get all imported DLLs and functions
2. `list_exports` — get all exported symbols
3. `list_strings` — get all embedded strings (look for flags, passwords, keys, encoded blobs)
4. `list_functions` — get the full function list (count them, note suspicious names)
5. `search_functions_by_name("main")` — find main entry point
6. `decompile_function(<main_address>)` — get main pseudocode
7. For each interesting function found in main (validation, check, decrypt, encode, flag):
   - `decompile_function(<address>)`
   - `get_xrefs(<address>)`

### Step 3 — Determine the binary name

Ask via a short message: "What is the name of the binary you are analyzing?" 
If the user has already stated it in conversation context, use that. 
Default to `unknown_binary` if no name is provided.

### Step 4 — Build the report content

Assemble the complete Markdown document using the template below.
Fill in every field with real data gathered from the tool calls.

### Step 5 — Save the file

Use `write_file` to write the report. 

**File path format:**
```
/mnt/c/Users/el-noir/Downloads/reports/<binary_name>_report.md
```

Where `<binary_name>` is the binary name (lowercase, spaces replaced with underscores).

### Step 6 — Confirm to the user

After writing, output:
```
✅ Report saved to:
/mnt/c/Users/el-noir/Downloads/reports/<binary_name>_report.md

Open it with any Markdown viewer or text editor.
```

---

## Report Template

Fill this template with real data. Do not leave any section empty.

```markdown
# Reverse Engineering Report — <BINARY_NAME>

**Date:** <current date and time>  
**Analyst:** myagent  
**Tool:** Ghidra (via MCP)  
**Status:** <Complete / Partial — note if .NET or packed>

---

## 1. Executive Summary

<2–4 sentences: what is this binary, what does it do, were any flags or keys found, 
and what is the overall security posture?>

---

## 2. Binary Metadata

| Field             | Value                        |
|-------------------|------------------------------|
| **Format**        | PE32 / PE32+ / ELF64 / .NET  |
| **Architecture**  | x86 / x86-64 / ARM           |
| **Compiler**      | MSVC / GCC / Clang / Unknown |
| **Packer**        | None / UPX / ConfuserEx / ?  |
| **Anti-Debug**    | Yes (list functions) / No    |
| **Anti-VM**       | Yes / No                     |
| **Stack Canary**  | Yes / No                     |
| **PIE/ASLR**      | Yes / No                     |
| **DEP/NX**        | Yes / No                     |

---

## 3. Imports Analysis

**Summary:** <what does the import list tell us about what this binary does?>

### Key Imports

| Library       | Function              | Significance                         |
|---------------|-----------------------|--------------------------------------|
| <dll_name>    | <function_name>       | <what it does / why it matters>      |

### Notable Categories

- **Crypto:** <list any crypto-related imports, or "None found">
- **Anti-Debug:** <list any anti-debug imports, or "None found">
- **Network:** <list any network imports, or "None found">
- **File I/O:** <list any file I/O imports>
- **Memory Ops:** <list any VirtualAlloc, WriteProcessMemory, mmap, etc.>
- **VM / Interpreter:** <list any signs of custom VM: mmap + mprotect, function pointer tables, unusual opcodes>

---

## 4. Strings Analysis

**Summary:** <what do the strings reveal about the binary?>

### Key Strings

| Address      | String                              | Significance                        |
|--------------|-------------------------------------|-------------------------------------|
| <address>    | <string value>                      | <what it means>                     |

### Flag / Key Candidates

<List any strings that look like flags, passwords, keys, or encoded data.
If none found: "No plaintext flags found in strings.">

---

## 5. Entry Point & Control Flow

### Entry Point

```
Address: <address>
Function: <function name>
```

### Main Function — Decompiled Pseudocode

```c
<paste the actual decompiled pseudocode of main here>
```

### Control Flow Summary

<Describe in plain English what main does step by step:
- What input does it take?
- What branches does it have?
- What functions does it call?
- What is the success / failure path?>

---

## 6. Key Functions Analysis

<For each important function (validation, decryption, flag check, VM handler, etc.), 
add a subsection:>

### 6.1 `<function_name>` @ `<address>`

**Purpose:** <one sentence: what does this function do?>

**Called from:** <list of caller addresses/functions from get_xrefs>

**Pseudocode:**

```c
<paste the decompiled pseudocode>
```

**Analysis:**

<Explain the algorithm in plain English:
- What are the inputs?
- What transformations happen? (XOR, strcmp, hash, VM opcode, etc.)
- What does it return and what does that mean?
- What constants or keys are hardcoded?
- For VM handlers: what opcode does this handle, and how does it modify VM state?>

### 6.2 VM Interpreter Structure (if applicable)

**VM Type:** <stack-based / register-based / hybrid>
**Instruction Format:** <e.g., 4 bytes: [opcode, reg, arg1, arg2]>
**Number of Opcodes:** <count>

| Opcode | Handler Address | Operation | Description |
|--------|-----------------|-----------|-------------|
| 0 | `<addr>` | `<operation>` | `<description>` |
| 1 | `<addr>` | `<operation>` | `<description>` |

**Bytecode Location:** `<virtual_address>` → file offset `<offset>`
**Bytecode Size:** `<size>` bytes
**Decryption Algorithm:** `<description or Python code>`

**Flag Check Mechanism:**
<Describe how the VM verifies the flag input:
- Which opcode triggers the check?
- What is the rolling key / comparison method?
- How is the expected input derived from the bytecode?>

---

## 7. Vulnerability / Protection Analysis

| Category             | Finding                                      |
|----------------------|----------------------------------------------|
| **Input Validation** | <is user input validated? how?>              |
| **Buffer Safety**    | <any unbounded copies? fgets vs gets?>       |
| **Crypto Strength**  | <single-byte XOR, RC4, AES? is key static?>  |
| **Obfuscation**      | <any junk code, opaque predicates?>          |
| **Patching Risk**    | <could you NOP the check? patch the jump?>   |

---

## 8. Flags Found

| #   | Flag Value                    | Location / Method                        |
|-----|-------------------------------|------------------------------------------|
| 1   | <flag value>                  | <where it was found and how>             |

<If no flags found: "No flags recovered. See Next Steps.">

### Flag Extraction Method (if applicable)

<If the flag was extracted via algorithm reversal or VM analysis, describe the method:
- Was it a static extraction from decrypted bytecode?
- Was it a dynamic execution or emulation?
- What was the decryption key / rolling key formula?
- What script or tool was used?
>

---

## 9. Algorithm Recreation

<If there is a custom algorithm (XOR, custom hash, etc.), 
write a clean Python script that recreates it:>

```python
# <Binary name> — Flag recovery script
# Generated by myagent

<python code that recovers the flag or implements the algorithm>
```

<If no custom algorithm: "Not applicable — flag was found via plaintext string match.">

---

## 10. Next Steps

<List what would be done next if analysis were to continue:>

- [ ] <next step 1>
- [ ] <next step 2>
- [ ] <next step 3>

---

## 11. Appendix — Full Function List

<paste the full list_functions output here, or a curated table of the most important ones>

---

*Report generated by myagent — Reverse Engineering Analysis Agent*  
*Powered by Hermes + Ghidra MCP*
```

---

## Pitfalls

- **If binary is .NET** (imports `_CorExeMain`): fill in what you can from imports
  and strings, but note clearly in the Executive Summary that Ghidra decompilation
  was not possible and dnSpy/ILSpy is needed for full analysis.
- **If decompile_function fails**: include the error in that section and use
  `list_strings` + `list_imports` data to fill in as much as possible.
- **If the user already ran analysis earlier in the conversation**: use those
  findings — do not call the MCP tools again for data you already have. Just
  format it into the report and save it.
- **NEVER fabricate or guess a flag**: A flag only counts if it came from actual code execution output or confirmed static analysis. If you cannot execute the recovery script and get real output, state clearly in the report: "Flag recovery script written but not executed — run [path] to obtain the flag." Do NOT invent a flag value. CTF flags do NOT always start with `flag{`. The format could be `CRABBY{}`, `CTF{}`, `monty{}`, or anything else. Do not assume.
- **Flag shortcut in strings**: if `list_strings` reveals a full flag like
  `flag{...}`, verify it immediately against the check functions, but also
  inspect any additional checks for hidden/encoded flags (e.g. XOR blobs) so
  the report captures all valid flags.
- **Short-circuit validation**: many crackmes test a plaintext flag first and
  fall back to an encoded/hidden check on mismatch. Report both branches and
  their respective acceptance conditions.
- **VM-based binaries**: If the binary uses a custom VM interpreter, document the
  full VM structure (instruction format, opcode handlers, bytecode location,
  decryption algorithm, and flag check mechanism). See the `vm-binary-analysis`
  skill for the detailed procedure.
- **File write path**: Use the canonical path from Step 5:
  `/mnt/c/Users/el-noir/Downloads/reports/<binary_name>_report.md`
  so the file is accessible from Windows Explorer at
  `C:\Users\el-noir\Downloads\reports\<binary_name>_report.md`.
  (The older duplicated-segment path is incorrect; ignore it.)

## Verification

After the skill runs, the user should:
1. See a confirmation message with the file path
2. Be able to open the file at the Windows path shown above
3. Find the report populated with real data (no placeholder text)
