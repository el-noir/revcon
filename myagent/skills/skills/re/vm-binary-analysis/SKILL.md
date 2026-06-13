---
name: vm-binary-analysis
description: Analyze and extract flags from binaries that use custom virtual machine interpreters with encrypted bytecode. Common in CTF challenges and advanced packers.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, vm, interpreter, bytecode, encryption, ctf]
    category: re
---
# VM-Based Binary Analysis Skill

## When to Use
Use this skill when analyzing a binary that contains a custom virtual machine interpreter.
Triggers:
- Decompilation shows a loop dispatching on opcodes via a function pointer table
- Binary contains encrypted/encoded bytecode that gets decrypted at runtime
- Multiple small handler functions that perform arithmetic/logic on a register array
- Anti-debug (`ptrace`, `IsDebuggerPresent`) combined with `mmap`/`VirtualAlloc` for executable memory

## Analysis Procedure

### Phase 1 — Identify VM Structure
1. **Find the interpreter loop**: Look for a loop that:
   - Reads bytes from a bytecode buffer
   - Extracts an opcode (usually first byte of instruction)
   - Dispatches to a handler via switch-statement or function pointer table
   - Increments a program counter (PC)

2. **Map opcode handlers**: For each handler function:
   - `decompile_function(handler_address)` — understand the operation
   - Common patterns: XOR, ADD, SUB, MOV, S-Box lookup, input read, comparison
   - Rename handlers: `vm_xor`, `vm_add`, `vm_sbox`, `vm_check`, etc.

3. **Identify instruction format**: From the interpreter loop decompilation:
   - Instruction size (commonly 4 bytes: `[opcode, reg, arg1, arg2]`)
   - How operands are extracted (direct bytes, bitfields, immediate values)

### Phase 2 — Locate Encrypted Bytecode
1. **Find the bytecode region**: Look for:
   - Large data arrays in `.rodata`/`.const` sections
   - Data copied to executable memory via `mmap`/`VirtualAlloc`
   - Decryption loops that transform data before execution

2. **Extract the bytecode**:
   - Note the virtual address (e.g., `DAT_100000a20`)
   - Use `list_segments` to map virtual address to file offset
   - For Mach-O/ELF: parse section headers to find exact file offset
   - For PE: use `list_data_items` to find the raw data

3. **Understand the decryption algorithm**:
   - From the decompilation, extract the exact decryption formula
   - Common patterns: XOR with rolling key, RC4-like stream, simple substitution
   - Write a Python script to decrypt the bytecode offline

### Phase 3 — Extract the Flag

#### Method A: Static Extraction (preferred when possible)
1. Decrypt the bytecode using the extracted algorithm
2. Parse instructions using the identified format
3. For flag-checking instructions (usually opcode 0 or a CMP opcode):
   - The expected input bytes are embedded in the instruction operands
   - A rolling key may be derived from the decrypted bytecode itself
   - Reverse the XOR/comparison to recover the expected input

```python
# Common rolling key pattern
def extract_flag(decrypted_bytecode):
    flag = bytearray()
    offset = INITIAL_OFFSET  # from decompilation (e.g., 0x37)
    
    for pc in range(0, len(decrypted_bytecode), INSTRUCTION_SIZE):
        opcode = decrypted_bytecode[pc]
        if opcode == FLAG_CHECK_OPCODE:
            expected = decrypted_bytecode[pc:pc+4]
            
            # Rolling key derived from bytecode
            for j in range(4):
                key_byte = decrypted_bytecode[(offset + j) % len(decrypted_bytecode)]
                rotated = rol(key_byte, ROTATION_BITS)  # e.g., rotate left by 3
                xor_key = (pc + j) ^ rotated
                flag.append(expected[j] ^ xor_key)
        
        offset = (offset + OFFSET_INCREMENT) % len(decrypted_bytecode)
    
    return bytes(flag)
```

#### Method A1 — Challenge-Response VM Pattern (fusion-style)
Some VMs use a challenge-response protocol over a file descriptor:
- The binary reads an initial input (e.g., 34 bytes) into a register array
- The VM loop processes instructions; some opcodes cause the VM to **write** a 4-byte challenge back to the peer
- Other opcodes (function pointer == NULL) cause the VM to **read** a 4-byte response from the peer
- The response is encrypted with a rolling keystream derived from the decrypted bytecode

**Key structures to identify:**
1. **Instruction format**: `[opcode, reg_idx, arg1, arg2]` (4 bytes)
2. **Function pointer table**: 5-10 handlers mapped to opcodes (e.g., opcodes 0x80-0x84)
3. **Opcode 0x00 or NULL handler**: Triggers the read path — peer must respond with `[offset_lo, offset_hi, reg_idx, value]` encrypted with the keystream
4. **Keystream derivation**: `keystream_byte = ROL(decrypted_bytecode[keystream_offset], 3) ^ (instruction_offset + byte_index)`
5. **Keystream offset increment**: Typically `0x1c` (28) per instruction, with `0xd` (13) per byte within the 4-byte response
6. **Magic number modulo**: The keystream offset wraps around using a fast modulo: `offset % bytecode_size` computed via multiplication by a magic constant (e.g., `0x27c45979c95204f9` for mod 0x338)

**Flag recovery approach:**
- The initial 34-byte input is the flag
- The VM transforms it through the 5 operations (XOR, S-Box, etc.)
- For each READ_PEER instruction, the expected value is the result of prior computations on the flag bytes
- To recover the flag, emulate the VM forward with symbolic or concrete values, tracking which register holds which flag byte
- When a READ_PEER instruction expects a specific value, derive the constraint on the flag bytes
- Solve the system of constraints (usually linear XOR equations) to recover the flag

#### Method B: Dynamic Execution
If static extraction is too complex:
1. Set up the binary's expected environment (e.g., `FUSION_PEER_FD` env var)
2. Run the binary with a known input or use a debugger
3. Hook the VM interpreter to log instructions
4. Extract the comparison values at runtime

### Phase 4 — Verify and Report
1. Check if extracted bytes form a printable flag (e.g., `flag{...}`, `picoCTF{...}`)
2. If not printable, verify:
   - Decryption algorithm is correct (re-check against decompilation)
   - Instruction parsing matches the VM format
   - Rolling key parameters (offset, increment, rotation) are correct
3. Report the flag and the VM structure for documentation

## Pitfalls & Recovery
- **Wrong file offset**: Mach-O/ELF section virtual addresses don't always match file offsets. Use `list_segments` or parse section headers to find the correct offset. **CRITICAL for fat Mach-O**: The binary may contain multiple slices (x86-64, AARCH64) at different file offsets. Always parse the fat header first! See `references/macho-section-offsets.md`.
- **PE .rdata section extraction**: For Windows PE binaries, the encrypted payload is often in the `.rdata` section. To extract it:
  1. Parse the DOS header to find the PE header offset (at offset 0x3c)
  2. Parse the COFF header to get the number of sections and optional header size
  3. Parse the section table to find `.rdata` (Name, VirtualAddress, PointerToRawData)
  4. Calculate file offset: `PointerToRawData + (payload_VA - ImageBase - VirtualAddress)`
  5. Read the payload bytes directly from the binary file
  See `references/pe-rdata-extraction.md` for a complete Python script.
- **Python bytecode in .rdata**: Some binaries embed Python bytecode (`.pyc` format) in `.rdata`. After XOR/decryption:
  1. Verify the 16-byte `.pyc` header: `\xcb\r\r\n` for Python 3.12
  2. Skip the 16-byte header and use `marshal.loads()` to load the code object
  3. Inspect `co_consts` for standard/custom Base64 alphabets and target arrays
  4. Reverse the custom Base64 checking logic to recover the flag
  See `references/python-bytecode-in-rdata.md` for the full workflow.
- **Decryption byte wraparound**: In rolling-key decryption loops, the key variable is often a byte that wraps around (e.g., `key = (key + 0xa7) & 0xff`). Using `(i * 0xa7)` without wraparound produces incorrect decryption. Always check the decompilation for the variable type.
- **Decryption key mismatch**: The rolling key may use `vm_pc` (instruction index) or `byte_offset` (byte index). Check the decompilation carefully — mixing these produces garbage.
- **Opcode 0 as NULL**: In some VMs, opcode 0 is a "no-op" or "end-of-program" marker. The actual flag check may use a different opcode or be triggered by a special condition. Look for the input-reading syscall (`read`, `recv`) in the handler functions.
- **Environment dependencies**: The binary may require specific environment variables (e.g., `FUSION_PEER_FD`) or file descriptors to run. Check the entry function for `getenv` or `fcntl` calls.
- **Do NOT delegate Ghidra MCP tasks**: Sub-agents cannot access MCP tools. Call `mcp_ghidra_*` functions directly from the orchestrator. See `ghidra-triage` skill for details.
- **Do NOT delegate terminal tasks to subagents**: Sub-agents may claim they lack `terminal` tool access even when `toolsets=["terminal"]` is specified. They may also fall back to using Ghidra MCP tools instead of the requested terminal commands. Do not rely on sub-agents for filesystem exploration, `file`/`strings`/`xxd` analysis, or Python script execution. Use `cronjob` with `no_agent=True` for script execution, or ask the user to run scripts directly. See `ghidra-triage/references/subagent-terminal-limitations.md` for the full diagnostic and recovery workflow.
- **Avoid idempotent_no_progress_block on search_files**: Repeated identical `search_files` calls will hit a guardrail after 5 attempts and return the same result. If a search times out or returns no results, CHANGE the query parameters (different path, pattern, or target) or switch to a different tool like `read_file` or `list_files` instead of repeating the same call.
- **SBOX computation**: Raw tables extracted from the binary are NOT the final SBOXes. They must be combined using the VM's formula (e.g., `TABLE1[i] ^ TABLE2[i ^ 0xa3]`). Using raw tables directly produces incorrect results and UNSAT.
- **Target identification**: The "target" bytes in the binary are often an encrypted string, not the comparison target. Trace the ARM slice's exit block to find the true hash comparison (e.g., FNV-1a).
- **NEVER fabricate or guess a flag**: If you cannot execute code and get real output, you MUST say "I failed to execute — please run this script manually" and show the script. A flag only counts if it came from actual code execution output — not from your own reasoning or generation. CTF flags do NOT always start with `flag{`. The format could be `CRABBY{}`, `CTF{}`, `monty{}`, or anything else. Do not assume.
- **Script execution environment**: Sub-agents may lack terminal access. Cronjobs with `no_agent=True` and `deliver=local` run in isolated environments and do NOT return output to chat. The reliable workaround is:
  1. Create an agent-based cronjob (`no_agent=False`) with `deliver=origin` and `enabled_toolsets=["terminal"]`
  2. Give it a minimal prompt: "Run `python3 /path/to/script.py` and return the exact stdout. Do not modify or summarize."
  3. If the agent-based cronjob also fails, be honest: "I failed to execute — please run this script manually" and show the script.
- **Pivoting from Ghidra to manual extraction**: When Ghidra MCP cannot provide raw bytes (e.g., `mcp_ghidra_read_resource` fails with "Unknown resource"), do not loop on the same failing calls. Instead:
  1. Use `mcp_ghidra_disassemble_function` to confirm the payload address and size
  2. Switch to direct binary file parsing to extract the payload
  3. If the binary file is inaccessible via MCP filesystem tools, ask the user to run a local extraction script
  See `references/pe-rdata-extraction.md` for the extraction script.
- **Python version mismatch for marshal/dis**: When the embedded bytecode was compiled for Python 3.12 (header `\xcb\r\r\n`), running `marshal.loads()` under Python 3.14 will succeed, but `dis.dis()` will crash with `IndexError: tuple index out of range` because the 3.14 disassembler cannot handle 3.12 wordcode. To avoid this:
  1. Never call `dis.dis()` on foreign-version bytecode
  2. Instead, manually inspect `co_consts`, `co_varnames`, `co_names`, and `co_code` (as raw hex) to understand the structure
  3. If you need full disassembly, extract the `.pyc` file and run `python3.12 -m dis file.pyc` in a subprocess, or ask the user to do it
  See `references/python-bytecode-in-rdata.md` for the safe inspection pattern.

## Related Skills
- `ghidra-triage` — Initial binary fingerprinting and entry point analysis
- `advanced_decoder` — Multi-layered string decoding (XOR, Base64, bit-scramble)
- `re-report` — Generate structured final report

## References
- `references/macho-section-offsets.md` — Mapping Mach-O virtual addresses to file offsets
- `references/vm-bytecode-patterns.md` — Common VM instruction formats and handler patterns
- `references/challenge-response-vm-pattern.md` — Detailed pattern for challenge-response VMs (fusion-style) with encrypted bytecode, rolling keystream, and peer file descriptor communication
- `references/z3-solver-vm-example.md` — Corrected Z3 symbolic execution approach with If-chain SBOXes, FNV-1a hash constraints, and true SBOX computation (TABLE1[i] ^ TABLE2[i^0xa3])
- `scripts/extract_vm_bytecode.py` — Template Python script to extract and decrypt VM bytecode from a binary file
- `scripts/z3_vm_solver_template.py` — Generic Z3 solver template for VM challenges (customize opcodes, SBOXes, and constraints)
- `scripts/inspect_python_bytecode_safe.py` — Safe Python bytecode inspector that avoids `dis.dis()` crashes across Python versions. Extracts and inspects `co_consts` from PE `.rdata` XOR-encrypted payloads.
