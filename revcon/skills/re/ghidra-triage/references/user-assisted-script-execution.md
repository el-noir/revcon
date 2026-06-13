# User-Assisted Script Execution for RE Tasks

## When to Use This Pattern

Use this approach when:
- The binary is open in Ghidra but the Linux sandbox cannot read the `.exe` file directly (`read_file` blocks `.exe`)
- `cronjob` with `no_agent=True` fails to produce output or cannot access the filesystem
- Sub-agents lack terminal access despite `toolsets=["terminal"]`
- You need to extract/decrypt embedded data from the binary and cannot do it through Ghidra MCP tools alone

## The Pattern

### Step 1: Write a complete, self-contained script

The script should:
- Embed all necessary parameters (file paths, offsets, keys) — do NOT depend on command-line arguments
- Use only standard library modules (no external dependencies like `pefile`, `uncompyle6`)
- Print clear, structured output
- Save outputs to well-known paths (e.g., user's Desktop)

Example template:
```python
#!/usr/bin/env python3
"""Extract embedded payload from PE binary."""
import struct

BINARY_PATH = "/mnt/d/Internship/test/re-agent/workspace/incoming_binaries/TARGET.exe"
OUTPUT_PATH = "/mnt/c/Users/USERNAME/Desktop/extracted.pyc"
DATA_VA = 0x14002b609
SIZE = 0xc2b
XOR_KEY = 0x69

def va_to_file_offset(data, va):
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    pe_sig = data[e_lfanew:e_lfanew+4]
    assert pe_sig == b'PE\x00\x00', "Invalid PE"
    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    size_optional = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    if magic == 0x10b:
        image_base = struct.unpack_from('<I', data, optional + 28)[0]
        section_table = optional + 224
    elif magic == 0x20b:
        image_base = struct.unpack_from('<Q', data, optional + 24)[0]
        section_table = optional + 240
    else:
        raise ValueError(f"Unknown magic: {hex(magic)}")
    rva = va - image_base
    for i in range(num_sections):
        sec_vaddr = struct.unpack_from('<I', data, section_table + i*40 + 12)[0]
        sec_vsize = struct.unpack_from('<I', data, section_table + i*40 + 8)[0]
        sec_foffset = struct.unpack_from('<I', data, section_table + i*40 + 20)[0]
        if sec_vaddr <= rva < sec_vaddr + sec_vsize:
            return sec_foffset + (rva - sec_vaddr)
    raise ValueError("Section not found")

with open(BINARY_PATH, "rb") as f:
    data = f.read()

offset = va_to_file_offset(data, DATA_VA)
encrypted = data[offset:offset + SIZE]
decrypted = bytes([b ^ XOR_KEY for b in encrypted])

with open(OUTPUT_PATH, "wb") as f:
    f.write(decrypted)

print(f"[*] File offset: 0x{offset:x}")
print(f"[*] Decrypted {len(decrypted)} bytes")
print(f"[*] First 20 bytes: {decrypted[:20].hex()}")
print(f"[*] Saved to: {OUTPUT_PATH}")
```

### Step 2: Provide the user with the exact command

Format the message clearly:
```
Please run this command in your WSL terminal and paste the output back:

/usr/bin/python3 /mnt/c/Users/USERNAME/Desktop/extract.py
```

### Step 3: Wait for user output

Do NOT:
- Try `send_message` with platform targets — use plain chat text instead
- Try `vision_analyze` on binary files — it only works on images
- Loop on `search_files` for python3 location — assume `/usr/bin/python3`
- Try alternative execution paths that waste turns

## CRITICAL STOP CONDITION

If the user explicitly asks you to "run the script" or "execute the extraction" and you have already written the script but cannot execute it due to sandbox limitations:

**STOP immediately. Do NOT try:**
- `cronjob` with `no_agent=True` — these often fail silently or never execute
- `delegate_task` with `toolsets=["terminal"]` — sub-agents frequently lack actual terminal access
- `vision_analyze` on binary files — it only works on images, not executables
- Repeated `read_file` on output files that don't exist — this hits tool loop guardrails
- `send_message` to arbitrary platforms — use plain chat text instead

**Alternative: Agent-based cronjob execution**
If you have access to the `cronjob` tool, you can sometimes execute scripts via an agent-based cronjob:
1. Create the job with `no_agent=False`, `deliver='origin'`, and `enabled_toolsets=['terminal']`
2. Give it a minimal prompt: "Run `python3 /path/to/script.py` and return the exact stdout. Do not modify or summarize."
3. Use `cronjob(action='run', job_id=...)` to trigger it immediately
4. Wait for the output to be delivered to chat

**Note**: This is still asynchronous — the output may not arrive within the same conversation turn. If the user is waiting for immediate results, fall back to asking them to run the script directly.

**The correct fallback action is:**
1. State clearly: "I cannot execute scripts directly in this environment."
2. Provide the exact command: `python3 /path/to/script.py`
3. Ask the user to run it and paste the output back
4. Wait for their response before proceeding

## Common Pitfalls

- **Blocked `read_file` on `.exe`**: The `read_file` tool explicitly refuses `.exe` files. Do not try to trick it with different paths or extensions. Accept this limitation and use the user-assisted pattern.
- **Missing Python interpreter**: If the user reports `python3: command not found`, ask them to install it (`sudo apt install python3`) or provide the correct path.
- **Path translation errors**: Windows paths (`D:\...`) must be converted to WSL paths (`/mnt/d/...`) in the script. Double-check this before writing the script.
- **Script dependencies**: Do not assume `pefile`, `uncompyle6`, or other packages are installed. Use only the Python standard library.
