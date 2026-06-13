# Rust Binaries with Embedded Python Bytecode

## Pattern Description
Some Rust binaries embed XOR-encrypted Python `.pyc` bytecode and execute it by spawning a Python interpreter process. The Rust code acts as a loader/stub that decrypts the bytecode, writes it to a temp file, and runs it with `python`, `python3`, `python3.12`, or `py`.

## Detection in Ghidra

### Imports to look for
- `CreateProcessW` — spawning Python interpreter
- `GetTempPathW` / `GetTempFileNameW` — creating temp file for .pyc
- `WriteFile` — writing decrypted bytecode
- `DeleteFileW` — cleaning up temp file

### Strings to look for
- `"*.pyc"` — the embedded Python file name (e.g., `"bruhmemegang.pyc"`)
- `"python"`, `"python3"`, `"python3.12"`, `"py"` — interpreter search paths
- Rust panic strings (`"called \`Result::unwrap()\` on an \`Err\` value"`) — indicates Rust binary

### Decompilation patterns
The Rust `main` function typically shows:

1. **Encrypted data blob**: A large byte array at a data address (e.g., `DAT_14002b609`)
2. **XOR decryption loop**: Simple XOR with a constant key (e.g., `0x69`)
   ```c
   for (i = 0; i < 0xc2b; i++) {
       decrypted[i] = encrypted[i] ^ 0x69;
   }
   ```
3. **Temp file creation**: Writes decrypted data to `%TEMP%\bruhmemegang.pyc`
4. **Python interpreter search**: Tries multiple Python executables in order
5. **Process spawn**: `CreateProcessW` with the .pyc as argument

## Extraction Procedure

### Step 1: Find the encrypted data address
From decompilation, note the data address (e.g., `DAT_14002b609`) and the size (e.g., `0xc2b` bytes).

### Step 2: Map virtual address to file offset
For PE binaries:
- Parse the PE section table to find which section contains the data address
- Calculate: `file_offset = section_file_offset + (data_rva - section_virtual_address)`

### Step 3: Extract and decrypt
Write a Python script to extract the bytes. If you cannot execute it directly (e.g., `read_file` blocks `.exe` files, sub-agents lack terminal access), use the user-assisted execution pattern from `references/user-assisted-script-execution.md`.

```python
#!/usr/bin/env python3
import struct

def extract_pyc_from_pe(binary_path, data_rva, size, xor_key):
    with open(binary_path, "rb") as f:
        data = f.read()
    
    # Parse PE header
    pe_offset = struct.unpack("<I", data[0x3c:0x40])[0]
    num_sections = struct.unpack("<H", data[pe_offset+0x6:pe_offset+0x8])[0]
    section_table = pe_offset + 0x178  # PE32+ header size
    
    # Find section containing data_rva
    for i in range(num_sections):
        sec_vaddr = struct.unpack("<I", data[section_table + i*0x28 + 0xc:section_table + i*0x28 + 0x10])[0]
        sec_vsize = struct.unpack("<I", data[section_table + i*0x28 + 0x8:section_table + i*0x28 + 0xc])[0]
        sec_foffset = struct.unpack("<I", data[section_table + i*0x28 + 0x14:section_table + i*0x28 + 0x18])[0]
        
        if sec_vaddr <= data_rva < sec_vaddr + sec_vsize:
            file_offset = sec_foffset + (data_rva - sec_vaddr)
            encrypted = data[file_offset:file_offset + size]
            decrypted = bytes([b ^ xor_key for b in encrypted])
            return decrypted
    
    return None

# Example usage
pyc_data = extract_pyc_from_pe("crabbymonty.exe", 0x2b609, 0xc2b, 0x69)
with open("/tmp/extracted.pyc", "wb") as f:
    f.write(pyc_data)
```

### Step 4: Analyze the .pyc file
Use `uncompyle6`, `decompyle3`, or `pycdc` to decompile the .pyc back to Python source:
```bash
uncompyle6 /tmp/extracted.pyc > /tmp/extracted.py
# or
pycdc /tmp/extracted.pyc > /tmp/extracted.py
```

## Why this pattern matters
- The actual challenge logic is in the Python code, not the Rust stub
- The Rust binary is just a delivery mechanism — the flag check, crypto, or VM is in Python
- Decompiling the .pyc reveals the real challenge

## Real-World Example: crabbymonty.exe

**Binary**: `crabbymonty.exe` (Rust binary, x86-64, MSVC)
**Embedded file**: `bruhmemegang.pyc` (Python 3.12 bytecode)
**Encrypted data**: `DAT_14002b609`, size `0xc2b` (3115 bytes)
**XOR key**: `0x69`
**Python interpreter search order**: `py`, `python3.12`, `python3`

### Key Ghidra findings
- `list_data_items` revealed: `s_bruhmemegang.pyc_14002c234 = "bruhmemegang.pyc"`
- `list_data_items` revealed: `s_python3.12_14002c24b = "python3.12"`, `s_python3_14002c255 = "python3"`
- `list_data_items` revealed: `s_pythonsrc\main.rs_14002c25c = "pythonsrc\main.rs"` (confirms Rust source)
- Decompilation of `FUN_140001720` showed the XOR decryption loop and process spawn logic
- The first encrypted byte `DAT_14002b609 = A2h` decrypts to `0xA2 ^ 0x69 = 0xCB`, which is the Python 3.12 .pyc magic number

### Extraction script (for user execution)
```python
#!/usr/bin/env python3
import struct

BINARY = "/mnt/d/Internship/test/re-agent/workspace/incoming_binaries/crabbymonty.exe"
OUTPUT = "/mnt/c/Users/el-noir/Desktop/bruhmemegang.pyc"
DATA_VA = 0x14002b609
SIZE = 0xc2b
XOR_KEY = 0x69

with open(BINARY, "rb") as f:
    data = f.read()

pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
section_table = pe_offset + 24 + opt_header_size
image_base = struct.unpack_from('<Q', data, pe_offset + 24 + 24)[0]
rva = DATA_VA - image_base

for i in range(num_sections):
    sec_offset = section_table + i * 40
    name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vaddr = struct.unpack_from('<I', data, sec_offset + 12)[0]
    vsize = struct.unpack_from('<I', data, sec_offset + 8)[0]
    foffset = struct.unpack_from('<I', data, sec_offset + 20)[0]
    if name == ".rdata" and vaddr <= rva < vaddr + vsize:
        file_offset = foffset + (rva - vaddr)
        encrypted = data[file_offset:file_offset + SIZE]
        decrypted = bytes([b ^ XOR_KEY for b in encrypted])
        with open(OUTPUT, "wb") as f:
            f.write(decrypted)
        print(f"[*] Extracted {len(decrypted)} bytes to {OUTPUT}")
        print(f"[*] First 4 bytes: {decrypted[:4].hex()}")
        break
```

## Related patterns
- **UPX-packed Python**: Similar but uses UPX compression instead of XOR
- **PyInstaller executables**: Embed Python interpreter + bytecode, but use a different structure
- **.NET + Python**: Less common, but possible with IronPython or similar
