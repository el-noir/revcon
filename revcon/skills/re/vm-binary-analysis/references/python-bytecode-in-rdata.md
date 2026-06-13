# Python Bytecode in .rdata — Concrete Recipe

## Context
PE binaries (especially Rust-compiled ones) sometimes embed Python 3.12 bytecode in the `.rdata` section. The bytecode is XOR-encrypted and wrapped in a `.pyc` header.

## Extraction Steps

### 1. Locate the payload in Ghidra
- Use `mcp_ghidra_list_data_items` or `mcp_ghidra_decompile_function` to find the function that references the payload
- Note the payload VA, size, and XOR key from the decompilation

### 2. Parse PE headers to find file offset
```python
import struct

def find_rdata_offset(exe_path):
    with open(exe_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    pe_sig = data[e_lfanew:e_lfanew+4]
    assert pe_sig == b'PE\x00\x00'
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_header_start = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_header_start)[0]
    if magic == 0x10b:
        section_table_start = opt_header_start + 224
    elif magic == 0x20b:
        section_table_start = opt_header_start + 240
    else:
        raise ValueError(f"Unknown magic: {hex(magic)}")
    for i in range(num_sections):
        sec_start = section_table_start + i * 40
        name = data[sec_start:sec_start+8].split(b'\x00')[0].decode('ascii', errors='ignore')
        virtual_address = struct.unpack_from("<I", data, sec_start + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_start + 16)[0]
        raw_offset = struct.unpack_from("<I", data, sec_start + 20)[0]
        if name == ".rdata":
            return raw_offset, virtual_address, raw_size
    raise ValueError(".rdata not found")
```

### 3. Extract and decrypt
```python
rdata_file_offset, rdata_va, rdata_size = find_rdata_offset(exe_path)
payload_offset = rdata_file_offset + (payload_va - rdata_va)
payload = data[payload_offset:payload_offset + payload_size]
decrypted = bytes([b ^ xor_key for b in payload])
```

### 4. Load Python bytecode
```python
import marshal
bytecode = decrypted[16:]  # skip .pyc header
code_obj = marshal.loads(bytecode)
```

### 5. Inspect co_consts
```python
for i, const in enumerate(code_obj.co_consts):
    print(f"[{i}] {type(const).__name__}: {repr(const)[:200]}")
```

Look for:
- A **tuple of integers** (the target array / encoded flag)
- A **64-byte string** (custom Base64 alphabet)
- A **list of 5 integers** (poly_key)

## Reversing the Encoding (crabbymonty.exe pattern)

When the encoding uses a **custom Base64 alphabet** and a **poly_key** applied to a **target tuple of integers**:

1. The target tuple values are often **indices into the custom Base64 alphabet**
2. Build the Base64 string: `b64_custom = "".join([chr(cust_alpha[v]) for v in target_tuple])`
3. Translate to standard Base64 alphabet and decode
4. The decoded bytes may then need arithmetic reversal with `poly_key`

Common reversal attempts:
- Subtraction: `(encoded[i] - poly_key[i % 5]) & 0xff`
- XOR: `encoded[i] ^ poly_key[i % 5]`
- Addition: `(encoded[i] + poly_key[i % 5]) & 0xff`
- Multiplication with modular inverse

## Critical Rules
- **NEVER fabricate a flag**. Only report flags that came from actual script execution output.
- **CTF flags do NOT always start with `flag{`**. The format could be `CRABBY{}`, `CTF{}`, `monty{}`, or anything else.
- If you cannot execute the script synchronously, say: *"I failed to execute — please run this script manually"* and show the script.
- **Python version mismatch**: `marshal.loads()` from 3.12 bytecode will succeed under 3.14, but `dis.dis()` will crash with `IndexError: tuple index out of range`. Do not call `dis.dis()` on foreign-version bytecode. Use manual `co_consts` inspection instead.

## Safe Inspection Pattern (no `dis` module)
When you cannot use `dis.dis()` due to Python version mismatch:

```python
import marshal

code_obj = marshal.loads(bytecode)

# Walk all nested code objects and constants
def scan_consts(obj, path=""):
    if hasattr(obj, 'co_consts'):
        for i, c in enumerate(obj.co_consts):
            scan_consts(c, f"{path}.co_consts[{i}]")
    elif isinstance(obj, tuple):
        print(f"  {path}: tuple len={len(obj)}, types={set(type(x).__name__ for x in obj)}, sample={obj[:5]}")
        for i, item in enumerate(obj):
            scan_consts(item, f"{path}[{i}]")
    elif isinstance(obj, bytes) and len(obj) == 64:
        print(f"  {path}: bytes(64) = {obj}")
    elif isinstance(obj, list) and len(obj) == 5 and all(isinstance(x, int) for x in obj):
        print(f"  {path}: list(5 ints) = {obj}")
    elif isinstance(obj, int) and obj > 0:
        print(f"  {path}: int = {obj}")

scan_consts(code_obj)
```

This avoids the `dis` module entirely and safely extracts all constants regardless of Python version.
