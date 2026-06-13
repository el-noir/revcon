# UPX-Packed Binary — Workspace Enumeration Workflow

## Context
Ghidra's decompiler often fails on UPX-packed stubs (bad instruction data, truncated control flow). If the binary is already unpacked on disk, skip the stub entirely.

## Quick Check
1. After `list_strings` / `list_data_items` reveals UPX markers (`$Info: This file is packed with the UPX executable packer`), check the workspace directory for companion files:
   - `<name>_unpacked`
   - `out_unpacked`
   - `unpacked`
   - Any file with the same base name and a different extension

2. Use `file` and `strings` on the candidate to confirm it is the same binary, unpacked.

## Static Analysis of Unpacked Binary (without Ghidra reload)
If the unpacked binary is valid but you do not want to (or cannot) re-import it into Ghidra, use Linux binutils directly:

| Tool | Purpose | Example |
|------|---------|---------|
| `nm` | List symbols, find `main` | `nm binary \| grep main` |
| `objdump -d` | Disassemble around `main` | `objdump -d --start-address=0x401d65 --stop-address=0x402000 binary` |
| `objdump -s` | Dump string / rodata sections | `objdump -s --start-address=0x495000 --stop-address=0x495100 binary` |
| `strings -a -t x` | Extract strings with file offsets | `strings -a -t x binary \| grep flag` |
| `readelf -r` | Show relocations / GOT entries | `readelf -r binary \| grep 4c007` |

## Verification
Once the password or flag is recovered, run the binary interactively to confirm:
```python
import subprocess
result = subprocess.run([binary_path], input=password + "\n", capture_output=True, text=True)
print(result.stdout)
```

## Pitfall
- `fgets` includes the trailing newline (`\n`). When testing passwords via `subprocess.run`, pass `input=password` (no newline) if the program uses `strncmp` with a fixed length, or strip the newline from the buffer in your test script.
