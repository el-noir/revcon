---
name: shellcode_emulator
description: Emulates raw shellcode (x86/x64/ARM) using Unicorn Engine to trace its execution, register changes, and memory accesses without executing it on the real CPU.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, shellcode, emulation, unicorn]
    category: re
---
# Shellcode Emulator Skill

## When to Use
Use this skill when you extract a suspicious blob of hex bytes from Ghidra that appears to be shellcode. Shellcode often obfuscates its purpose and resolves APIs dynamically. Emulating it allows you to observe its behavior safely.
Trigger: user says "emulate this shellcode" or when the main agent identifies an injected payload.

## Prerequisites
- The raw shellcode as a hex string or a binary file path.
- This skill runs inside the Modal cloud sandbox.
- Requires `unicorn` and `capstone` (install dynamically with `pip install unicorn capstone`).

## Python Implementation Template
```python
try:
    from unicorn import *
    from unicorn.x86_const import *
    from capstone import *
except ImportError:
    import subprocess
    subprocess.check_call(["pip", "install", "unicorn", "capstone"])
    from unicorn import *
    from unicorn.x86_const import *
    from capstone import *

import sys
import struct

# Example shellcode: \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
shellcode_hex = "<INSERT_SHELLCODE_HEX_HERE>"
shellcode = bytes.fromhex(shellcode_hex)

# Constants
ADDRESS = 0x1000000
STACK_ADDR = 0x2000000
STACK_SIZE = 2 * 1024 * 1024
CODE_SIZE = 2 * 1024 * 1024

# Setup Capstone for disassembly
md = Cs(CS_ARCH_X86, CS_MODE_32) # Change to CS_MODE_64 if x64

print("[*] Initializing Unicorn Engine (x86 32-bit)...") # Adjust as needed
try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map memory for code and stack
    mu.mem_map(ADDRESS, CODE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # Write machine code to be emulated to memory
    mu.mem_write(ADDRESS, shellcode)

    # Set up the stack pointer
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE // 2)

    # Hook for instruction tracing
    def hook_code(uc, address, size, user_data):
        mem = uc.mem_read(address, size)
        for i in md.disasm(mem, address):
            print(f">>> Tracing instruction at 0x{address:x}: {i.mnemonic} {i.op_str}")

    mu.hook_add(UC_HOOK_CODE, hook_code)

    print("[*] Emulating shellcode...")
    # Start emulation
    mu.emu_start(ADDRESS, ADDRESS + len(shellcode))

    print("[+] Emulation complete.")

except UcError as e:
    print(f"[-] Emulation failed: {e}")
```

## Reporting Format
Provide the trace of the executed instructions. Highlight any API resolution attempts, memory writes, or specific syscalls. Explain what the shellcode is trying to achieve based on the trace.
