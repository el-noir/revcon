# Z3 Solver VM Example — Fusion-Style Challenge

## Overview
This is a concrete example of using Z3 to solve a VM-based challenge statically. The approach demonstrates symbolic execution of VM bytecode to recover a flag, with specific techniques for handling S-BOX lookups and hash-based constraints.

## Key Components

### S-BOX Tables
Two 256-byte S-BOX tables (one for x86, one for ARM) computed as:
```
SBOX(val) = TABLE1[val] ^ TABLE2[val ^ 0xa3]
```
**CRITICAL**: The raw tables extracted from the binary are NOT the S-BOXes directly. They must be combined using the formula above.

### Bytecode
Encrypted bytecode that gets executed by the VM interpreter. The true bytecode length is 0x334 (820 bytes = 205 instructions), not the truncated version that may appear in initial extractions.

### Instruction Format (4 bytes)
```
[opcode, dst_reg, src1_reg, src2_or_imm]
```

Common opcodes:
- `0x10` — XOR reg,reg -> reg (ARM)
- `0x11` — XOR reg,imm -> reg (ARM)
- `0x12` — SBOX_ARM[reg] -> reg (ARM)
- `0x13` — reg[dst] += reg[op1] + imm (ARM)
- `0x15` — reg[op1] + reg[op2] -> reg (ARM)
- `0x80` — XOR reg,reg -> reg (x86)
- `0x81` — XOR reg,imm -> reg (x86)
- `0x82` — SBOX_X86[reg] -> reg (x86)
- `0x83` — reg[dst] ^= reg[op1] ^ imm (x86)

### Target Constraint (NOT a target buffer!)
The "target constant" extracted from the binary is often an encrypted string that the VM prints upon exit (e.g., "fusion> peer-only slice.."). **DO NOT** constrain the final registers to match this string — it will always be UNSAT.

Instead, the true comparison is typically a hash function (e.g., FNV-1a) over the output registers XORed with a key:
```python
FNV_OFFSET = 0xcbf20420d6b784b5
FNV_PRIME = 0x00000100001b3b93
TARGET_HASH = 0xa7243aa137436677

h = FNV_OFFSET
for i in range(34):
    val = reg[0x22 + i] ^ ARM_XOR_KEY[i]
    h = ((h ^ val) * FNV_PRIME) & 0xffffffffffffffff
assert h == TARGET_HASH
```

## Z3 Symbolic Execution Approach

### 1. If-Chain S-BOX Lookup (Recommended)
For Z3 symbolic execution, use If-chain S-BOX lookups instead of Z3 Arrays. Arrays are slower and can cause solver timeouts:

```python
def make_sbox_fn(table):
    def apply(bv8):
        expr = z3.BitVecVal(table[255], 8)
        for i in range(254, -1, -1):
            expr = z3.If(bv8 == i, z3.BitVecVal(table[i], 8), expr)
        return expr
    return apply
```

### 2. Symbolic Register Initialization
```python
flag_syms = [z3.BitVec(f"f{i}", 8) for i in range(34)]
regs = {}
for i in range(34):
    regs[i] = flag_syms[i]
# All other registers default to 0 (concrete)
```

### 3. VM Emulation
Process each 4-byte instruction linearly, updating symbolic register expressions. For ADD operations, truncate to 8 bits using `Extract(7, 0, ...)`.

### 4. Hash Constraint
Build the FNV-1a hash expression symbolically and constrain it to the target hash:
```python
h = z3.BitVecVal(FNV_OFFSET, 64)
prime64 = z3.BitVecVal(FNV_PRIME, 64)
for i in range(34):
    key_byte = z3.BitVecVal(ARM_XOR_KEY[i], 64)
    val8 = z3.ZeroExt(56, out_regs[i])  # zero-extend 8->64 bits
    val64 = val8 ^ key_byte
    h = (h ^ val64) * prime64
s.add(h == z3.BitVecVal(TARGET_HASH, 64))
```

## Why This Works
The VM bytecode is linear (no branches, no loops) — each instruction simply transforms register values. This makes it perfect for Z3 symbolic execution because:
- No path explosion (single execution path)
- All operations are bit-vector friendly (XOR, ADD, S-BOX lookups)
- The constraints are mostly linear and easy for Z3 to solve

## Running the Script
```bash
pip3 install z3-solver
python3 fusion_solver.py
```

## Output
```
[*] Building SBOX If-chains...
[*] SBOXes ready.
[*] Symbolically executing VM...
[*] VM execution done. Building constraints...
[*] Solving...
[+] FLAG: flag{...}
```

## Critical Lessons Learned

### Data Correctness
1. **S-BOX computation**: Raw tables from the binary must be combined with `TABLE1[i] ^ TABLE2[i ^ 0xa3]`. Using raw tables directly produces incorrect results.
2. **Bytecode length**: Ensure the full decrypted bytecode is extracted (0x334 bytes). Truncated bytecode will produce UNSAT.
3. **Target identification**: The "target" bytes in the binary are often an encrypted string, not the comparison target. Trace the ARM slice's exit block to find the true hash comparison.

### Execution Environment
1. **Sub-agent terminal access is unreliable**: Sub-agents may claim they lack terminal access or fall back to wrong tools. Always verify they can actually execute commands.
2. **Cronjob execution**: Cronjobs with `no_agent=True` may fail silently or run in isolated environments. Do not rely on them for critical execution.
3. **Direct execution**: When automated execution fails, create self-contained scripts and ask the user to run them directly. Embed all data in the script to avoid dependency issues.

### Solver Performance
1. **If-chain vs Array**: If-chain S-BOX lookups are faster than Z3 Arrays for this use case.
2. **Timeout**: Set a reasonable timeout (e.g., 5 minutes) and handle UNKNOWN results.
3. **Printable ASCII**: Constrain flag bytes to printable ASCII range (0x20-0x7e) to reduce search space.
