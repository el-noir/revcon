# Challenge-Response VM Pattern (fusion-style)

## Overview
This pattern appears in CTF binaries where the program communicates with a peer over a file descriptor (set via `FUSION_PEER_FD` env var). The binary contains a custom VM that processes input bytes and exchanges challenge-response messages with the peer.

## Binary Structure

### Entry Point Behavior
1. `ptrace(0x1f, 0, 0, 0)` — anti-debug (PTRACE_TRACEME)
2. `mmap(0, 0x338, 3, 0x1002, -1, 0)` — allocate 824 bytes for decrypted bytecode
3. Decrypt bytecode loop:
   ```c
   bVar9 = 0;
   for (i = 0; i < 0x338; i++) {
       decrypted[i] = ((i >> 8) * 'S') ^ bVar9 ^ encrypted[i] ^ 0x4d;
       bVar9 = (bVar9 + 0xa7) & 0xff;  // byte wraparound!
   }
   ```
   **CRITICAL**: `bVar9` is a byte that wraps around. The formula is NOT `(i * 0xa7)` but rather a rolling byte that increments by 0xa7 each iteration with wraparound.
4. Setup 5 VM handler function pointers at offsets 0x470, 0x478, 0x480, 0x488, 0x490
5. Read 34 bytes (0x22) from `FUSION_PEER_FD` into register array
6. Run VM loop until opcode 0xff (halt)

### VM Handler Functions
| Address | Operation | Formula |
|---------|-----------|---------|
| 0x926 | XOR_REG | `reg[arg2] ^ reg[arg1]` |
| 0x940 | XOR_IMM | `arg2 ^ reg[arg1]` |
| 0x955 | S-BOX | `lookup2[reg[arg1]] ^ lookup1[reg[arg1] ^ 0xa3]` |
| 0x985 | XOR3 | `arg2 ^ reg[reg_idx] ^ reg[arg1]` |
| 0x99f | IDENTITY | `reg[arg1]` |

### Instruction Format
4 bytes: `[opcode, reg_idx, arg1, arg2]`

- **Opcode mapping**: Function pointers stored at `DAT_100002470 + (opcode - 0x80) * 8`
  - Opcode 0x80 → XOR_REG
  - Opcode 0x81 → XOR_IMM
  - Opcode 0x82 → S-BOX
  - Opcode 0x83 → XOR3
  - Opcode 0x84 → IDENTITY
  - Opcode 0x00 → NULL (read from peer)

### VM Loop Behavior
```c
for (pc = 0; pc < 0x334; pc += 4) {
    opcode = bytecode[pc];
    if (opcode == 0xff) break;
    reg_idx = bytecode[pc + 1];
    arg1 = bytecode[pc + 2];
    arg2 = bytecode[pc + 3];
    
    if (handler_table[opcode] == NULL) {
        // READ path: read 4 bytes from peer, decrypt, verify
        read(fd, &buf, 4);
        decrypt_buffer(buf, pc, keystream_offset);
        if (buf.offset != pc) return 4;
        if (buf.reg_idx != reg_idx) return 4;
        reg[reg_idx] = buf.value;
    } else {
        // WRITE path: compute, store, encrypt, write back
        result = handler(opcode, reg_idx, arg1, arg2);
        reg[reg_idx] = result;
        buf.offset = pc;
        buf.reg_idx = reg_idx;
        buf.value = result;
        encrypt_buffer(buf, pc, keystream_offset);
        write(fd, &buf, 4);
    }
    keystream_offset += 0x1c;
}
```

### Keystream Derivation
The encryption/decryption uses a keystream derived from the decrypted bytecode:

```c
for (j = 0; j < 4; j++) {
    key_byte = decrypted_bytecode[(keystream_offset + j * 0xd) % 0x338];
    rotated = (key_byte << 3) | (key_byte >> 5);  // ROL by 3
    decrypted[j] = received[j] ^ (pc + j) ^ rotated;
}
```

The modulo operation uses a fast division by multiplication:
```c
// Compute offset % 0x338 using magic number 0x27c45979c95204f9
quotient = (offset >> 3) * 0x27c45979c95204f9 >> 4;
remainder = offset - quotient * 0x338;
```

### Data Layout in Binary
**IMPORTANT**: For fat Mach-O binaries, the file offsets are relative to each slice:
- `0x100000a00` — Error message string (25 bytes, encrypted)
- `0x100000a20` — Encrypted VM bytecode (0x338 = 824 bytes)
- `0x100000d60` — Lookup table 1 (256 bytes)
- `0x100000e60` — Lookup table 2 (256 bytes)
- `0x100002010` — Register array (34 bytes for flag input)
- `0x100002470` — Function pointer table (5 entries)

**Fat Mach-O slice offsets** (fusion binary example):
- x86-64 slice: file offset `0x4000`
- AARCH64 slice: file offset `0xc000`
- Absolute file offset for bytecode = `slice_offset + 0xa20`

## Flag Recovery Strategy

1. **Parse the fat Mach-O header** to find slice offsets
2. **Extract encrypted bytecode** from the correct file offset for each slice
3. **Decrypt bytecode** using the rolling key algorithm with byte wraparound
4. **Parse instructions** to identify the sequence of operations
5. **Emulate the VM symbolically**:
   - Track which registers hold which flag bytes
   - For each READ_PEER instruction, the expected value is the result of prior computations
   - Derive linear equations (mostly XOR) relating flag bytes
6. **Solve the constraint system** to recover the 34-byte flag

## Common Pitfalls
- **Architecture confusion**: The Mach-O may contain both x86-64 and AARCH64 slices. Use `disassemble_function` on the entry point to confirm which architecture is currently active in Ghidra — the assembly reveals x86-64 (RBP, RSP) vs AARCH64 (X29, X30) registers.
- **Fat binary offsets**: Always parse the fat header to get the correct slice offset before reading data. The virtual address 0x100000a20 does NOT map to file offset 0xa20 in a fat binary!
- **Decryption byte wraparound**: The `bVar9` variable in the decryption loop is a byte that wraps around. Using `(i * 0xa7)` without `& 0xff` produces incorrect decryption.
- **Keystream offset wrapping**: The offset wraps at 0x338, but the increment is 0x1c per instruction and 0xd per byte. Be careful with modulo arithmetic.
- **Opcode 0x00 as NULL**: Don't assume all opcodes map to handlers. Opcode 0x00 explicitly triggers the read path.
- **Environment variable**: The binary requires `FUSION_PEER_FD` to be set. Without it, the binary prints an error message and exits with code 2.
