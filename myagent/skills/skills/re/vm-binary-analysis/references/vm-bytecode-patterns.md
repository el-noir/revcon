# VM Bytecode Patterns in Reverse Engineering

## Common VM Instruction Formats

### Format 1: 4-Byte Fixed Width `[opcode, reg, arg1, arg2]`
**Example:** Fusion binary (macOS Mach-O x86-64)
- Byte 0: opcode (0-4)
- Byte 1: register index
- Byte 2: argument 1 (immediate or register index)
- Byte 3: argument 2 (immediate or register index)

**Opcode Mapping:**
| Opcode | Operation | Description |
|--------|-----------|-------------|
| 0 | `regs[arg2] ^ regs[arg1]` | XOR two registers, also used for flag check |
| 1 | `arg2 ^ regs[arg1]` | XOR immediate with register |
| 2 | `SBOX[regs[arg1]]` | S-Box substitution |
| 3 | `arg2 ^ regs[arg1] ^ regs[arg2]` | 3-way XOR |
| 4 | `regs[arg1]` | MOV register |

### Format 2: Variable Width (prefix + operands)
- Byte 0: opcode + operand count (e.g., upper 4 bits = opcode, lower 4 bits = operand count)
- Following bytes: operands based on count

### Format 3: Word-Aligned (32-bit instructions)
- Each instruction is 4 bytes, aligned to 4-byte boundary
- Opcode in bits 24-31, operands in remaining bits

## Common Handler Patterns

### Pattern 1: Register Array
```c
// VM state
uint64_t regs[16];      // Register file
uint8_t *bytecode;      // Code segment
uint8_t *memory;        // Data segment
size_t pc;              // Program counter

// Handler signature
void handler(uint8_t reg, uint8_t arg1, uint8_t arg2) {
    regs[reg] = OPERATION(regs[arg1], arg2);
}
```

### Pattern 2: Stack-Based
```c
void push(uint64_t value);
uint64_t pop(void);

// ADD handler
void op_add() {
    uint64_t b = pop();
    uint64_t a = pop();
    push(a + b);
}
```

## Flag Check Patterns

### Pattern A: Inline Comparison (Fusion-style)
```c
// Opcode 0 handler also checks input
if (opcode == 0) {
    uint8_t input[4];
    read(peer_fd, input, 4);
    
    uint8_t expected[4];
    for (int j = 0; j < 4; j++) {
        uint8_t key_byte = bytecode[(offset + j) % bytecode_size];
        uint8_t rotated = ROL(key_byte, 3);
        expected[j] = (pc + j) ^ rotated;
    }
    
    if (memcmp(input, expected, 4) != 0) {
        exit(1);  // Wrong flag
    }
}
```

**Extraction:** The expected bytes ARE the instruction bytes after decryption.

### Pattern B: Accumulator Comparison
```c
// After processing all instructions, compare accumulator
if (regs[0] == TARGET_VALUE) {
    print("Correct!");
}
```

**Extraction:** Trace the VM execution to find the input that produces `TARGET_VALUE`.

### Pattern C: Checksum/Hash
```c
// Compute hash of input, compare against embedded hash
uint32_t hash = compute_hash(input);
if (hash == EMBEDDED_HASH) {
    print("Correct!");
}
```

**Extraction:** Brute-force or reverse the hash function.

## Decryption Algorithms

### Rolling XOR Key
```python
def decrypt_rolling_xor(data):
    key = INITIAL_KEY  # e.g., 0
    decrypted = bytearray()
    for i, byte in enumerate(data):
        decrypted.append(byte ^ key)
        key = (key + KEY_INCREMENT) & 0xFF  # e.g., +0xA7
    return bytes(decrypted)
```

### Position-Dependent XOR
```python
def decrypt_position_xor(data):
    decrypted = bytearray()
    for i, byte in enumerate(data):
        key = ((i >> 8) * 0x53) ^ (i * 0xA7) ^ 0x4D
        decrypted.append(byte ^ key)
    return bytes(decrypted)
```

## Anti-Debug in VM Binaries
| Technique | Detection | Bypass |
|-----------|-----------|--------|
| `ptrace` | Check decompilation for `ptrace(0, 0, 0, 0)` | Patch to `ptrace(0, 0, 0, 1)` or NOP |
| `IsDebuggerPresent` | Import from `kernel32.dll` | Patch PEB byte or NOP check |
| Timing checks | `rdtsc` or `gettimeofday` around VM loop | Emulate or patch thresholds |
| Checksum verification | Hash of bytecode before decryption | Break before check or patch expected hash |
