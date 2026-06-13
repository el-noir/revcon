---
name: advanced_decoder
description: Dynamically writes Python scripts to attempt multi-layered decoding (Base64, XOR, Hex, ROT) on heavily obfuscated strings found during analysis.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, crypto, decoding, obfuscation]
    category: re
---
# Advanced Decoder Skill

## When to Use
Use this skill when you find a suspicious string or byte array in Ghidra that appears encoded.
Trigger: user says "decode this", "figure out this string", or when standard static analysis reveals garbage strings.

## Procedure
1. Identify the suspicious string/bytes and the context in which it is used.
2. Determine potential encoding type:
   - **Base64:** ends in `=`, charset `[A-Za-z0-9+/]`
   - **Hex:** purely `[0-9a-fA-F]`, even length
   - **XOR:** custom loop in Ghidra decompilation with a single-byte or multi-byte key
   - **Bit-scramble / custom bit order:** loop that extracts individual bits with non-standard ordering (e.g., bit 6,5,4,3,2,1,0,7 instead of 7,6,5,4,3,2,1,0). See the Bit-Scrambled Validation section below.
3. Write a Python script to perform the decoding. You have access to `pwntools` which has powerful utilities like `xor()`, `unhex()`, `b64d()`, etc.

### Python Implementation Template — XOR / Base64 / Hex
```python
from pwn import *
import base64

encoded_data = b"<INSERT_ENCODED_DATA>"
# Example: Base64 then XOR with key 0x77
try:
    decoded_b64 = base64.b64decode(encoded_data)
    decoded_xor = xor(decoded_b64, 0x77)
    print("Decoded String:", decoded_xor.decode('utf-8', errors='ignore'))
except Exception as e:
    print("Decoding failed:", e)
```

### Bit-Scrambled Validation Decoding
When the decompiled code compares input bits against a hardcoded array using a **non-standard bit order** (e.g., reading bits 6,5,4,3,2,1,0,7 per byte instead of MSB-to-LSB), reconstruct the expected input as follows:

1. Extract the hardcoded byte array from the decompilation.
2. For each byte in the array, read its bits in the order the **check function** reads them (usually 7,6,5,4,3,2,1,0 = standard MSB-to-LSB).
3. Map each extracted bit to the corresponding **input bit position** based on the scrambled order used by the input side.
4. Reassemble the input bytes from the mapped bits.

```python
# Example: check reads local_58 bits as 7,6,5,4,3,2,1,0
#          but reads input bits as 6,5,4,3,2,1,0,7
local_58 = [0xe1, 0xa7, ...]  # hardcoded array from decompilation

result = bytearray(EXPECTED_LENGTH)
local_1c = 0   # input byte index
local_20 = 0   # input bit position tracker

for local_24 in range(len(local_58)):
    for local_28 in range(8):  # check reads local_58 bits 7..0
        if local_20 == 0:
            local_20 = 1
        local_30 = 1 << (7 - local_28)   # mask for local_58 bit
        local_34 = 1 << (7 - local_20)   # mask for input bit
        if local_58[local_24] & local_30:
            result[local_1c] |= local_34
        local_20 += 1
        if local_20 == 8:
            local_20 = 0
            local_1c += 1

print(result.decode('latin-1'))
```

**Key insight:** The check function usually has two bit-extraction expressions — one for the hardcoded array (standard order) and one for the input (scrambled order). The scrambled order is the critical detail to capture correctly. Common scrambled orders include:
- `6,5,4,3,2,1,0,7` (bit 7 is last instead of first)
- `0,1,2,3,4,5,6,7` (LSB-to-MSB)
- Any permutation based on a counter variable

## Reporting Format
Show the user the decoded string clearly, explain the encoding layers used (e.g., "The string was Base64 encoded, then XOR'd with the key 0x55"), and suggest what the decoded string might be used for (e.g., C2 server URL, registry key).

## Pitfalls
- **Bit-scramble off-by-one:** When the scrambled bit order includes a wrap-around (e.g., counter hits 8, resets to 0, then gets forced to 1), the first bit of the next byte may be skipped or duplicated. Trace the exact counter logic from the decompilation — do not assume a clean 8-bit cycle.
- **Partial validation:** The check may validate fewer bytes than the declared input length. Always count how many input bytes are actually accessed by the loop, not just the `strlen` comparison.
- **Signed byte arrays:** Ghidra decompilation may show negative decimal values (e.g., `-0x1f`, `-99`). Convert to unsigned bytes with `b & 0xFF` before bit manipulation.
