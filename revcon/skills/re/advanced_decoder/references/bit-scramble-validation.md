# Bit-Scrambled Validation — Reference

## Technique
Some crackmes validate input by comparing individual bits against a hardcoded byte array, but read the input bits in a non-standard order. This obfuscates the expected password without requiring complex crypto.

## Pattern in Ghidra Decompilation

Look for nested loops like:
```c
for (i = 0; i < HARDCODED_ARRAY_LEN; i++) {
    for (j = 0; j < 8; j++) {
        if (input_bit_pos == 0) input_bit_pos = 1;
        mask_target = 1 << (7 - j);           // standard: bits 7..0
        mask_input  = 1 << (7 - input_bit_pos); // scrambled!
        if ((input[input_idx] & mask_input) != (target[i] & mask_target))
            return WRONG;
        input_bit_pos++;
        if (input_bit_pos == 8) {
            input_bit_pos = 0;
            input_idx++;
        }
    }
}
```

## Decoding Strategy

1. **Extract the hardcoded array** from the decompilation. Convert signed values to unsigned: `val & 0xFF`.
2. **Identify the scrambled order** by tracing the `input_bit_pos` variable. In the example above, the sequence is `1,2,3,4,5,6,7,0,1,2,...` which means input bits are read as `6,5,4,3,2,1,0,7`.
3. **Simulate the check in reverse:** For each bit position in the hardcoded array (standard order 7..0), set the corresponding input bit according to the scrambled mapping.

## Worked Example — picoCTF "perplexed"

**Hardcoded array (23 bytes):**
```
E1 A7 1E F8 75 23 7B 61 B9 9D FC 5A 5B DF 69 D2 FE 1B ED F4 ED 67 F4
```

**Scrambled input bit order:** `6,5,4,3,2,1,0,7` per byte

**Python recovery:**
```python
local_58 = [0xe1, 0xa7, 0x1e, 0xf8, 0x75, 0x23, 0x7b, 0x61,
            0xb9, 0x9d, 0xfc, 0x5a, 0x5b, 0xdf, 0x69, 0xd2,
            0xfe, 0x1b, 0xed, 0xf4, 0xed, 0x67, 0xf4]

result = bytearray(27)
local_1c = 0   # input byte index
local_20 = 0   # input bit position tracker

for local_24 in range(len(local_58)):
    for local_28 in range(8):
        if local_20 == 0:
            local_20 = 1
        local_30 = 1 << (7 - local_28)   # mask for target bit
        local_34 = 1 << (7 - local_20)   # mask for input bit
        if local_58[local_24] & local_30:
            result[local_1c] |= local_34
        local_20 += 1
        if local_20 == 8:
            local_20 = 0
            local_1c += 1

print(result.decode('latin-1'))
# Output: picoCTF{0n3_bi7_4t_a_7im\x00\x00\x00
```

**Result:** The validated prefix is `picoCTF{0n3_bi7_4t_a_7im` (24 bytes). The remaining 3 bytes are unconstrained by the check loop.

## Key Insight
The `strlen == 0x1b` (27) check is a red herring — only 184 bits (23 bytes + 1 bit) are actually validated. The last few bytes can be anything. Always count loop iterations, not just the length check.
