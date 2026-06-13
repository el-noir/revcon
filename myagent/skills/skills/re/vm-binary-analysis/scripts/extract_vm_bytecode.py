#!/usr/bin/env python3
"""Template script to extract and decrypt VM bytecode from a binary file.

Usage: Adjust BINARY_PATH, ENCRYPTED_OFFSET, and ENCRYPTED_SIZE for your target.
For fat Mach-O binaries, ENCRYPTED_OFFSET must include the slice offset.
"""

import struct
import sys

# === CONFIGURATION ===
BINARY_PATH = '/path/to/binary'
ENCRYPTED_OFFSET = 0x4a20     # File offset of encrypted bytecode (include slice offset for fat binaries!)
ENCRYPTED_SIZE = 0x338        # Size of encrypted bytecode
LOOKUP1_OFFSET = 0x4d60       # File offset of lookup table 1 (include slice offset)
LOOKUP2_OFFSET = 0x4e60       # File offset of lookup table 2 (include slice offset)
LOOKUP_SIZE = 0x100           # Size of each lookup table

# Decryption parameters (extract from decompilation)
DECRYPT_KEY1 = ord('S')       # e.g., (i >> 8) * 'S'
DECRYPT_KEY2 = 0xa7           # e.g., rolling byte that increments by 0xa7 with wraparound
DECRYPT_KEY3 = 0x4d           # e.g., ^ 0x4d

# Keystream parameters (for challenge-response VMs)
KEYSTREAM_ROT = 3             # ROL bits
KEYSTREAM_INCREMENT = 0x1c    # Per instruction
KEYSTREAM_BYTE_INCREMENT = 0xd  # Per byte within 4-byte response
# =====================

def rol(byte, bits):
    return ((byte << bits) | (byte >> (8 - bits))) & 0xff

def decrypt_bytecode(encrypted):
    """Decrypt VM bytecode using the rolling key algorithm.
    
    CRITICAL: The rolling key (bVar9) is a byte that wraps around.
    Do NOT use (i * DECRYPT_KEY2) without the wraparound!
    """
    decrypted = bytearray(len(encrypted))
    bVar9 = 0
    for i in range(len(encrypted)):
        b = ((i >> 8) * DECRYPT_KEY1) ^ bVar9 ^ encrypted[i] ^ DECRYPT_KEY3
        decrypted[i] = b & 0xff
        bVar9 = (bVar9 + DECRYPT_KEY2) & 0xff
    return decrypted

def extract_data():
    with open(BINARY_PATH, 'rb') as f:
        f.seek(ENCRYPTED_OFFSET)
        encrypted = f.read(ENCRYPTED_SIZE)
        f.seek(LOOKUP1_OFFSET)
        lookup1 = f.read(LOOKUP_SIZE)
        f.seek(LOOKUP2_OFFSET)
        lookup2 = f.read(LOOKUP_SIZE)
    return encrypted, lookup1, lookup2

def parse_instructions(decrypted):
    """Parse VM instructions from decrypted bytecode."""
    instructions = []
    for i in range(0, len(decrypted), 4):
        opcode = decrypted[i]
        if opcode == 0xff:
            instructions.append((i, 'HALT', 0, 0, 0))
            break
        reg = decrypted[i+1] if i+1 < len(decrypted) else 0
        arg1 = decrypted[i+2] if i+2 < len(decrypted) else 0
        arg2 = decrypted[i+3] if i+3 < len(decrypted) else 0
        instructions.append((i, opcode, reg, arg1, arg2))
    return instructions

def main():
    encrypted, lookup1, lookup2 = extract_data()
    decrypted = decrypt_bytecode(encrypted)
    
    print(f'Encrypted bytecode ({len(encrypted)} bytes):')
    print(encrypted.hex())
    print()
    print(f'Decrypted bytecode ({len(decrypted)} bytes):')
    print(decrypted.hex())
    print()
    print('Lookup table 1:')
    print(lookup1.hex())
    print()
    print('Lookup table 2:')
    print(lookup2.hex())
    print()
    
    instructions = parse_instructions(decrypted)
    print(f'Instructions ({len(instructions)} total):')
    for addr, opcode, reg, arg1, arg2 in instructions[:20]:
        if opcode == 'HALT':
            print(f'  [{addr:04x}] HALT')
        else:
            print(f'  [{addr:04x}] opcode={opcode:02x} reg={reg:02x} arg1={arg1:02x} arg2={arg2:02x}')
    if len(instructions) > 20:
        print(f'  ... ({len(instructions) - 20} more)')

if __name__ == '__main__':
    main()
