#!/usr/bin/env python3
"""
Fusion binary flag extractor.

The binary is a macOS Mach-O with a custom VM interpreter.
The VM bytecode is encrypted at DAT_100000a20 and decrypted at runtime.

Decryption algorithm (from entry function):
    for i in range(0x338):
        decrypted[i] = ((i >> 8) * 0x53) ^ key ^ encrypted[i] ^ 0x4d
        key += 0xa7

VM instruction format (4 bytes):
    [opcode, reg_idx, arg1, arg2]

Opcode handlers:
    0: FUN_100000926 — regs[arg2] ^ regs[arg1]  (XOR registers)
    1: FUN_100000940 — arg2 ^ regs[arg1]        (XOR immediate with register)
    2: FUN_100000955 — S-Box substitution
    3: FUN_100000985 — arg2 ^ regs[arg1] ^ regs[arg2]  (3-way XOR)
    4: FUN_10000099f — regs[arg1]               (MOV)

For opcode 0 (NULL handler in the jump table), the VM reads 4 bytes from
peer fd, XORs them with a rolling key derived from the decrypted bytecode,
and compares against the instruction bytes. This is the flag check.

The rolling key for each 4-byte check:
    key_byte = decrypted_bytecode[(offset + j) % 0x338]
    rotated = rol(key_byte, 3)  # rotate left by 3
    xor_key = (vm_pc + j) ^ rotated
    
Where offset starts at 0x37 and increments by 0x1c each iteration.
"""

import struct
import sys

def rol(byte, n):
    """Rotate left a byte by n bits."""
    return ((byte << n) | (byte >> (8 - n))) & 0xff

def decrypt_bytecode(encrypted_data):
    """Decrypt the VM bytecode using the algorithm from the entry function."""
    decrypted = bytearray(len(encrypted_data))
    key = 0
    for i in range(len(encrypted_data)):
        decrypted[i] = ((i >> 8) * 0x53) ^ key ^ encrypted_data[i] ^ 0x4d
        key = (key + 0xa7) & 0xff
    return decrypted

def extract_flag(decrypted_bytecode):
    """
    Extract the flag from the decrypted bytecode.
    
    The VM checks input by reading 4 bytes and XORing with a rolling key.
    For opcode 0 (the NULL handler case), the expected value is the instruction
    itself: [opcode=0, reg_idx, arg1, arg2].
    
    The rolling key for each check at VM pc=i:
        key_byte = decrypted_bytecode[(offset + j) % 0x338]
        rotated = rol(key_byte, 3)
        xor_key = (i + j) ^ rotated
        
    Where offset starts at 0x37 and increments by 0x1c each iteration.
    """
    flag = bytearray()
    offset = 0x37
    
    for pc in range(0, 0x334, 4):
        opcode = decrypted_bytecode[pc]
        if opcode == 0xff:
            break
            
        if opcode == 0:
            # This is a flag check instruction
            # The expected 4 bytes are the instruction itself
            expected = decrypted_bytecode[pc:pc+4]
            
            # Compute the rolling key and decrypt
            decrypted_check = bytearray(4)
            for j in range(4):
                key_byte = decrypted_bytecode[(offset + j) % 0x338]
                rotated = rol(key_byte, 3)
                xor_key = (pc + j) ^ rotated
                decrypted_check[j] = expected[j] ^ xor_key
            
            flag.extend(decrypted_check)
        
        offset = (offset + 0x1c) % 0x338
    
    return bytes(flag)

def main():
    # Read the binary file
    binary_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    if binary_path:
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        # Find the encrypted bytecode at offset 0xa20 (address 100000a20)
        # In the file, this is at offset 0xa20 from the start of the __TEXT segment
        # For a simple Mach-O, the file offset might be different due to headers
        # Let's try to find it by searching for the known pattern
        
        # The encrypted bytecode starts with 0x5c, 0xae (from list_data_items)
        # Let's look for it in the file
        encrypted_start = data.find(bytes([0x5c, 0xae]))
        if encrypted_start == -1:
            print("Could not find encrypted bytecode pattern")
            sys.exit(1)
        
        print(f"Found encrypted bytecode at file offset: 0x{encrypted_start:x}")
        encrypted = data[encrypted_start:encrypted_start + 0x338]
    else:
        # Hardcoded encrypted bytecode from the binary (first few bytes from data items)
        # This is a fallback if we can't read the file
        print("No binary path provided, using hardcoded data")
        encrypted = bytes([
            0x5c, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]) + bytes(0x338 - 16)
    
    print(f"Encrypted bytecode length: {len(encrypted)}")
    print(f"First 16 bytes: {encrypted[:16].hex()}")
    
    decrypted = decrypt_bytecode(encrypted)
    print(f"Decrypted bytecode length: {len(decrypted)}")
    print(f"First 32 bytes: {decrypted[:32].hex()}")
    
    flag = extract_flag(decrypted)
    print(f"Extracted flag bytes: {flag.hex()}")
    print(f"Flag (ASCII): {flag}")
    
    # Try to interpret as printable
    try:
        flag_str = flag.decode('ascii')
        print(f"Flag as ASCII: {flag_str}")
    except:
        print("Flag is not pure ASCII")
        # Try to find printable characters
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag)
        print(f"Printable representation: {printable}")

if __name__ == '__main__':
    main()
