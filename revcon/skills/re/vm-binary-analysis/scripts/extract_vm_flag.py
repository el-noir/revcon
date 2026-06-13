#!/usr/bin/env python3
"""
Template script for extracting flags from VM-based binaries.

Usage:
    python3 extract_vm_flag.py <binary_path>

Customize the following sections based on your binary analysis:
- SECTION 1: Mach-O/PE/ELF parsing (choose one)
- SECTION 2: Bytecode decryption algorithm
- SECTION 3: VM instruction parsing and flag extraction
"""

import struct
import sys

# ============================================================
# SECTION 1: Binary Format Parsing (choose your format)
# ============================================================

def parse_fat_macho_slices(data):
    """Parse fat Mach-O header and return slice offsets."""
    magic = struct.unpack('>I', data[:4])[0]
    if magic == 0xcafebabe:
        nfat_arch = struct.unpack('>I', data[4:8])[0]
        offset = 8
        slices = []
        for i in range(nfat_arch):
            cputype, cpusubtype, slice_offset, size, align = struct.unpack('>5I', data[offset:offset+20])
            slices.append({
                'cputype': cputype,
                'offset': slice_offset,
                'size': size
            })
            offset += 20
        return slices
    return None

def parse_macho_find_section(data, section_name, segment_name='__TEXT'):
    """Find section offset in Mach-O binary (thin or fat slice)."""
    # Check if it's a fat binary
    slices = parse_fat_macho_slices(data)
    if slices:
        # For fat binaries, we need to parse each slice separately
        # This function assumes data is a single slice (thin binary)
        pass
    
    magic = struct.unpack('<I', data[:4])[0]
    is_64 = (magic == 0xfeedfacf)
    header_size = 32 if is_64 else 28
    ncmds = struct.unpack('<I', data[header_size-8:header_size-4])[0]
    offset = header_size
    
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[offset:offset+8])
        if cmd == 0x19 and is_64:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].decode('utf-8', errors='ignore').rstrip('\x00')
            if segname == segment_name:
                nsects = struct.unpack('<I', data[offset+64:offset+68])[0]
                sect_offset = offset + 72
                for _ in range(nsects):
                    sectname = data[sect_offset:sect_offset+16].decode('utf-8', errors='ignore').rstrip('\x00')
                    if sectname == section_name:
                        sect_addr = struct.unpack('<Q', data[sect_offset+32:sect_offset+40])[0]
                        sect_size = struct.unpack('<Q', data[sect_offset+40:sect_offset+48])[0]
                        sect_fileoff = struct.unpack('<I', data[sect_offset+48:sect_offset+52])[0]
                        return sect_fileoff, sect_addr, sect_size
                    sect_offset += 80
        offset += cmdsize
    return None, None, None

# ============================================================
# SECTION 2: Bytecode Decryption (customize per binary)
# ============================================================

def decrypt_bytecode(encrypted_data):
    """
    Decrypt VM bytecode.
    
    CRITICAL: The rolling key (bVar9) is a byte that wraps around.
    Do NOT use (i * DECRYPT_KEY2) without the wraparound!
    
    Common patterns:
    - Rolling XOR: key = (key + increment) & 0xFF
    - Position-dependent: key = f(i) where i is byte index
    - Multi-byte key: key = key_stream[i % key_length]
    """
    decrypted = bytearray(len(encrypted_data))
    key = 0  # Initial key from decompilation
    
    for i in range(len(encrypted_data)):
        # Example from Fusion binary:
        # decrypted[i] = ((i >> 8) * 0x53) ^ key ^ encrypted_data[i] ^ 0x4d
        # key = (key + 0xa7) & 0xff
        decrypted[i] = ((i >> 8) * 0x53) ^ key ^ encrypted_data[i] ^ 0x4d
        key = (key + 0xA7) & 0xFF
    
    return decrypted

# ============================================================
# SECTION 3: Flag Extraction (customize per binary)
# ============================================================

def rol(byte, n):
    """Rotate left a byte by n bits."""
    return ((byte << n) | (byte >> (8 - n))) & 0xff

def extract_flag(decrypted_bytecode):
    """
    Extract flag from decrypted VM bytecode.
    
    TODO: Customize based on VM instruction format and flag check mechanism.
    
    Common patterns:
    - Opcode 0 reads input and compares against rolling key
    - Specific opcode triggers comparison against embedded constant
    - Accumulator matches target value after execution
    """
    flag = bytearray()
    offset = 0x37  # Initial offset from decompilation
    bytecode_size = len(decrypted_bytecode)
    
    for pc in range(0, bytecode_size - 4, 4):
        opcode = decrypted_bytecode[pc]
        
        # TODO: Adjust opcode value for flag check
        if opcode == 0:  # Flag check opcode
            expected = decrypted_bytecode[pc:pc+4]
            
            # TODO: Adjust rolling key computation
            for j in range(4):
                key_byte = decrypted_bytecode[(offset + j) % bytecode_size]
                rotated = rol(key_byte, 3)  # TODO: Adjust rotation bits
                xor_key = (pc + j) ^ rotated  # TODO: Adjust key formula
                flag.append(expected[j] ^ xor_key)
        
        # TODO: Adjust offset increment
        offset = (offset + 0x1c) % bytecode_size
    
    return bytes(flag)

# ============================================================
# MAIN
# ============================================================

def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not binary_path:
        print("Usage: python3 extract_vm_flag.py <binary_path>")
        sys.exit(1)
    
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    print(f"Binary size: {len(data)} bytes")
    
    # Check if it's a fat binary
    slices = parse_fat_macho_slices(data)
    if slices:
        print(f"Fat binary with {len(slices)} slices:")
        for i, s in enumerate(slices):
            print(f"  Slice {i}: cputype=0x{s['cputype']:08x}, offset=0x{s['offset']:08x}, size=0x{s['size']:08x}")
    
    # Find encrypted bytecode section
    fileoff, addr, size = parse_macho_find_section(data, '__const', '__TEXT')
    if fileoff is None:
        print("Could not find __const section")
        sys.exit(1)
    
    # TODO: Adjust virtual address of bytecode
    bytecode_va = 0x100000a20  # Example from Fusion binary
    bytecode_offset = fileoff + (bytecode_va - addr)
    
    # TODO: Adjust bytecode size
    bytecode_size = 0x338
    encrypted = data[bytecode_offset:bytecode_offset + bytecode_size]
    
    print(f"Encrypted bytecode: {encrypted[:16].hex()}...")
    
    # Decrypt
    decrypted = decrypt_bytecode(encrypted)
    print(f"Decrypted bytecode: {decrypted[:16].hex()}...")
    
    # Extract flag
    flag = extract_flag(decrypted)
    print(f"\nExtracted flag: {flag}")
    
    try:
        print(f"Flag (ASCII): {flag.decode('ascii')}")
    except:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag)
        print(f"Printable: {printable}")

if __name__ == '__main__':
    main()
