#!/usr/bin/env python3
"""
Safe Python bytecode inspector — works across Python versions.
Avoids `dis.dis()` which crashes when bytecode was compiled for a different Python version.
"""
import struct
import marshal
import sys


def find_rdata_offset(exe_path):
    """Parse PE headers to find .rdata section file offset."""
    with open(exe_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    pe_sig = data[e_lfanew:e_lfanew+4]
    assert pe_sig == b'PE\x00\x00'
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_header_start = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_header_start)[0]
    if magic == 0x10b:
        section_table_start = opt_header_start + 224
    elif magic == 0x20b:
        section_table_start = opt_header_start + 240
    else:
        raise ValueError(f"Unknown magic: {hex(magic)}")
    for i in range(num_sections):
        sec_start = section_table_start + i * 40
        name = data[sec_start:sec_start+8].split(b'\x00')[0].decode('ascii', errors='ignore')
        virtual_address = struct.unpack_from("<I", data, sec_start + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_start + 16)[0]
        raw_offset = struct.unpack_from("<I", data, sec_start + 20)[0]
        if name == ".rdata":
            return raw_offset, virtual_address, raw_size
    raise ValueError(".rdata not found")


def scan_consts(obj, path=""):
    """Recursively scan all constants in a code object tree."""
    results = {
        'tuples': [],
        'bytes_64': [],
        'lists_5': [],
        'ints': [],
        'code_objects': []
    }
    
    def _scan(obj, path=""):
        if hasattr(obj, 'co_consts'):
            results['code_objects'].append((path, obj.co_name, len(obj.co_code)))
            for i, c in enumerate(obj.co_consts):
                _scan(c, f"{path}.co_consts[{i}]")
        elif isinstance(obj, tuple):
            results['tuples'].append((path, obj))
            for i, item in enumerate(obj):
                _scan(item, f"{path}[{i}]")
        elif isinstance(obj, bytes) and len(obj) == 64:
            results['bytes_64'].append((path, obj))
        elif isinstance(obj, list) and len(obj) == 5 and all(isinstance(x, int) for x in obj):
            results['lists_5'].append((path, obj))
        elif isinstance(obj, int) and obj > 0:
            results['ints'].append((path, obj))
    
    _scan(obj, path)
    return results


def extract_and_inspect(exe_path, payload_va, payload_size, xor_key):
    """Extract XOR-encrypted Python bytecode from PE .rdata and inspect constants."""
    rdata_file_offset, rdata_va, rdata_size = find_rdata_offset(exe_path)
    
    with open(exe_path, "rb") as f:
        data = f.read()
    
    payload_offset = rdata_file_offset + (payload_va - rdata_va)
    payload = data[payload_offset:payload_offset + payload_size]
    decrypted = bytes([b ^ xor_key for b in payload])
    
    # Skip 16-byte .pyc header
    bytecode = decrypted[16:]
    code_obj = marshal.loads(bytecode)
    
    print(f"Python version: {sys.version}")
    print(f"Payload VA: 0x{payload_va:x}, size: 0x{payload_size:x}")
    print(f"XOR key: 0x{xor_key:x}")
    print()
    
    results = scan_consts(code_obj)
    
    print(f"=== Code Objects ===")
    for path, name, code_len in results['code_objects']:
        print(f"  {path}: {name} (co_code len={code_len})")
    
    print(f"\n=== Tuples ===")
    for path, t in results['tuples']:
        print(f"  {path}: len={len(t)}, types={set(type(x).__name__ for x in t)}, sample={t[:5]}")
    
    print(f"\n=== bytes(64) ===")
    for path, b in results['bytes_64']:
        print(f"  {path}: {b}")
    
    print(f"\n=== lists(5 ints) ===")
    for path, l in results['lists_5']:
        print(f"  {path}: {l}")
    
    print(f"\n=== Positive ints (first 20) ===")
    for path, v in results['ints'][:20]:
        print(f"  {path}: {v}")
    
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Inspect Python bytecode in PE .rdata")
    parser.add_argument("exe", help="Path to PE executable")
    parser.add_argument("--va", type=lambda x: int(x, 0), required=True, help="Payload virtual address (hex)")
    parser.add_argument("--size", type=lambda x: int(x, 0), required=True, help="Payload size (hex)")
    parser.add_argument("--key", type=lambda x: int(x, 0), required=True, help="XOR key (hex)")
    args = parser.parse_args()
    
    extract_and_inspect(args.exe, args.va, args.size, args.key)
