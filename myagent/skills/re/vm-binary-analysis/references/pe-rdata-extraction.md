# PE .rdata Section Extraction

## When to Use
When a Windows PE binary contains an encrypted payload in the `.rdata` section and Ghidra MCP cannot provide raw bytes directly.

## Extraction Script

```python
import struct

def extract_rdata_payload(binary_path, payload_va, payload_size):
    """
    Extract payload from PE .rdata section.
    
    Args:
        binary_path: Path to the PE binary
        payload_va: Virtual address of the payload (e.g., 0x14002b609)
        payload_size: Size of the payload in bytes (e.g., 0xc2b)
    
    Returns:
        bytes: The extracted payload
    """
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # Parse DOS header
    dos_header = data[:64]
    pe_offset = struct.unpack_from('<I', dos_header, 60)[0]
    
    # Parse COFF header
    coff_header = data[pe_offset+4:pe_offset+24]
    num_sections = struct.unpack_from('<H', coff_header, 2)[0]
    size_optional_header = struct.unpack_from('<H', coff_header, 16)[0]
    
    # Parse optional header
    optional_header = data[pe_offset+24:pe_offset+24+size_optional_header]
    magic = struct.unpack_from('<H', optional_header, 0)[0]
    
    if magic == 0x10b:  # PE32
        image_base = struct.unpack_from('<I', optional_header, 28)[0]
    else:  # PE32+ (64-bit)
        image_base = struct.unpack_from('<Q', optional_header, 24)[0]
    
    # Parse section table
    section_table_offset = pe_offset + 24 + size_optional_header
    
    for i in range(num_sections):
        section_offset = section_table_offset + i * 40
        section = data[section_offset:section_offset+40]
        name = section[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virtual_address = struct.unpack_from('<I', section, 12)[0]
        pointer_to_raw_data = struct.unpack_from('<I', section, 20)[0]
        
        if name == '.rdata':
            section_va = image_base + virtual_address
            payload_offset_in_section = payload_va - section_va
            file_offset = pointer_to_raw_data + payload_offset_in_section
            payload = data[file_offset:file_offset+payload_size]
            return payload
    
    raise ValueError(".rdata section not found")

# Example usage
# payload = extract_rdata_payload('crabbymonty.exe', 0x14002b609, 0xc2b)
```

## Key Points
- The payload virtual address is relative to the image base
- The file offset is calculated as: `PointerToRawData + (payload_VA - ImageBase - VirtualAddress)`
- Always verify the payload size matches the decompilation (e.g., `CMP R14,0xc2b`)
- After extraction, apply the decryption algorithm (e.g., XOR with 0x69)
