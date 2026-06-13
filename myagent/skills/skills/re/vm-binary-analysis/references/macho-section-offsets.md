# Mach-O Section Offset Mapping

## Problem
In Mach-O binaries, the virtual address (VA) of a section does not equal its file offset. The `__TEXT` segment typically starts at VA `0x100000000` but its file offset is after the Mach-O header and load commands.

## Solution

### Method 1: Using Ghidra MCP
```
list_segments  → shows segment VAs and sizes
list_data_items → shows data labels with VAs
```

The file offset for a data item at VA `0x100000a20`:
1. Find the section containing this VA via `list_segments`
2. Calculate: `file_offset = section_file_offset + (va - section_va)`

### Method 2: Python Script
```python
import struct

def find_section_offset(data, section_name, segment_name='__TEXT'):
    magic = struct.unpack('<I', data[:4])[0]
    is_64 = (magic == 0xfeedfacf)  # MH_MAGIC_64
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

# Usage
fileoff, addr, size = find_section_offset(data, '__const', '__TEXT')
va_target = 0x100000a20
file_offset = fileoff + (va_target - addr)
```

## Common Mach-O Sections for VM Bytecode
| Section | Segment | Typical Content |
|---------|---------|-----------------|
| `__const` | `__TEXT` | Read-only data, encrypted bytecode, S-Box tables |
| `__data` | `__DATA` | Mutable data, function pointer tables |
| `__bss` | `__DATA` | Zero-initialized data, VM registers, input buffers |

## Example: Fusion Binary (Fat Mach-O)
**CRITICAL**: The fusion binary is a **fat Mach-O** (universal binary) containing multiple slices.
- Slice 0 (x86-64): file offset `0x4000`, size `0x6a30`
- Slice 1 (AARCH64): file offset `0xc000`, size `0xcc90`

Within each slice, the `__const` section is at VA `0x100000a00` with file offset `0xa00` **relative to the slice start**.
- Encrypted bytecode at VA `0x100000a20`:
  - x86-64 slice: absolute file offset = `0x4000 + 0xa20 = 0x4a20`
  - AARCH64 slice: absolute file offset = `0xc000 + 0xa20 = 0xca20`

### Fat Mach-O Header Parsing
```python
import struct

def parse_fat_binary(data):
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

# Example: fusion binary
slices = parse_fat_binary(data)
# slices[0] = {'cputype': 0x01000007, 'offset': 0x4000, 'size': 0x6a30}  # x86-64
# slices[1] = {'cputype': 0x0100000c, 'offset': 0xc000, 'size': 0xcc90}  # AARCH64
```

### Pitfall: Thin vs Fat Binary
Always check the magic number first:
- `0xfeedfacf` or `0xfeedface` = thin binary (single architecture)
- `0xcafebabe` or `0xcafebabf` = fat binary (multiple architectures)

For thin binaries, the file offset is the section offset directly.
For fat binaries, you must add the slice offset to the section offset.
