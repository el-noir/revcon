---
name: auto_unpack
description: Dynamically unpacks packed binaries by hooking memory-protection APIs (VirtualProtect, VirtualAlloc, mprotect) with Frida, detecting when the packer writes real code to executable memory, and dumping the unpacked payload to disk.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, unpacking, frida, dynamic-analysis]
    category: re
---
# Automated Unpacking Skill

## When to Use
Use this skill when Ghidra shows garbage pseudocode, the imports table is suspiciously small (only `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`), or the binary has high entropy sections — all signs of a packed binary.
Trigger: user says "unpack this", "this looks packed", or when the main agent detects packer signatures.

## Prerequisites
- The target binary must be provided to the `sandbox_runner`.
- This skill runs exclusively inside the Modal cloud sandbox.
- Requires `frida-tools` (install dynamically with `pip install frida-tools` in the script).

## How Packing Works (Context for the Agent)
1. A packer compresses/encrypts the real binary code into a data section.
2. At runtime, a small stub decompresses/decrypts the code into a newly allocated memory region.
3. The stub calls `VirtualProtect` (Windows) or `mprotect` (Linux) to mark that region as executable (RWX → RX).
4. The stub jumps to the Original Entry Point (OEP) in the unpacked code.

**Our strategy:** Hook the memory-protection API. When the packer marks a region as executable, dump that entire region to disk. That dump contains the unpacked binary.

## Python Implementation Template
```python
import frida
import sys
import os

target_binary = "<INSERT_BINARY_PATH>"

# JavaScript to inject — hooks VirtualProtect and mprotect
js_code = """
'use strict';

// Track allocated regions
var allocations = {};

// Hook VirtualAlloc (Windows) or mmap (Linux)
try {
    var virtualAlloc = Module.findExportByName(null, "VirtualAlloc");
    if (virtualAlloc) {
        Interceptor.attach(virtualAlloc, {
            onEnter: function(args) {
                this.size = args[1].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    allocations[retval.toString()] = this.size;
                    send({type: "alloc", address: retval.toString(), size: this.size});
                }
            }
        });
    }
} catch(e) {}

// Hook VirtualProtect (Windows) or mprotect (Linux)
var protectFn = Module.findExportByName(null, "VirtualProtect") ||
                Module.findExportByName(null, "mprotect");

if (protectFn) {
    Interceptor.attach(protectFn, {
        onEnter: function(args) {
            var addr = args[0];
            var size = args[1].toInt32();
            var prot = args[2].toInt32();
            
            // Check if setting memory to executable (PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40)
            var isExec = (prot & 0x10) || (prot & 0x20) || (prot & 0x40) || (prot & 0x80);
            // Linux: PROT_EXEC = 0x4
            isExec = isExec || (prot & 0x4);
            
            if (isExec && size > 4096) {
                send({
                    type: "unpack_candidate",
                    address: addr.toString(),
                    size: size,
                    protection: prot
                });
                // Dump the memory region
                var data = Memory.readByteArray(addr, Math.min(size, 10 * 1024 * 1024));
                send({type: "dump", address: addr.toString(), size: size}, data);
            }
        }
    });
}
"""

dump_count = 0

def on_message(message, data):
    global dump_count
    if message['type'] == 'send':
        payload = message['payload']
        if payload['type'] == 'alloc':
            print(f"[*] VirtualAlloc at {payload['address']}, size={payload['size']}")
        elif payload['type'] == 'unpack_candidate':
            print(f"[!] UNPACK CANDIDATE: addr={payload['address']}, size={payload['size']}, prot={payload['protection']}")
        elif payload['type'] == 'dump' and data:
            dump_count += 1
            dump_path = f"/tmp/unpacked_dump_{dump_count}.bin"
            with open(dump_path, 'wb') as f:
                f.write(data)
            print(f"[+] DUMPED {len(data)} bytes to {dump_path}")
    elif message['type'] == 'error':
        print(f"[-] Error: {message['stack']}")

try:
    pid = frida.spawn([target_binary])
    session = frida.attach(pid)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
    
    print(f"[*] Hooks installed. Resuming {target_binary}...")
    frida.resume(pid)
    
    import time
    time.sleep(10)  # Let the packer run its course
    
    frida.kill(pid)
    print(f"[*] Done. {dump_count} memory region(s) dumped.")
except Exception as e:
    print(f"Failed: {e}")
```

## Reporting Format
Report each dumped region with its memory address, size, and file path. Recommend which dump is most likely the unpacked payload (usually the largest one with executable permissions). Advise the user to load the dump into Ghidra for further analysis.
