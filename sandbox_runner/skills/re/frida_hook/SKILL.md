---
name: frida_hook
description: Uses Frida to dynamically instrument a running binary, allowing the agent to hook specific functions, dump arguments, and trace execution logic safely.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, dynamic-analysis, frida, instrumentation]
    category: re
---
# Frida Dynamic Instrumentation Skill

## When to Use
Use this skill when static analysis in Ghidra hits a wall due to obfuscation, dynamic API resolution, or encrypted payloads. 
Trigger: user says "hook this function", "use frida", or "trace the arguments".

## Prerequisites
- This skill should primarily be executed by the `sandbox_runner` sub-agent within the isolated Modal environment.
- The target binary path and the function name (or memory offset) to hook must be provided.

## Procedure
1. Identify the target function or API you want to hook (e.g., a custom decryption function at offset `0x401500`, or a system API like `WriteProcessMemory`).
2. Write a Python script using the `frida` module to spawn the process and inject your JavaScript instrumentation logic.
3. The injected JavaScript should read the arguments being passed to the target function (e.g., decryption keys, payload addresses) and send them back to Python.

### Python Implementation Template
Execute the following script using your code execution capabilities in the sandbox:
```python
import frida
import sys

target_binary = "<INSERT_BINARY_PATH>"
# Example: Hooking a standard libc function or a specific offset
# To hook an offset, use: Interceptor.attach(ptr("0x401500"), ... )
js_code = """
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function (args) {
        var str1 = Memory.readUtf8String(args[0]);
        var str2 = Memory.readUtf8String(args[1]);
        if (str1.indexOf("flag") !== -1 || str2.indexOf("flag") !== -1) {
            send({type: "match", arg1: str1, arg2: str2});
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(f"[+] Hook triggered! Args: {payload['arg1']} vs {payload['arg2']}")
    elif message['type'] == 'error':
        print(f"[-] Frida Error: {message['stack']}")

try:
    # Spawn the process in suspended state
    pid = frida.spawn([target_binary])
    session = frida.attach(pid)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
    
    print("[*] Frida script loaded. Resuming execution...")
    frida.resume(pid)
    
    # Let it run briefly to catch the execution
    import time
    time.sleep(3)
    
    frida.kill(pid)
except Exception as e:
    print(f"Failed to run Frida: {e}")
```

## Reporting Format
Report the extracted arguments or memory dumps cleanly. Explain to the user what the hooked arguments represent in the context of the malware's execution flow.
