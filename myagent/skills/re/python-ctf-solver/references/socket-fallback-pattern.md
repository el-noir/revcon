# Socket Fallback Pattern (No External Dependencies)

## When to Use
- `pwntools` is not installed in the target environment
- You need a minimal script that runs with only Python stdlib
- The challenge requires only basic TCP connect + recv + close

## Pattern

```python
import socket
import ast

def capture_with_socket(host, port):
    """Capture server output using only Python stdlib socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    
    return data.decode('utf-8', errors='replace')

# Usage
output = capture_with_socket('verbal-sleep.picoctf.net', 50118)
scrambled = ast.literal_eval(output.strip())
```

## Comparison with pwntools

| Feature | pwntools | socket stdlib |
|---------|----------|---------------|
| Install required | Yes (`pip install pwntools`) | No |
| recvall with timeout | `conn.recvall(timeout=5)` | Manual loop + `socket.settimeout()` |
| Interactive mode | `conn.interactive()` | Not available |
| recvuntil | `conn.recvuntil(b'prompt')` | Manual buffer search |
| recvline | `conn.recvline()` | Read until `\n` |

## When pwntools is Worth It
- Interactive challenges (need to send responses based on prompts)
- Binary exploitation (need packing/unpacking, ELF parsing)
- Complex protocols (need `recvuntil`, `sendlineafter`, etc.)

## When Socket is Sufficient
- One-shot output capture (server just sends data and closes)
- Simple send-then-receive patterns
- Environments where `pip install` is not available

## Full Example: Quantum Scrambler Solver (stdlib only)

```python
import socket
import ast

HOST = 'verbal-sleep.picoctf.net'
PORT = 50118

# Capture
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
data = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()

output = data.decode('utf-8', errors='replace')
scrambled = ast.literal_eval(output.strip())

# Extract hex strings in order
hex_strings = []
def extract(obj):
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, str) and item.startswith('0x'):
                hex_strings.append(item)
            elif isinstance(item, list):
                extract(item)

extract(scrambled)
flag = ''.join(chr(int(h, 16)) for h in hex_strings)
print(f"FLAG: {flag}")
```
