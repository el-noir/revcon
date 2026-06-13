# Netcat Capture Patterns for Python CTF Challenges

## Basic Capture with pwntools
```python
from pwn import remote

conn = remote('host', port)
output = conn.recvall(timeout=5)
conn.close()
print(output.decode('utf-8', errors='replace'))
```

## Capture with Line-by-Line Reading
```python
from pwn import remote

conn = remote('host', port)
lines = []
while True:
    try:
        line = conn.recvline(timeout=2)
        if not line:
            break
        lines.append(line.decode())
    except:
        break
conn.close()
print(''.join(lines))
```

## Capture with Known Terminator
```python
from pwn import remote

conn = remote('host', port)
output = conn.recvuntil(b' terminator_here', timeout=5)
conn.close()
```

## Interactive Capture (send input, then receive)
```python
from pwn import remote

conn = remote('host', port)
conn.sendline(b'some_input')
output = conn.recvall(timeout=5)
conn.close()
```

## Save Output for Offline Analysis
```python
from pwn import remote

conn = remote('host', port)
output = conn.recvall(timeout=5)
conn.close()

with open('server_output.txt', 'wb') as f:
    f.write(output)

# Later, read and parse without reconnecting
with open('server_output.txt', 'r') as f:
    data = f.read()
```

## Using subprocess (fallback if pwntools unavailable)
```python
import subprocess

result = subprocess.run(
    ['nc', 'host', str(port)],
    capture_output=True,
    text=True,
    timeout=10
)
print(result.stdout)
```
