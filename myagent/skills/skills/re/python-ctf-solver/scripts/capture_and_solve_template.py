#!/usr/bin/env python3
"""
Template script for CTF Python scramble challenges.
Captures output from a netcat server and reverses the scrambling.
Supports both pwntools (if available) and stdlib socket fallback.
"""
import ast
import socket

# Try pwntools, fall back to stdlib socket if unavailable
try:
    from pwn import remote, context
    context.log_level = 'error'
    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False
    print("[!] pwntools not available, using stdlib socket fallback")

# ── CONFIG ──
HOST = 'verbal-sleep.picoctf.net'
PORT = 50118
TIMEOUT = 5
# ────────────


def capture_output_pwntools(host, port, timeout=5):
    """Connect to the server using pwntools and return the raw output string."""
    p = remote(host, port)
    output = p.recvall(timeout=timeout).decode('utf-8', errors='replace')
    p.close()
    return output


def capture_output_socket(host, port):
    """Connect to the server using stdlib socket (no external deps)."""
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


def capture_output(host, port, timeout=5):
    """Connect to the server and return the raw output string.
    Tries pwntools first, falls back to stdlib socket if unavailable."""
    if HAS_PWNTOOLS:
        return capture_output_pwntools(host, port, timeout)
    else:
        return capture_output_socket(host, port)


def parse_scrambled(output):
    """Safely parse the server output into a Python object."""
    output = output.strip()
    try:
        return ast.literal_eval(output)
    except Exception as e:
        print(f"[!] Failed to parse output with ast.literal_eval: {e}")
        print(f"[!] Raw output (first 500 chars): {output[:500]}")
        raise


def extract_hex_strings(obj):
    """Recursively extract all hex-encoded strings like '0x70' from nested lists."""
    result = []
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, str) and item.startswith('0x'):
                result.append(item)
            elif isinstance(item, list):
                result.extend(extract_hex_strings(item))
    return result


def hex_strings_to_flag(hex_strings):
    """Convert a list of hex strings back to a flag string."""
    return ''.join(chr(int(h, 16)) for h in hex_strings)


def main():
    print(f"[*] Connecting to {HOST}:{PORT} ...")
    raw_output = capture_output(HOST, PORT, TIMEOUT)
    print(f"[*] Captured {len(raw_output)} characters")

    # Save for offline analysis
    with open('scrambled_output.txt', 'w') as f:
        f.write(raw_output)
    print("[*] Saved to scrambled_output.txt")

    print("[*] Parsing scrambled structure ...")
    scrambled = parse_scrambled(raw_output)

    print("[*] Extracting hex strings ...")
    hex_strings = extract_hex_strings(scrambled)
    print(f"[*] Found {len(hex_strings)} hex strings")

    print("[*] Converting to flag ...")
    flag = hex_strings_to_flag(hex_strings)
    print(f"[+] Flag: {flag}")

    return flag


if __name__ == '__main__':
    main()
