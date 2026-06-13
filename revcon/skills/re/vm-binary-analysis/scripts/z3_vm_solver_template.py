#!/usr/bin/env python3
"""
Z3 VM Solver Template
Generic template for solving VM-based CTF challenges using Z3 symbolic execution.
Customize the BYTECODE, SBOXes, opcodes, and final constraint for your challenge.
"""
import z3, sys

# ── Configuration (customize these for your challenge) ────────────────────────
BYTECODE = bytes.fromhex(
    # Paste your decrypted bytecode here
    ""
)

SBOX_TABLE = bytes.fromhex(
    # Paste your computed SBOX here (256 bytes)
    ""
)

# If you have two tables that need combining:
# SBOX_TABLE = bytes(TABLE1[i] ^ TABLE2[i ^ 0xa3] for i in range(256))

# Final constraint parameters
CONSTRAINT_TYPE = "hash"  # or "buffer" for direct comparison
HASH_OFFSET = 0xcbf20420d6b784b5  # FNV-1a offset basis
HASH_PRIME = 0x00000100001b3b93  # FNV-1a prime
TARGET_HASH = 0x0000000000000000  # Target hash value
XOR_KEY = bytes.fromhex("")  # Key for XOR before hashing

# Output register range
OUT_REG_START = 0x22
OUT_REG_COUNT = 34

# Flag constraints
FLAG_LENGTH = 34
FLAG_MIN = 0x20  # printable ASCII
FLAG_MAX = 0x7e

# ── Build If-chain SBOX for Z3 ───────────────────────────────────────────────
def make_sbox_fn(table):
    def apply(bv8):
        expr = z3.BitVecVal(table[255], 8)
        for i in range(254, -1, -1):
            expr = z3.If(bv8 == i, z3.BitVecVal(table[i], 8), expr)
        return expr
    return apply

# ── Symbolic registers ────────────────────────────────────────────────────────
flag_syms = [z3.BitVec(f"f{i}", 8) for i in range(FLAG_LENGTH)]
regs = {}
for i in range(FLAG_LENGTH):
    regs[i] = flag_syms[i]

def get_reg(idx):
    return regs.get(idx, z3.BitVecVal(0, 8))

def set_reg(idx, val):
    regs[idx] = val

# ── VM forward execution ──────────────────────────────────────────────────────
print("[*] Symbolically executing VM...", flush=True)
for i in range(0, len(BYTECODE), 4):
    op, dst, op1, op2 = BYTECODE[i], BYTECODE[i+1], BYTECODE[i+2], BYTECODE[i+3]
    op2v = z3.BitVecVal(op2, 8)
    
    # Customize opcodes for your VM
    if op == 0x10:   # XOR reg,reg -> reg
        set_reg(dst, get_reg(op1) ^ get_reg(op2))
    elif op == 0x11: # XOR reg,imm -> reg
        set_reg(dst, get_reg(op1) ^ op2v)
    elif op == 0x12: # SBOX[reg] -> reg
        sbox_fn = make_sbox_fn(SBOX_TABLE)
        set_reg(dst, sbox_fn(get_reg(op1)))
    elif op == 0x13: # reg[dst] += reg[op1] + imm
        set_reg(dst, z3.Extract(7, 0, get_reg(dst) + get_reg(op1) + op2v))
    elif op == 0x15: # reg[op1] + reg[op2] -> reg
        set_reg(dst, z3.Extract(7, 0, get_reg(op1) + get_reg(op2)))
    elif op == 0x80: # XOR reg,reg -> reg (x86)
        set_reg(dst, get_reg(op1) ^ get_reg(op2))
    elif op == 0x81: # XOR reg,imm -> reg (x86)
        set_reg(dst, get_reg(op1) ^ op2v)
    elif op == 0x82: # SBOX[reg] -> reg (x86)
        sbox_fn = make_sbox_fn(SBOX_TABLE)
        set_reg(dst, sbox_fn(get_reg(op1)))
    elif op == 0x83: # reg[dst] ^= reg[op1] ^ imm (x86)
        set_reg(dst, get_reg(dst) ^ get_reg(op1) ^ op2v)
    else:
        print(f"[!] Unknown opcode {hex(op)} at offset {i}")
        sys.exit(1)

print("[*] VM execution done. Building constraints...", flush=True)

# ── Solver setup ──────────────────────────────────────────────────────────────
s = z3.Solver()
s.set("timeout", 300000)  # 5 min

# Flag must be printable ASCII
for sym in flag_syms:
    s.add(sym >= FLAG_MIN, sym <= FLAG_MAX)

# Grab output registers
out_regs = [get_reg(OUT_REG_START + i) for i in range(OUT_REG_COUNT)]

# Final constraint: hash or direct comparison
if CONSTRAINT_TYPE == "hash":
    h = z3.BitVecVal(HASH_OFFSET, 64)
    prime64 = z3.BitVecVal(HASH_PRIME, 64)
    for i in range(OUT_REG_COUNT):
        key_byte = z3.BitVecVal(XOR_KEY[i], 64)
        val8 = z3.ZeroExt(56, out_regs[i])
        val64 = val8 ^ key_byte
        h = (h ^ val64) * prime64
    s.add(h == z3.BitVecVal(TARGET_HASH, 64))
else:
    # Direct comparison against target buffer
    TARGET_BUFFER = bytes.fromhex("")
    for i in range(OUT_REG_COUNT):
        s.add(out_regs[i] == TARGET_BUFFER[i])

print("[*] Solving...", flush=True)
result = s.check()

if result == z3.sat:
    m = s.model()
    flag_bytes = []
    for sym in flag_syms:
        v = m[sym]
        flag_bytes.append(v.as_long() if v is not None else ord('?'))
    flag = bytes(flag_bytes)
    print(f"[+] FLAG: {flag.decode('ascii', errors='replace')}")
elif result == z3.unsat:
    print("[-] UNSAT — constraints are unsatisfiable")
    print("    Possible causes:")
    print("    1. Wrong output registers")
    print("    2. Wrong SBOX computation")
    print("    3. Wrong hash parameters or target")
else:
    print("[-] UNKNOWN (timeout or solver gave up)")
