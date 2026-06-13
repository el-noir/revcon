---
name: python-ctf-solver
description: Solve CTF challenges that provide Python artifacts — source code, disassembly dumps, or server-visible scrambling behavior — by reconstructing algorithms and writing reverse scripts. Covers netcat-based challenges and flat `dis.dis()` dumps from Python bytecode.
version: 1.0.0
metadata:
  hermes:
    tags: [ctf, python, scrambling, netcat, pwntools, reverse-engineering]
    category: re
---
# Python CTF Challenge Solver

## When to Use
Use this skill when:
- The challenge provides a `.py` file (e.g., `quantum_scrambler.py`, `encoder.py`)
- The challenge provides a flat `dis.dis()` text dump from a Python script
- The challenge requires connecting to a netcat server to capture scrambled/encrypted output
- The goal is to reverse the Python algorithm and recover a flag
- The flag format is known (e.g., `picoCTF{...}`, `flag{...}`)

## Artifacts This Handles
- Inline `dis.dis()` output saved to a text file
- Marshalled code objects referenced in disassembly (`<code object <listcomp> at ...>`)
- Python constant arrays that have been XOR-transformed or otherwise obscured

## NOT for
- Compiled binary VM challenges (use `vm-binary-analysis` instead)
- Pure cryptography challenges without a server component
- Web-based challenges (use browser tools instead)

## Analysis Procedure

### Phase 1 — Understand the Scrambling Logic
1. **Read the Python source** carefully. Look for:
   - The input source (usually `flag.txt`, `open('flag.txt').read()`)
   - The transformation loop (nested list manipulations, XOR, shifts, etc.)
   - The output format (print, socket send, etc.)

2. **Trace the algorithm manually** with a small example:
   - Pick a 3-5 character input like `['a','b','c']`
   - Walk through each iteration step by step
   - Note how the data structure changes (list concatenations, nested lists, pops)

3. **Identify the key invariant**: Often the scrambled data preserves the original bytes but wraps them in nested structures. The original bytes may still be extractable in order.

### Phase 2 — Capture Server Output
1. **Write a capture script** using `pwntools`:
   ```python
   from pwn import remote
   conn = remote('host', port)
   output = conn.recvall(timeout=5)
   conn.close()
   print(output.decode())
   ```

2. **Save the output** to a file for repeated analysis without hitting the server:
   ```python
   with open('scrambled_output.txt', 'w') as f:
       f.write(output.decode())
   ```

### Phase 3 — Write the Reverse Script
1. **Parse the output** using `ast.literal_eval()` if it's a Python literal (list, dict, etc.)
   - NEVER use `eval()` — security risk and unnecessary
   - `ast.literal_eval()` safely parses Python literals

2. **Extract the original bytes**:
   - If the scramble preserves byte order: recursively extract hex strings or raw bytes
   - If the scramble permutes bytes: trace the permutation and write an un-permute function
   - If the scramble uses XOR/ADD: identify the key and write the inverse operation

3. **Common patterns**:
   - **List pop-and-merge with nested references**: `A[i-2] += A.pop(i-1)` followed by `A[i-1].append(A[:i-2])` — this pattern (seen in `quantum_scrambler.py`) preserves the original hex strings in order but wraps them in increasingly deep nested lists. The key insight: the original data elements maintain their relative order throughout the scramble. To reverse: recursively walk the final structure and collect all hex strings in DFS pre-order. Convert with `chr(int(h, 16))`.
   - **List pop-and-merge**: `A[i-2] += A.pop(i-1)` — the popped element is appended to an earlier list. The original elements are still in the structure, just nested deeper.
   - **Nested list append**: `A[i-1].append(A[:i-2])` — creates deep nesting. The original data is preserved but wrapped in reference structures.
   - **Hex encoding**: `hex(ord(c))` produces strings like `'0x70'`. Collect these and convert back with `chr(int(h, 16))`.

### Phase 4 — Execute and Verify
1. **Run the script** and capture the exact output
2. **Verify the flag format** matches the expected pattern
3. **If the flag is wrong**, re-check:
   - Did you capture the complete output? (netcat may truncate)
   - Did you parse the structure correctly? (print intermediate states)
   - Is the extraction order correct? (the scramble may not preserve order)

## Pitfalls & Recovery

- **delegate_task with toolsets=["terminal"] may NOT give terminal access**: Sub-agents sometimes lack the terminal tool even when requested. If this happens:
  1. Try `delegate_task` with `toolsets=["terminal", "file"]` explicitly
  2. If the sub-agent still fails, use `cronjob` with `no_agent=False`, `deliver='origin'`, `enabled_toolsets=['terminal']` — this is the most reliable workaround
  3. If the cronjob runs but output doesn't appear in chat, check `cronjob(action='list')` for `last_status`. Status `ok` means it ran but output may not have been delivered. The script may need to write results to a known file path that you can then `read_file`
  4. If all else fails, be honest: "I cannot execute this script in my environment. Please run it manually:" and show the complete script

- **Execution via cronjob with no_agent=True + file output**: When you need guaranteed execution and chat delivery is unreliable:
  1. Write a script that writes its results to a known file path (e.g., `/mnt/d/Internship/test/hermes-revcon-workspace/flag_result.txt`)
  2. Place the script in `~/.hermes/scripts/` (required for no_agent=True cronjobs)
  3. Create a cronjob with `no_agent=True`, `script=<filename>` (no .py extension needed), `deliver='origin'`
  4. The script's stdout will be delivered to chat. If it writes to a file, you can `read_file` that path after the job runs
  5. Check `cronjob(action='list')` to see `last_run_at` and `last_status` to confirm execution
  6. **Critical**: Do NOT repeatedly poll the same file with `read_file` before the job has run — this hits `same_tool_failure_halt` after 4 failures. Wait for `last_run_at` to be populated first.

- **Tool loop guardrails**: Repeated identical tool calls hit guardrails:
  - `idempotent_no_progress_block` — triggers after 5 identical read-only calls that return the same result (e.g., `search_files` timing out). **Fix**: Change the query pattern or use a different tool; never repeat the exact same call.
  - `same_tool_failure_halt` — triggers after 4 consecutive failures of the same tool with identical arguments (e.g., `read_file` on a non-existent path). **Fix**: Check if the file was created by a different path, or use `search_files` to locate it, or wait for an async process to finish.
  - **General rule**: If a tool fails twice with the same error, change strategy before the guardrail hits.

- **pwntools may not be installed**: The environment may not have `pwntools` available. Always provide a stdlib-only fallback using `socket`:
  ```python
  import socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('host', port))
  data = b''
  while True:
      chunk = s.recv(4096)
      if not chunk:
          break
      data += chunk
  s.close()
  output = data.decode('utf-8', errors='replace')
  ```
  This avoids the `ModuleNotFoundError: No module named 'pwn'` failure when the user tries to run the script.

- **User wants direct commands, not explanations**: When the user asks "how to run this", they want the exact command line, not a tutorial on virtual environments or package management. Give the command first, then optionally mention prerequisites if the command fails. If they ask "where is X installed", check common paths (`/usr/local/lib`, `/usr/lib`, `~/.local/lib`) and report findings directly rather than explaining how Python package installation works.

- **ast.literal_eval fails on large output**: For very large structures, `ast.literal_eval` may hit recursion limits. In that case:
  1. Save the raw output to a file
  2. Process it line-by-line or with a custom parser
  3. Or use `json.loads()` if the output happens to be JSON-compatible

- **Do NOT fabricate flags**: If you cannot execute the script and get real output, you MUST say "I failed to execute — please run this script manually" and show the script. Never guess or derive a flag statically without verification.

- **Server rate limiting**: Some CTF servers rate-limit connections. Save the output on first capture and work offline. Do not hammer the server with repeated connections.

## Related Skills
- `vm-binary-analysis` — For compiled binary VM challenges (not Python scripts)
- `advanced_decoder` — For multi-layered string decoding after extraction
- `re-report` — For generating structured final reports

## References
- `references/netcat-capture-patterns.md` — Common pwntools patterns for capturing server output
- `references/python-scramble-reverse-patterns.md` — Common Python scramble patterns and their reverses
- `references/quantum-scrambler-pattern.md` — Deep dive on the list pop-and-merge with nested references pattern (quantum_scrambler.py)
- `references/socket-fallback-pattern.md` — Stdlib-only socket pattern when pwntools is unavailable (no pip install needed)
- `references/dis-dump-reversal.md` — Reconstructing Python source from disassembly dumps
- `scripts/capture_and_solve_template.py` — Template script for capture + solve workflow
