# Python dis() Dump Reversal

## When to use
Challenge file is a text dump of `dis.dis()` output rather than `.py` source.

## Reconstruction approach
1. Extract constants from `LOAD_CONST` lines.
2. Reconstruct string/key variables from `LOAD_CONST` / `BINARY_ADD` / `STORE_NAME`.
3. Reconstruct loops and list comprehensions from opcode flow (`FOR_ITER`, `BUILD_LIST`, `LIST_APPEND`, `CALL_FUNCTION`).
4. Watch for arithmetic on paired values: `UNPACK_SEQUENCE 2` followed by `BINARY_XOR` signals an XOR cipher.
5. Rebuild equivalent Python and execute; do not guess the flag from raw bytes.

## Pitfalls
- `dis()` output alone does not prove Python version compatibility. Execute the reconstructed source in the target environment.
- XOR ciphers in CTFs often produce non-printable intermediate bytes. Do not fabricate a flag if output is not clean ASCII.
- Always run the reconstructed code in a real Python process and capture `stdout` with `repr()` to see exact bytes.
