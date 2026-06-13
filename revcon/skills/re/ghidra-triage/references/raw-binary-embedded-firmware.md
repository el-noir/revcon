# Raw Binary / Embedded Firmware Analysis in Ghidra

## Problem

When Ghidra opens a raw binary without auto-analysis, MCP tools return empty results:
- `list_functions` → empty
- `list_strings` → empty
- `list_imports` → empty
- `list_exports` → only `Reset -> 0x00000000`
- `list_data_items` → empty

This is common with:
- Microcontroller firmware (ARM Cortex-M, AVR, PIC, etc.)
- Bootloaders
- Raw flash dumps
- Binaries loaded without specifying the processor architecture

## Diagnostic Checklist

1. **Check segments**: `mcp_ghidra_list_segments`
   - If empty → no program is open at all
   - If single segment `ram: 00000000 - 0000XXXX` → raw binary loaded

2. **Check exports**: `mcp_ghidra_list_exports`
   - If only `Reset -> 0x00000000` → unanalyzed embedded firmware

3. **Check current address**: `mcp_ghidra_get_current_address`
   - If `00000000` with no function at that location → no auto-analysis run

## What to Tell the User

"The binary is loaded but Ghidra has not analyzed it. Please:
1. Set the correct processor architecture (ARM, AVR, MIPS, etc.) in Ghidra
2. Run Auto-Analysis: Analysis > Auto Analyze
3. Once analysis completes, I can pull the full disassembly and decompilation."

## After Auto-Analysis

Once the user confirms analysis is complete, re-run the standard triage:
1. `list_functions` — should now show defined functions
2. `list_strings` — may still be empty for bare-metal firmware
3. `decompile_function_by_address` on the Reset vector → entry point logic
4. `disassemble_function` on key addresses → verify instruction decoding

### When Auto-Analysis Still Produces No Functions

If `list_functions` remains empty after auto-analysis:
- The binary is likely a raw firmware image without standard entry point markers
- Ghidra's auto-analysis cannot determine code boundaries automatically
- **Required action**: Manual function creation in Ghidra UI
  1. Go to the Reset vector address (usually `0x00000000`) in the Listing view
  2. Right-click → **Create Function** (or press `F`)
  3. Re-run Auto-Analysis if needed
  4. Then MCP tools will work for disassembly/decompilation

**Do NOT** continue calling `disassemble_function` or `decompile_function_by_address` on addresses with no defined function — these tools will fail with "No function found at or containing address".

## Note on MCP Limitations

The Ghidra MCP bridge cannot:
- Set processor architecture
- Run auto-analysis
- Create functions manually
- Read raw bytes from arbitrary addresses

These must be done in the Ghidra UI before MCP analysis can proceed.