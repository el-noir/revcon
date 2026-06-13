# Subagent Terminal Access Limitations

## Problem

When delegating tasks to subagents via `delegate_task` with `toolsets=["terminal"]`, the subagent may:
1. Claim it lacks terminal tool access
2. Fall back to using Ghidra MCP tools (`mcp_ghidra_*`) instead of terminal commands
3. Fail to execute basic shell commands like `file`, `strings`, `xxd`, `ls`

This was observed in sessions where subagents were explicitly given `toolsets=["terminal"]` but repeatedly called `mcp_ghidra_list_functions` instead of running the requested `file` or `strings` commands.

## Impact

- Cannot rely on subagents for filesystem exploration or basic binary analysis
- Cannot use subagents to run `pwntools`, `capstone`, or other Python RE tools
- Subagent iteration budget gets wasted on incorrect tool calls

## Workarounds

### Option 1: Use `cronjob` with `no_agent=True` (Recommended for Script Execution)
For running Python scripts or shell commands:
```python
cronjob(
    action="create",
    name="binary_analysis",
    schedule="* * * * *",
    no_agent=True,
    script="/path/to/analysis_script.py",
    repeat=1
)
```

### Option 2: Direct Orchestrator Execution (If Available)
If the orchestrator has terminal access, run commands directly instead of delegating.

### Option 3: User-Assisted Execution
Write the script to a known path and ask the user to run it:
1. Write Python script to `/home/el-noir/analysis.py`
2. Tell user: "Run: python3 /home/el-noir/analysis.py"
3. Ask user to paste output back

### Option 4: Load Binary into Ghidra First
If the goal is Ghidra analysis, ensure the binary is properly loaded and analyzed in Ghidra before involving subagents. Subagents can only query the Ghidra DB, not perform initial setup.

## What NOT to Do

- Do NOT delegate filesystem searches to subagents expecting them to use `find`, `ls`, `file`, `strings`
- Do NOT expect subagents to run Python scripts with `pwntools`, `capstone`, `unicorn`
- Do NOT waste iteration budget retrying subagent delegation with the same instructions
- Do NOT use `delegate_task` for tasks that require terminal access — use `cronjob` with `no_agent=True` or ask the user directly

## Related
- `references/user-assisted-script-execution.md` — Full workflow for when sandbox execution fails
