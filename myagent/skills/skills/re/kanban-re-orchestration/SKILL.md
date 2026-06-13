---
name: kanban-re-orchestration
description: Orchestrate reverse engineering work across named Hermes profiles using Kanban cards instead of anonymous subagents.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, kanban, orchestration, malware-analysis]
    category: re
---

# Kanban RE Orchestration

## When to Use
Use this for any non-trivial reverse engineering request: binary triage, malware analysis, CTF solving, packed binaries, dynamic traces, OSINT, or final reporting.

## Specialist Map
- `static_analyst`: Ghidra MCP, imports, strings, functions, decompilation, XREFs, static reports.
- `sandbox_runner`: Modal sandbox execution, pwntools, Frida, Unicorn/Capstone, unpacking, runtime observations.
- `osint_analyst`: web research, CVEs, malware family context, IOC enrichment.
- `exploit_dev`: exploit or proof-of-concept work only when explicitly needed.

## Procedure
1. Normalize paths. Convert `D:\path\file.exe` to `/mnt/d/path/file.exe`.
2. Create a static triage card for `static_analyst` unless the user only asks OSINT.
3. Create dynamic/sandbox cards for `sandbox_runner` only when execution/emulation is required.
4. Create OSINT cards for `osint_analyst` when hashes, domains, CVEs, malware family, or API docs matter.
5. Put exact acceptance criteria in every card body.
6. Link dependent cards with `parents=[...]`.
7. After cards complete, synthesize the handoffs and cite uncertainty.

## Card Body Template
```text
Target:
- Path:
- Format/arch:
- Hashes:
- Ghidra program name if known:

Task:
- Exact question:
- Required tools/skills:
- Addresses/functions/strings:

Acceptance criteria:
- Must report:
- Must not do:
- Block if:
```

## Pitfalls
- `delegate_task` creates anonymous children. It does not load `static_analyst` or `sandbox_runner`.
- Unknown Kanban assignees stall. Use only known profile names.
- Workers start fresh. Include all context in the card body.
