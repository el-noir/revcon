# Hermes Agent Multi-Profile Setup

Orchestrated multi-agent Hermes configuration for CTF/RE workflows and general-purpose task delegation.

## Installation

Each folder below must be copied into `~/.hermes/profiles/` as a profile directory.

```bash
git clone <repo-url>.git /tmp/hermes-profiles
cp -R /tmp/hermes-profiles/* ~/.hermes/profiles/
```

After copying, restart Hermes or switch profiles with `hermes profile <name>`.

## Profiles

| Directory | Purpose |
|-----------|---------|
| `myagent/` | Orchestrator. Decomposes tasks into Kanban cards and delegates to subagents. |
| `static_analyst/` | Static binary and bytecode analysis. |
| `sandbox_runner/` | Dynamic execution, sandboxed runtime, and fuzzing harnesses. |
| `osint_analyst/` | OSINT, reconnaissance, and threat-intel gathering. |
| `exploit_dev/` | Exploit development, payload crafting, and PoC generation. |

## Orchestration Architecture

```
  User
    |
    v
  myagent (orchestrator)
    |
    +---> static_analyst  (static analysis)
    +---> sandbox_runner   (dynamic / runtime)
    +---> osint_analyst    (OSINT / recon)
    +---> exploit_dev      (exploit dev / payloads)
    |
    v
  Final synthesized report
```

`myagent` uses Hermes Kanban to assign cards to subagents, collects results, and produces the final report.

## Prerequisites

- Hermes Agent installed
- Profiles enabled in Hermes config (default profile dir: `~/.hermes/profiles/`)
- Optional for subagent workflows:
  - Docker / Singularity / Modal configured in `myagent/config.yaml`
  - Sandbox image built (e.g. `sandbox-ctf:latest`)
  - `tirith` binary placed in `myagent/bin/` and each subagent `bin/` if security scanning is desired

## Configuration Notes

- Each profile ships a `config.yaml` with secrets blanked out. Fill in your own API keys and provider settings.
- `SOUL.md` defines the agent’s persona and task framing.
- `memories/` contains empty or starter memory files; they’re overwritten at runtime.

## Large Bundled Skill Set

Every profile includes the full bundled skill catalog under `skills/`. This means:
- Strong out-of-the-box capability.
- Large repository size (~500+ files per profile).

If you want a minimal profile, trim `skills/` to only the categories you need.

## License

Private / organizational use.
