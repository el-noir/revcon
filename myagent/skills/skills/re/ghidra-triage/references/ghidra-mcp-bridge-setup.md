# Ghidra MCP Bridge Setup & Troubleshooting

## Prerequisites
- Ghidra installed and running
- GhidraMCP script loaded in Ghidra (the Java/Python side that exposes the HTTP API)
- Python 3 with pip available

## Bridge Installation

The bridge (`bridge_mcp_ghidra.py`) requires the `mcp` Python package (FastMCP from the official Model Context Protocol SDK).

### Common Error: `ModuleNotFoundError: No module named 'mcp'`

This means the MCP SDK is not installed. Do NOT try `apt install python3-mcp` — that package does not exist.

### Installation Options (in order of preference)

**Option 1: pip with --break-system-packages (fastest for dev VMs)**
```bash
pip3 install mcp --break-system-packages
```
Use this on dedicated development VMs where breaking the system Python is acceptable. This is the most common path on Ubuntu/Debian systems that enforce PEP 668.

**Option 2: uv run (zero setup, if uv is installed)**
The bridge script includes PEP 723 inline metadata declaring dependencies. If `uv` is available:
```bash
cd ~/Downloads/GhidraMCP-release-1-4
uv run bridge_mcp_ghidra.py
```
This automatically creates an ephemeral venv and installs `mcp>=1.2.0`.

**Option 3: Virtual environment (cleaner, recommended for persistent systems)**
```bash
python3 -m venv ~/ghidra-mcp-venv
source ~/ghidra-mcp-venv/bin/activate
pip install mcp
# Run bridge from within the venv
cd ~/Downloads/GhidraMCP-release-1-4
python3 bridge_mcp_ghidra.py
```

**Option 4: pipx**
```bash
sudo apt install pipx -y
pipx install mcp
```

### PEP 668 Externally-Managed Environment

Modern Ubuntu/Debian systems enforce PEP 668. If you see:
```
error: externally-managed-environment
```

You must use one of the four options above. Do NOT try to override with random flags.

## Running the Bridge

```bash
cd ~/Downloads/GhidraMCP-release-1-4
python3 bridge_mcp_ghidra.py
```

The bridge connects to Ghidra's internal HTTP server (usually 127.0.0.1:8080 or 8081) and exposes MCP tools over stdio.

## Testing the Connection

In another terminal:
```bash
hermes mcp test ghidra
```

Expected: `✓ Connection succeeded`

## Troubleshooting Checklist

1. Is Ghidra actually running with the MCP server script loaded?
2. Is the bridge script pointing to the correct Ghidra HTTP port?
3. Is the `mcp` package installed in the Python environment being used?
4. If using a venv, is it activated before running the bridge?
5. Check Ghidra's script manager — the MCP server script must be running inside Ghidra first.

## Hermes MCP Configuration

The bridge is typically configured in `~/.hermes/config.yaml` as:
```yaml
mcp:
  ghidra:
    transport: stdio
    command: python3
    args: ["/path/to/bridge_mcp_ghidra.py"]
```

If the bridge is in a venv, use the venv's python path:
```yaml
    command: /home/user/ghidra-mcp-venv/bin/python3
```

## Agent Tool Access Note

When a user runs `hermes tools enable terminal`, this enables the tool in the Hermes
configuration but does not automatically add `terminal` to the agent's available
function list. The agent can only use tools explicitly provided in its toolset.
If the agent lacks `terminal` or `execute_code`, it cannot run commands directly
and must delegate to sub-agents or use cronjobs.
