# MCP Connectivity Troubleshooting — Ghidra

## Problem class

User asks "check if Ghidra MCP is working" or reports that `mcp_ghidra_*` tools are unavailable. The bridge may be mis-configured, the Ghidra server not running, or the MCP layer not handshaking.

## Diagnostic checklist

Run these in order. Stop at the first failure and fix it before proceeding.

### 1. Inspect Hermes config for the `ghidra` server entry

```bash
grep -n "ghidra" ~/.hermes/config.yaml ~/.hermes/profiles/*/config.yaml
```

Expected shape (YAML list syntax for `args`):
```yaml
mcp_servers:
  ghidra:
    command: python3
    args:
      - /home/el-noir/Downloads/GhidraMCP-release-1-4/bridge_mcp_ghidra.py
      - --ghidra-server
      - http://127.0.0.1:8080
    enabled: true
```

**Common misconfigurations:**
- Path uses Windows backslashes (`home\el-noir\...`) or is relative instead of absolute.
- `args` is a single string instead of a YAML list (causes Pydantic `list_type` error).
- `command` is `python3` but the bridge script is a Windows `.py` that needs `python.exe`.

### 2. Verify the bridge script exists and is readable

```bash
ls -la <absolute_path_to_bridge_mcp_ghidra.py>
```

If the path is under `/mnt/c/...`, ensure it is accessible from the WSL environment.

### 3. Check if the Ghidra HTTP backend is listening

```bash
ss -tlnp | grep 8080
# or
netstat -tlnp | grep 8080
```

If nothing is listening, the Ghidra server itself is not running. Start it from Ghidra GUI: **File → Server → Start Server** or use the `ghidraSvr` script.

### 4. Test the bridge script manually

```bash
cd <bridge_directory>
python3 bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080
```

Watch for:
- Python import errors (`mcp` package missing) → install `mcp` (see `pip install mcp` or `uv run` notes in SKILL.md pitfalls).
- Connection refused / timeout → Ghidra server not on port 8080.
- Successful startup → bridge is healthy; the issue is likely Hermes MCP client discovery.

### 5. Test via Hermes MCP client

```bash
hermes mcp list
hermes mcp test ghidra
```

- `hermes mcp list` shows `all` instead of enumerated tools → runtime discovery failed; fall back to bridge-script extraction (see `references/bridge-script-tool-extraction.md`).
- `hermes mcp test ghidra` returns `Connection failed (...): Connection closed` → MCP-layer handshake failure. The bridge may have started but the Hermes client cannot speak to it. Restart the bridge, check for port conflicts, or verify the `command`/`args` in config.

### 6. Try a direct tool call from a sub-agent

Spawn a sub-agent with the `terminal` toolset and have it run:
```bash
python3 -c "from mcp import ClientSession; ..."  # or equivalent probe
```
If the sub-agent also fails, the issue is environment-wide (missing package, wrong Python). If it succeeds, the issue is Hermes-specific.

## Important: WSL loopback caveat

Do **not** use WSL `curl http://127.0.0.1:8080` to test a Ghidra server that is running inside Windows Python/Ghidra. The Windows loopback is not reliably reachable from WSL curl. Use `ss`/`netstat` from WSL, or test from a Windows terminal instead.

## Fixing the config path

If the config path is wrong, edit `~/.hermes/profiles/<profile>/config.yaml` manually with `nano` or `vim`. `hermes config set` does **not** handle list values correctly and will serialize `args` as a string, breaking the server.

After editing, run `hermes mcp test ghidra`, then start a new session (`/reset`) for tool discovery to take effect.
