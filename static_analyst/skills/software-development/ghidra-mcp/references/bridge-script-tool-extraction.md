# Bridge Script Tool Extraction

## Problem

`hermes mcp list` returned `all` for the `ghidra` server and did not enumerate
individual tools. The Python `mcp` package was also missing in the active
environment, so runtime discovery via the Hermes MCP client was unavailable.

## Solution

Read the server's bridge script directly and extract function names from
`@mcp.tool()` decorators.

### Files inspected

- `/mnt/c/Users/el-noir/Downloads/GhidraMCP-release-1-4/GhidraMCP-release-1-4/bridge_mcp_ghidra.py`
- `/home/el-noir/.hermes/config.yaml`
- `/home/el-noir/.hermes/profiles/myagent/config.yaml`

## Config pattern / tool discovery

- `mcp_servers.ghidra.enabled: true`
- `command` points to Windows Python
- `args` contains the bridge script path plus `--ghidra-server http://127.0.0.1:8080`
- If `hermes mcp list` shows `all`, extract tools directly from `bridge_mcp_ghidra.py` decorators instead of relying on MCP runtime discovery.

## Verified tool surface (bridge script)

27 tools confirmed from `@mcp.tool()` decorators in `bridge_mcp_ghidra.py`:
`list_methods, list_classes, decompile_function, rename_function, rename_data, list_segments, list_imports, list_exports, list_namespaces, list_data_items, search_functions_by_name, rename_variable, get_function_by_address, get_current_address, get_current_function, list_functions, decompile_function_by_address, disassemble_function, set_decompiler_comment, set_disassembly_comment, rename_function_by_address, set_function_prototype, set_local_variable_type, get_xrefs_to, get_xrefs_from, get_function_xrefs, list_strings`.

## Runtime notes

- `hermes mcp test ghidra` can fail with `Connection failed (...): Connection closed` even when the bridge script and config are valid. This indicates an MCP-layer handshake issue, not that `http://127.0.0.1:8080` is down.
- Do not use WSL curl against `http://127.0.0.1:8080` to judge bridge health when the bridge runs through Windows Python. That loopback is not reliable across the WSL-to-Windows boundary.
instead of `python3 -e` / bash heredocs for inline execution when approval
behavior is ambiguous. This is a runtime policy detail, not a durable rule.