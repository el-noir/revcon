On this system, `hermes tools list` shows MCP servers but can return `all` instead of enumerated per-tool names, so for fast still running blocks overviews, fall back to reading the server script’s registered tool names directly.
§
When `hermes mcp list` shows `all` instead of individual tools, derive the tool list by reading the MCP server's bridge script and extracting function names from `@mcp.tool()` decorators. This is necessary when the MCP SDK (`mcp` Python package) is not installed and runtime discovery is unavailable.
§
User explicitly forbids WSL curl checks of Windows-loopback MCP bridges. When instructed to use Ghidra MCP, invoke mcp_ghidra_* tools immediately without curl validation. The bridge is trusted to run on Windows Python with access to the Windows loopback.
§
In this Hermes setup, `~/.dotnet/tools/ilspycmd` may resolve under the active profile’s sheltered home directory `~/.hermes/profiles/<profile>/home/.dotnet/tools/`. If a claimed install is missing via one path, probe the profile home tree before reinstalling.
§
picoCTF perplexed challenge: flag is picoCTF{0n3_bi7_4t_a_7im}. Binary uses bit-scrambled comparison (input bits read in order 6,5,4,3,2,1,0,7 per byte) against hardcoded 23-byte array. Length check is 27 bytes but only first 24 are validated.