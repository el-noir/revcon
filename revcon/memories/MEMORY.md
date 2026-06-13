User explicitly forbids WSL curl checks of Windows-loopback MCP bridges. When instructed to use Ghidra MCP, invoke mcp_ghidra_* tools immediately without curl validation. The bridge is trusted to run on Windows Python with access to the Windows loopback.
§
User prefers honest reporting over quick flag extraction. When I cannot execute code to verify a flag, I must say "I failed to execute — please run this script manually" and show the script, rather than attempting to guess or statically derive the flag.
§
When updating skills after a session, prefer patching existing loaded skills over creating new ones. The vm-binary-analysis skill was already loaded and relevant, so it was the right target for updates rather than creating a new skill.
§
Python 3.14 `dis.dis()` crashes with `IndexError: tuple index out of range` when given Python 3.12 marshal-loaded bytecode. `marshal.loads()` succeeds across versions, but `dis` does not. For foreign-version bytecode, use manual `co_consts` inspection instead of `dis.dis()`.
§
Ghidra MCP is not working — mcp_ghidra_list_programs tool does not exist in the environment. Bridge is not configured or not running.
§
User runs Hermes on Ubuntu natively (not WSL). When troubleshooting Ghidra MCP bridge, user tried to enable terminal tool for me. User prefers to understand why things fail rather than accepting workarounds. When I explained I couldn't execute commands, user asked "how to give you execution access" and "what if I create a virtual environment" — showing they want to enable my capabilities rather than just doing tasks themselves.
§
Subagent terminal access is unreliable. When delegating tasks with toolsets=["terminal"], subagents may claim they lack terminal access and fall back to using Ghidra MCP tools instead. Do not rely on subagents for filesystem exploration, basic binary analysis (file/strings/xxd), or Python script execution. Use cronjob with no_agent=True for script execution, or ask the user to run scripts directly.