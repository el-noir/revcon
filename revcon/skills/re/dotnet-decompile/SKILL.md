---
name: dotnet-decompile
description: Decompile and analyze .NET (C#) binaries using ilspycmd. Use this when analyzing .NET executables or DLLs.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, dotnet, csharp, decompile, ilspy]
    category: re
---
# .NET Binary Decompilation Skill

## When to Use
Use this skill when you encounter a .NET binary. You can recognize a .NET binary by:
- Importing `_CorExeMain` or `_CorDllMain` from `mscoree.dll` (found via Ghidra `list_imports`).
- Executable files that contain typical .NET structures.
Trigger: user says "decompile dotnet", "ilspy", "decompile C#", or when Ghidra shows the binary is a .NET assembly.

## Critical Rules
1. Always run `ilspycmd` using command execution in the WSL environment.
2. Since path configurations may vary, specify the absolute path `/home/el-noir/.dotnet/tools/ilspycmd` to execute the tool if `ilspycmd` is not found in the global path.
3. Decompiled output can be large. Use output redirection or specify output folders (`-o`) rather than outputting everything to the terminal.

## Analysis Procedure

### Phase 1 — List Assembly Members
List all types/namespaces defined in the assembly to locate the entry point or main application logic.
Command:
```bash
/home/el-noir/.dotnet/tools/ilspycmd <path_to_assembly> -l
```

### Phase 2 — Target Decompilation
1. **Decompile a specific type/class** (most recommended to avoid clutter):
   ```bash
   /home/el-noir/.dotnet/tools/ilspycmd <path_to_assembly> -t <Namespace.TypeName>
   ```
2. **Decompile the whole assembly into a C# project** (useful for complex binaries):
   Create a target directory and decompile:
   ```bash
   mkdir -p /mnt/c/Users/el-noir/Downloads/decompiled_dotnet
   /home/el-noir/.dotnet/tools/ilspycmd <path_to_assembly> -p -o /mnt/c/Users/el-noir/Downloads/decompiled_dotnet
   ```

### Phase 3 — High-Yield Search Targets
Search the decompiled C# source files or listing for:
- Main class: Look for `Program` or `Main`.
- Encryption keys: Look for `RijndaelManaged`, `Aes`, `TripleDES`, `byte[] Key`, `byte[] IV`.
- String decryption methods: Look for custom XOR routines.
- Network endpoints: Look for HTTP requests, IPs, or domains.

## Reporting Format
Produce a .NET specific analysis report, including:
1. Entry point class and method.
2. Structure of key classes/namespaces.
3. Decompiled C# source of the validation routines.
4. Extracted strings or keys.

## Known Pitfalls and Workarounds

### .NET SDK/version mismatch for ilspycmd
ilspycmd snapshots often target an older `Microsoft.NETCore.App` than the machine has. Symptoms: "You must install or update .NET to run this application" or "framework version 6.0.0 (x64) not found when only 8.0+ is installed." Fix sequence:
```bash
dotnet tool uninstall -g ilspycmd
dotnet tool install -g ilspycmd
```
If `install` still complains about `DotnetToolSettings.xml was not found`, the NuGet package for that invocation is bad; retry after network/refresh.

If only a fixed version string existed and NuGet returned "Version 8.0.0 of package ilspycmd is not found", the fix is to omit `--version` and install the latest compatible package rather than hardcoding a specific version.

### Hermes profile-scoped .NET tool resolution
In some Hermes environments, `~/.dotnet/tools/ilspycmd` can resolve under the active profile’s sheltered home (`~/.hermes/profiles/<profile>/home/.dotnet/tools/ilspycmd`). If the binary exists but `which` / `realpath` disagrees, discover it by inspecting the profile home tree rather than assuming a home-relative path.

### ilspycmd fallback path
- If repeated install/uninstall/fix attempts fail, do not loop on reinstalls. Pivot to:
  - `strings -e l <assembly>` for readable .NET strings (UTF-16)
  - `monodis`, `ikdasm`, or `ildasm` for raw IL
  - `dnSpy` or `ILSpy` GUI/CLI variants if available on Windows
  - Pattern-based heuristics from plain `strings` match output for flags and encoded payloads

### .NET list query survival
Preferred discovery commands still run regardless of .NET tool availability: `strings`, `file`, `readelf -S`, `objdump -h`. Use them to validate format (`PE32 Mono/.Net assembly`, presence of `_CorExeMain` in exports) before concluding decompilation is required.
