# Bedrock External Scanner

External read-only scanner foundation for Minecraft Bedrock on Windows.

The scanner attaches to `Minecraft.Windows.exe` with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`, enumerates the main PE image, reads sections, supports AOB/pattern scanning with wildcards, and resolves RIP-relative addresses. It does **not** inject code or write to the game process.

## Build

### Visual Studio / CMake

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output: `build/Release/BedrockScanner.exe`

### GitHub Actions

Every push to `main` builds a Windows x64 artifact named `BedrockScanner-win64` containing:

- `BedrockScanner.exe`
- `probe-v2645.ps1`
- this README

## Usage

```powershell
BedrockScanner.exe
BedrockScanner.exe --module Minecraft.Windows.exe
BedrockScanner.exe --pattern "48 8B 0D ? ? ? ? 48 85 C9" --section .text
BedrockScanner.exe --pattern "48 8B 0D ? ? ? ?" --section .text --rip 3 7
```

`--rip <dispOffset> <instructionSize>` resolves a 32-bit RIP-relative displacement from each match.

## v26.45 probe

1. Open Minecraft Bedrock v26.45 and enter a world.
2. Keep `BedrockScanner.exe` and `probe-v2645.ps1` in the same folder.
3. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\probe-v2645.ps1
```

The script tests a small set of **candidate** Bedrock signatures and creates `scan-report-v26.45.txt`. These signatures are probes, not trusted offsets; matches need to be validated on the exact game build before they are used.

## Next step for the XRay

Use the v26.45 report to validate anchors for player/level/dimension/block access. Once stable runtime anchors are confirmed, move them into a versioned signature table and then implement the external world/chunk reader and overlay. Avoid hard-coded absolute addresses so ASLR and small game updates do not immediately break the scanner.
