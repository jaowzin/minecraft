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

Every push to `main` builds a Windows x64 release artifact named `BedrockScanner-win64`.

## Usage

```powershell
BedrockScanner.exe
BedrockScanner.exe --module Minecraft.Windows.exe
BedrockScanner.exe --pattern "48 8B 0D ? ? ? ? 48 85 C9" --section .text
BedrockScanner.exe --pattern "48 8B 0D ? ? ? ?" --section .text --rip 3 7
```

`--rip <dispOffset> <instructionSize>` resolves a 32-bit RIP-relative displacement from each match.

## Next step for the XRay

Run this build while Bedrock v26.45 is open and capture the scanner output. Once we have validated signatures for the runtime structures (camera/player/world/chunks), they can be moved into a versioned signature table instead of hard-coded absolute addresses.
