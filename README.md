# MINE MOD - Minecraft Bedrock 26.45 XRay

Internal Windows x64 client for the exact Bedrock build used during development (`Minecraft.Windows.exe` 1.26.4501.0 / 26.45).

The XRay implementation follows the BlockLegacy render-layer approach used by open-source Bedrock clients such as Horion/Borion: selected blocks keep their normal render layer while ordinary terrain is moved to the XRay layer. This is not a texture pack and it is not the old BlockESP box overlay.

## Package

The GitHub Actions artifact `MineMod-win64` contains:

- `MineModLoader.exe` - loads the DLL into `Minecraft.Windows.exe`
- `MineMod.dll` - internal XRay client
- `xray-blocks.txt` - editable list of blocks that remain visible
- `BedrockScanner.exe` / `probe-v2645.ps1` - diagnostics kept for signature updates

## Use

1. Keep `MineModLoader.exe`, `MineMod.dll`, and `xray-blocks.txt` in the same folder.
2. Open Minecraft Bedrock 26.45. Injecting before entering the world is preferred because new chunk geometry will be built with XRay already enabled.
3. Run `MineModLoader.exe`.
4. XRay enables automatically after the render-layer hook is validated.

Keys:

- `F6` - toggle XRay
- `F7` - write detailed signature / BlockLegacy diagnostics to `%TEMP%\MineMod.log`
- `F8` - request a chunk geometry rebuild
- `F12` - disable, restore the patched function, and unload the DLL

If XRay is toggled while already inside a world and old chunks do not immediately refresh, press `F8`. If the rebuild signature changed, leaving and re-entering the world also rebuilds the chunks through the active XRay hook.

## Choose visible blocks

Edit `xray-blocks.txt`. Each non-comment line is a lowercase substring matched against the Bedrock block identifier. The default is:

```text
ore
ancient_debris
lava
water
chest
spawner
amethyst
vault
```

For example, replacing `ore` with `diamond_ore` makes the filter much narrower.

## Implementation notes

The client does not hard-code an ASLR address. It pattern-scans the loaded `Minecraft.Windows.exe`, resolves `BlockLegacy`, validates the tiny `getRenderLayer` getter before patching it, and uses the current BlockLegacy string layout (`translateName` at `+0x8`) with legacy fallbacks. The known Borion vtable slot is only accepted when the target still decodes as the expected padded integer getter; it is never patched blindly.

The existing ClientInstance signature discovered for 26.45 is also used for the optional in-place chunk rebuild path.
