param(
    [string]$SourceDir = "upstream-necromancer"
)

$ErrorActionPreference = 'Stop'

function Replace-Regex {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Replacement
    )

    $text = Get-Content -LiteralPath $Path -Raw
    $updated = [regex]::Replace($text, $Pattern, $Replacement, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($updated -eq $text) {
        throw "Patch did not match: $Path"
    }
    Set-Content -LiteralPath $Path -Value $updated -Encoding utf8
}

function Replace-Literal {
    param(
        [string]$Path,
        [string]$Old,
        [string]$New
    )

    $text = Get-Content -LiteralPath $Path -Raw
    if (-not $text.Contains($Old)) {
        throw "Literal patch did not match: $Path :: $Old"
    }
    Set-Content -LiteralPath $Path -Value $text.Replace($Old, $New) -Encoding utf8
}

$moduleManager = Join-Path $SourceDir 'src/client/feature/module/ModuleManager.cpp'
$clickGui = Join-Path $SourceDir 'src/client/screen/screens/ClickGUI.cpp'
$necromancer = Join-Path $SourceDir 'src/client/Necromancer.cpp'
$blockEsp = Join-Path $SourceDir 'src/client/feature/module/modules/visual/BlockESP.cpp'
$renderFrameState = Join-Path $SourceDir 'src/client/misc/RenderFrameState.cpp'
$cmake = Join-Path $SourceDir 'CMakeLists.txt'

# Keep the upstream client core, SDK, renderer, hooks, menu and BlockESP dependencies,
# but only register BlockESP as a user-facing module.
Replace-Regex -Path $moduleManager `
    -Pattern 'ModuleManager::ModuleManager\(\) \{.*?(?=ModuleManager::~ModuleManager\(\))' `
    -Replacement @'
ModuleManager::ModuleManager() {
    this->items.push_back(std::make_shared<BlockESP>());

    for (auto& mod : items) {
        mod->onInit();
    }
    Eventing::get().listen<KeyUpdateEvent>(this, (EventListenerFunc)&ModuleManager::onKey);
}

'@

# The menu stays intact (search/settings/block picker), but only BlockESP is visible.
Replace-Regex -Path $clickGui `
    -Pattern 'bool ClickGUI::isModuleInTab\(Module& mod\) const \{.*?(?=void ClickGUI::refreshConfigList\(\))' `
    -Replacement @'
bool ClickGUI::isModuleInTab(Module& mod) const {
    return modTab == VISUALS && mod.name() == "BlockESP";
}

'@

# Bedrock 1.26.4501.0 changed mce::RenderMaterialGroup::common. That signature is
# only needed by the game's native 3D material path. Mine Mod renders BlockESP via
# the existing D2D projection path instead, so do not make startup depend on it.
Replace-Literal -Path $necromancer `
    -Old '        MVSIG(RenderMaterialGroup__common),' `
    -New '        // Mine Mod Slim: RenderMaterialGroup__common intentionally not required.'

# The upstream projection snapshot is normally produced only for AntiObs. Mine Mod
# uses the same projection data for its normal on-screen BlockESP, so capture it every
# render-level event without enabling or registering AntiObs.
Replace-Literal -Path $renderFrameState `
    -Old '    if (!AntiObs::isActive()) return;' `
    -New '    // Mine Mod Slim: always capture projection state for the D2D BlockESP overlay.'

# Keep BlockESP's scanning logic, but remove its native Minecraft 3D material render
# path. This avoids RenderMaterialGroup entirely on 1.26.4501.0.
Replace-Regex -Path $blockEsp `
    -Pattern '    if \(found\.empty\(\)\) return;\s+if \(AntiObs::isActive\(\)\) return;\s+MCDrawUtil3D dc \{ ci->levelRenderer, SDK::ScreenContext::instance3d, SDK::MaterialPtr::getUIColor\(\) \};.*?    dc\.drawThickBoxes\(thickBoxes\);\s+\}' `
    -Replacement @'
    if (found.empty()) return;

    // Mine Mod Slim: scanning happens here; rendering happens in the D2D overlay.
}
'@

# Project BlockESP every overlay frame regardless of AntiObs state.
Replace-Literal -Path $blockEsp `
    -Old "void BlockESP::onRenderOverlay(Event&) {`r`n    if (!AntiObs::isActive()) return;" `
    -New "void BlockESP::onRenderOverlay(Event&) {"

# The upstream scan identifies each block by dereferencing Block::legacyBlock and
# reading BlockLegacy::namespacedId. The Block layout changed in 1.26.4501.0, so that
# stale field is the likely access violation that happens immediately after adding a
# block (the scan starts as soon as entries becomes non-empty). For Mine Mod, the
# picker catalog has already resolved stable Block state pointers. Match those pointer
# identities instead, which avoids dereferencing the stale Block layout entirely.
Replace-Regex -Path $blockEsp `
    -Pattern '                    int idx;\s+                    auto it = blockLookup\.find\(block\);\s+                    if \(it == blockLookup\.end\(\)\) \{\s+                        idx = -1;\s+                        auto legacy = block->legacyBlock;\s+                        if \(legacy\) \{.*?                        \}\s+                        if \(blockLookup\.size\(\) >= blockLookupCap\) blockLookup\.clear\(\);\s+                        blockLookup\.emplace\(block, idx\);\s+                    \} else \{\s+                        idx = it->second;\s+                    \}' `
    -Replacement @'
                    int idx;
                    auto it = blockLookup.find(block);
                    if (it == blockLookup.end()) {
                        idx = -1;

                        // Mine Mod Slim: no Block::legacyBlock dereference here.
                        // The picker catalog's state pointer is already validated enough
                        // to render its icon; use that same pointer as the scan key.
                        for (auto const& cat : catalog) {
                            if (cat.block != block) continue;
                            for (size_t i = 0; i < entries.size(); i++) {
                                if (entries[i]->id == cat.id) {
                                    idx = static_cast<int>(i);
                                    break;
                                }
                            }
                            if (idx >= 0) break;
                        }

                        if (blockLookup.size() >= blockLookupCap) blockLookup.clear();
                        blockLookup.emplace(block, idx);
                    } else {
                        idx = it->second;
                    }
'@

# A persisted block list may start scanning before the picker has ever been opened in
# this session. Build the safe catalog once before scanning so pointer matching works.
Replace-Literal -Path $blockEsp `
    -Old "    if (!lp || !region) return;`r`n`r`n    Vec3 p = lp->getPos();" `
    -New "    if (!lp || !region) return;`r`n`r`n    if (catalog.empty()) rebuildCatalog();`r`n    if (catalog.empty()) return;`r`n`r`n    Vec3 p = lp->getPos();"

# Reduce the default scan radius a little while we stabilize this exact build. The
# scanner is time-budgeted already; this mainly shortens a full sweep after edits.
Replace-Literal -Path $blockEsp `
    -Old '    constexpr int scanRadius = 96;' `
    -New '    constexpr int scanRadius = 48;'

# Rename the produced DLL without renaming internal upstream classes/namespaces.
$cmakeText = Get-Content -LiteralPath $cmake -Raw
$cmakeText = $cmakeText.Replace('OUTPUT_NAME_RELEASE "Necromancer${NECROMANCER_NAME_SUFFIX}"', 'OUTPUT_NAME_RELEASE "MineMod"')
$cmakeText = $cmakeText.Replace('PDB_NAME_RELEASE "Necromancer${NECROMANCER_NAME_SUFFIX}"', 'PDB_NAME_RELEASE "MineMod"')
Set-Content -LiteralPath $cmake -Value $cmakeText -Encoding utf8

# Add a clear notice alongside the source tree.
@'
MINE MOD SLIM

This build is a modified version of Necromancer Client.
Upstream: https://github.com/asdasfxcvxcvcb/necromancer-minecraft-bedrock
License: GNU GPL v3

Changes made by this patcher:
- ModuleManager registers only BlockESP.
- ClickGUI exposes only BlockESP in the Visuals tab.
- Release output is named MineMod.dll.
- RenderMaterialGroup::common is not a required startup signature.
- BlockESP renders through the normal D2D projected overlay instead of the native 3D material path.
- Projection frame state is captured without enabling AntiObs.
- Block scanning identifies selected states by catalog pointer instead of stale Block::legacyBlock layout.
- Default scan radius is reduced to 48 blocks while stabilizing Bedrock 1.26.4501.0.

No anti-cheat bypass, stealth, Anti OBS, combat, movement or automation module is registered.
'@ | Set-Content -LiteralPath (Join-Path $SourceDir 'MINE_MOD_NOTICES.txt') -Encoding utf8

Write-Host '[+] Mine Mod slim patches applied.' -ForegroundColor Green
