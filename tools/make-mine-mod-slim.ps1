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

No anti-cheat bypass, stealth, Anti OBS, combat, movement or automation module is registered.
'@ | Set-Content -LiteralPath (Join-Path $SourceDir 'MINE_MOD_NOTICES.txt') -Encoding utf8

Write-Host '[+] Mine Mod slim patches applied.' -ForegroundColor Green
