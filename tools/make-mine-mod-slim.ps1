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

$moduleManager = Join-Path $SourceDir 'src/client/feature/module/ModuleManager.cpp'
$clickGui = Join-Path $SourceDir 'src/client/screen/screens/ClickGUI.cpp'
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

No anti-cheat bypass, stealth, Anti OBS, combat, movement or automation module is registered.
'@ | Set-Content -LiteralPath (Join-Path $SourceDir 'MINE_MOD_NOTICES.txt') -Encoding utf8

Write-Host '[+] Mine Mod slim patches applied.' -ForegroundColor Green
