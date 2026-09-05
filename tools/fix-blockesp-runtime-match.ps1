param(
    [string]$SourceDir = "upstream-necromancer"
)

$ErrorActionPreference = 'Stop'

$blockEsp = Join-Path $SourceDir 'src/client/feature/module/modules/visual/BlockESP.cpp'
$text = Get-Content -LiteralPath $blockEsp -Raw

$old = @'
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

$new = @'
                    int idx;
                    auto it = blockLookup.find(block);
                    if (it == blockLookup.end()) {
                        idx = -1;

                        // A world block may be any BlockState permutation, while the
                        // picker catalog stores the default state. Those state pointers
                        // are therefore not expected to be equal. Both states point back
                        // to the same BlockLegacy at +backPtr, so compare that identity.
                        auto runtimeLegacy = safeReadAs<void*>(
                            reinterpret_cast<char const*>(block) + blockLegacyBackPtrOffset);

                        if (runtimeLegacy && *runtimeLegacy) {
                            for (auto const& cat : catalog) {
                                if (!cat.block) continue;
                                auto catLegacy = safeReadAs<void*>(
                                    reinterpret_cast<char const*>(cat.block) + blockLegacyBackPtrOffset);
                                if (!catLegacy || !*catLegacy || *catLegacy != *runtimeLegacy) continue;

                                for (size_t i = 0; i < entries.size(); i++) {
                                    if (entries[i]->id == cat.id) {
                                        idx = static_cast<int>(i);
                                        break;
                                    }
                                }
                                if (idx >= 0) break;
                            }
                        }

                        if (blockLookup.size() >= blockLookupCap) blockLookup.clear();
                        blockLookup.emplace(block, idx);
                    } else {
                        idx = it->second;
                    }
'@

if (-not $text.Contains($old)) {
    throw 'Runtime-state BlockESP patch did not match expected Mine Mod code.'
}

$text = $text.Replace($old, $new)
Set-Content -LiteralPath $blockEsp -Value $text -Encoding utf8
Write-Host '[+] BlockESP runtime-state matching fixed: BlockState -> BlockLegacy identity.' -ForegroundColor Green
