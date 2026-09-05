$ErrorActionPreference = 'Continue'

$scanner = Join-Path $PSScriptRoot 'BedrockScanner.exe'
if (-not (Test-Path $scanner)) {
    Write-Host "BedrockScanner.exe must be in the same folder as this script." -ForegroundColor Red
    exit 1
}

$report = Join-Path $PSScriptRoot 'scan-report-v26.45-v2.txt'
"Bedrock v26.45 discovery report v2 - $(Get-Date -Format o)" | Set-Content $report

function Run-Scanner {
    param([string[]]$Arguments)
    $text = (& $scanner @Arguments 2>&1 | Out-String)
    $text | Tee-Object -FilePath $report -Append | Write-Host
    return $text
}

Write-Host "[+] Capturing module/section fingerprint..."
Run-Scanner @() | Out-Null

# Current 1.26.x / late-2026 public Bedrock RE anchors. These are still treated as
# candidates and are validated on the exact running 1.26.4501.0 binary.
$candidates = @(
    @{ Name = 'ClientInstance_vtable'; Pattern = '48 8D 05 ?? ?? ?? ?? 49 89 45 00 48 8D 05 ?? ?? ?? ?? 49 89 45 18 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ??'; Rip = $true; InstanceScan = $true; ClientSlots = $true },
    @{ Name = 'LocalPlayer_vtable'; Pattern = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 87 08 0F 00 00 48 89 85 ?? ?? ?? ?? C6 87 30 0F 00 00 00 C6 87 39 0F 00 00 00'; Rip = $true; InstanceScan = $true },
    @{ Name = 'Level_vtable'; Pattern = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 05 ?? ?? ?? ?? 48 89 47 18 48 8D 05 ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 89 47 20'; Rip = $true; InstanceScan = $true },
    @{ Name = 'Actor_vtable_1_26'; Pattern = '48 8D 05 ?? ?? ?? ?? 48 89 01 49 8B 01 48 89 41 08 49 8B 41 08 48 89 41 10 41 8B 41 10 89 41 18 48 89 69'; Rip = $true },
    @{ Name = 'ClientInstance_update_1_26'; Pattern = '48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B F1 E8 ?? ?? ?? ?? 48 8B D8' },
    @{ Name = 'ClientInstance_updateScreenSize_1_26'; Pattern = '48 8B C4 48 89 58 ?? 48 89 70 ?? 55 57 41 54 41 56 41 57 48 8D 68 ?? 48 81 EC ?? ?? ?? ?? 0F 29 70 ?? 0F 29 78 ?? 44 0F 29 40 ?? 44 0F 29 48 ?? 44 0F 29 50 ?? 44 0F 29 98 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 28 FB' },
    @{ Name = 'LevelRenderer_renderLevel_1_26'; Pattern = '48 8B C4 48 89 58 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 0F 29 70 ?? 0F 29 78 ?? 44 0F 29 40 ?? 44 0F 29 48 ?? 44 0F 29 90 ?? ?? ?? ?? 44 0F 29 98 ?? ?? ?? ?? 44 0F 29 A0 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 4D 8B F0' },
    @{ Name = 'LocalPlayer_applyTurnDelta_1_26'; Pattern = '48 8B C4 48 89 58 ?? 48 89 70 ?? 48 89 78 ?? 55 41 54 41 55 41 56 41 57 48 8D 68 ?? 48 81 EC ?? ?? ?? ?? 0F 29 70 ?? 0F 29 78 ?? 44 0F 29 40 ?? 44 0F 29 48 ?? 44 0F 29 50 ?? 44 0F 29 98 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 4C 8B EA' },
    @{ Name = 'ClientInstance_getLocalPlayerIndex_short'; Pattern = '49 8B 00 49 8B C8 48 8B 80 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 85 C0' }
)

foreach ($candidate in $candidates) {
    $header = "`n===== $($candidate.Name) ====="
    Write-Host $header -ForegroundColor Cyan
    $header | Add-Content $report

    $args = @('--section', '.text', '--pattern', $candidate.Pattern)
    if ($candidate.Rip) { $args += @('--rip', '3', '7') }
    $output = Run-Scanner $args

    if ($candidate.Rip) {
        $ripTargets = [regex]::Matches($output, 'RIP_TARGET=0x([0-9A-Fa-f]+)') |
            ForEach-Object { '0x' + $_.Groups[1].Value } |
            Select-Object -Unique

        foreach ($target in $ripTargets) {
            "`n----- resolved $($candidate.Name): $target -----" | Add-Content $report
            Write-Host "[+] $($candidate.Name) resolved to $target" -ForegroundColor Green

            if ($candidate.InstanceScan) {
                Write-Host "[+] Looking for live objects whose first pointer is $target ..."
                Run-Scanner @('--pointer', $target, '--limit', '64') | Out-Null
            }

            if ($candidate.ClientSlots) {
                "`n----- ClientInstance vslot 0x1E (getRegion/BlockSource candidate) -----" | Add-Content $report
                Write-Host "[+] Dumping ClientInstance vslot 0x1E"
                Run-Scanner @('--vslot', $target, '0x1E') | Out-Null

                "`n----- ClientInstance vslot 0x1F (getLocalPlayer candidate) -----" | Add-Content $report
                Write-Host "[+] Dumping ClientInstance vslot 0x1F"
                Run-Scanner @('--vslot', $target, '0x1F') | Out-Null
            }
        }
    }
}

Write-Host "`n[+] Finished. Report: $report" -ForegroundColor Green
Write-Host "Send scan-report-v26.45-v2.txt back. The important parts are vtable matches, pointer matches, and the 0x1E/0x1F function dumps."
