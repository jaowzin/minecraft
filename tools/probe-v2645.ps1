$ErrorActionPreference = 'Continue'

$scanner = Join-Path $PSScriptRoot 'BedrockScanner.exe'
if (-not (Test-Path $scanner)) {
    Write-Host "BedrockScanner.exe must be in the same folder as this script." -ForegroundColor Red
    exit 1
}

$report = Join-Path $PSScriptRoot 'scan-report-v26.45.txt'
"Bedrock v26.45 candidate signature report - $(Get-Date -Format o)" | Set-Content $report

Write-Host "[+] Capturing module/section fingerprint..."
& $scanner 2>&1 | Tee-Object -FilePath $report -Append

# Candidate signatures gathered from public Bedrock reverse-engineering projects.
# They are probes only: every result must be validated against this exact v26.45 build.
$candidates = @(
    @{ Name = 'Actor_getPosition_A'; Pattern = 'E8 ?? ?? ?? ?? 0F B6 4F ?? 84 C9' },
    @{ Name = 'Actor_getPosition_B'; Pattern = 'E8 ?? ?? ?? ?? F3 0F 10 45 ?? 48 8B CF' },
    @{ Name = 'Actor_getLevel_A'; Pattern = 'E8 ?? ?? ?? ?? 4C 8B C8 45 33 C0 48 8B D7' },
    @{ Name = 'Actor_getRegion'; Pattern = '40 53 48 83 EC ?? 48 8B 91 ?? ?? ?? ?? 45 33 C0' },
    @{ Name = 'Actor_getDimension'; Pattern = '40 53 48 83 EC ?? 48 8B 91 ?? ?? ?? ?? 48 8B D9 48 85 D2 74 ?? 8B 42' },
    @{ Name = 'ClientInstance_update'; Pattern = '48 8B C4 48 89 58 ?? 48 89 70 ?? 48 89 78 ?? 55 41 54 41 55 41 56 41 57 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 0F 29 70 ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 0F B6 F2' },
    @{ Name = 'ClientInstance_getLocalPlayerIndex'; Pattern = '49 8B 00 49 8B C8 48 8B 80 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B C8' }
)

foreach ($candidate in $candidates) {
    $header = "`n===== $($candidate.Name) ====="
    Write-Host $header
    $header | Add-Content $report
    & $scanner --section .text --pattern $candidate.Pattern 2>&1 | Tee-Object -FilePath $report -Append
}

Write-Host "`n[+] Finished. Report: $report" -ForegroundColor Green
Write-Host "Send scan-report-v26.45.txt back so the matches can be validated before any offsets are used."
