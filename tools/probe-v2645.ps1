$ErrorActionPreference = 'Continue'

$scanner = Join-Path $PSScriptRoot 'BedrockScanner.exe'
if (-not (Test-Path $scanner)) {
    Write-Host "BedrockScanner.exe must be in the same folder as this script." -ForegroundColor Red
    exit 1
}

$report = Join-Path $PSScriptRoot 'scan-report-v26.45-v4.txt'
"Bedrock v26.45 discovery report v4 - $(Get-Date -Format o)" | Set-Content $report

function Hex([UInt64]$value) {
    return ('0x{0:X}' -f $value)
}

function Run-Scanner {
    param(
        [string[]]$Arguments,
        [switch]$Quiet
    )

    $text = (& $scanner @Arguments 2>&1 | Out-String)
    $text | Add-Content $report
    if (-not $Quiet) { Write-Host $text }
    return $text
}

function Resolve-VTable {
    param([string]$Name, [string]$Pattern)

    $header = "`n===== $Name ====="
    Write-Host $header -ForegroundColor Cyan
    $header | Add-Content $report

    $output = Run-Scanner @('--section', '.text', '--pattern', $Pattern, '--rip', '3', '7')
    $m = [regex]::Match($output, 'RIP_TARGET=0x([0-9A-Fa-f]+)')
    if (-not $m.Success) {
        Write-Host "[-] Could not resolve $Name" -ForegroundColor Yellow
        return $null
    }

    $value = [Convert]::ToUInt64($m.Groups[1].Value, 16)
    Write-Host "[+] $Name = $(Hex $value)" -ForegroundColor Green
    return $value
}

function Find-PointerRefs {
    param(
        [UInt64]$Target,
        [int]$Limit = 128,
        [string]$Label = ''
    )

    if ($Label) {
        "`n===== $Label =====" | Add-Content $report
        Write-Host "`n[+] $Label" -ForegroundColor Cyan
    }

    $output = Run-Scanner @('--pointer', (Hex $Target), '--limit', $Limit.ToString()) -Quiet
    $matches = [regex]::Matches($output, '(?m)^\s+\[\d+\]\s+(0x[0-9A-Fa-f]+)\s*$')
    $result = New-Object System.Collections.Generic.List[UInt64]
    foreach ($m in $matches) {
        $result.Add([Convert]::ToUInt64($m.Groups[1].Value.Substring(2), 16))
    }

    $line = "[+] refs($(Hex $Target)) = $($result.Count)"
    Write-Host $line
    $line | Add-Content $report
    foreach ($v in $result) {
        $entry = "    $(Hex $v)"
        Write-Host $entry
        $entry | Add-Content $report
    }
    return $result.ToArray()
}

function Find-LiveObject {
    param([string]$Name, [UInt64]$VTable)

    $refs = Find-PointerRefs $VTable 64 "live $Name objects (first pointer == vtable)"
    if ($refs.Count -eq 0) {
        Write-Host "[-] No live $Name object found by exact-vtable scan." -ForegroundColor Yellow
        return $null
    }

    $value = [UInt64]$refs[0]
    Write-Host "[+] $Name object = $(Hex $value)" -ForegroundColor Green
    return $value
}

function Read-RemoteBytes {
    param([UInt64]$Address, [int]$Count)

    $output = Run-Scanner @('--dump', (Hex $Address), $Count.ToString()) -Quiet
    $result = New-Object System.Collections.Generic.List[byte]

    foreach ($line in ($output -split "`r?`n")) {
        if ($line -notmatch '^0x[0-9A-Fa-f]+\s{2}(.+)$') { continue }
        foreach ($token in ($Matches[1] -split '\s+')) {
            if ($token -match '^[0-9A-Fa-f]{2}$') {
                $result.Add([Convert]::ToByte($token, 16))
                if ($result.Count -ge $Count) { break }
            }
        }
        if ($result.Count -ge $Count) { break }
    }

    if ($result.Count -lt $Count) { return $null }
    return $result.ToArray()
}

function Read-RemotePtr {
    param([UInt64]$Address)
    $bytes = Read-RemoteBytes $Address 8
    if ($null -eq $bytes) { return $null }
    return [BitConverter]::ToUInt64($bytes, 0)
}

function Read-RemoteByte {
    param([UInt64]$Address)
    $bytes = Read-RemoteBytes $Address 1
    if ($null -eq $bytes) { return $null }
    return [byte]$bytes[0]
}

function Is-ReadableAddress {
    param([UInt64]$Address)
    if ($Address -eq 0) { return $false }
    return $null -ne (Read-RemoteBytes $Address 1)
}

function Print-PtrField {
    param([string]$Owner, [UInt64]$Base, [UInt64]$Offset, [string]$Name)

    $value = Read-RemotePtr ($Base + $Offset)
    if ($null -eq $value) {
        $line = "[-] $Owner+$('{0:X}' -f $Offset) $Name = <read failed>"
    } else {
        $readable = Is-ReadableAddress $value
        $line = "[+] $Owner+$('{0:X}' -f $Offset) $Name = $(Hex $value) readable=$readable"
    }
    Write-Host $line
    $line | Add-Content $report
    return $value
}

Write-Host "[+] Capturing module/section fingerprint..."
Run-Scanner @() | Out-Null

# Anchors verified on the user's exact 1.26.4501.0 binary.
$clientVtablePattern = '48 8D 05 ?? ?? ?? ?? 49 89 45 00 48 8D 05 ?? ?? ?? ?? 49 89 45 18 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ??'
$levelVtablePattern  = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 05 ?? ?? ?? ?? 48 89 47 18 48 8D 05 ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 89 47 20'
$localVtablePattern  = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 87 08 0F 00 00 48 89 85 ?? ?? ?? ?? C6 87 30 0F 00 00 00 C6 87 39 0F 00 00 00'

$clientVtable = Resolve-VTable 'ClientInstance_vtable' $clientVtablePattern
$levelVtable  = Resolve-VTable 'Level_vtable' $levelVtablePattern
$localVtable  = Resolve-VTable 'LocalPlayer_vtable' $localVtablePattern

if ($null -eq $clientVtable -or $null -eq $levelVtable) {
    Write-Host "[-] Required vtable anchors were not found; stopping." -ForegroundColor Red
    exit 2
}

$client = Find-LiveObject 'ClientInstance' $clientVtable
$level  = Find-LiveObject 'Level' $levelVtable

if ($null -eq $client -or $null -eq $level) {
    Write-Host "[-] Need both live ClientInstance and Level. Enter a world and run again." -ForegroundColor Red
    exit 3
}

"`n===== ClientInstance virtual slots =====" | Add-Content $report
Write-Host "`n[+] ClientInstance vslot 0x1E (getRegion / BlockSource candidate)" -ForegroundColor Cyan
Run-Scanner @('--vslot', (Hex $clientVtable), '0x1E') | Out-Null
Write-Host "[+] ClientInstance vslot 0x1F (getLocalPlayer candidate)" -ForegroundColor Cyan
Run-Scanner @('--vslot', (Hex $clientVtable), '0x1F') | Out-Null

# First show why the copied Necromancer ClientInstance field offsets are not trusted on this exact build.
"`n===== stale-field sanity check =====" | Add-Content $report
Write-Host "`n[+] Testing public 1.26.x ClientInstance field candidates for readability..." -ForegroundColor Cyan
$oldMcGame        = Print-PtrField 'ClientInstance' $client 0x1A0 'MinecraftGame* candidate'
$oldMinecraft     = Print-PtrField 'ClientInstance' $client 0x1A8 'Minecraft* candidate'
$oldLevelRenderer = Print-PtrField 'ClientInstance' $client 0x1B8 'LevelRenderer* candidate'
$oldPacketSender  = Print-PtrField 'ClientInstance' $client 0x1C8 'PacketSender* candidate'
$oldInputHandler  = Print-PtrField 'ClientInstance' $client 0x1D8 'InputHandler* candidate'

# Reverse discovery starts from the independently verified live Level object.
# Necromancer's current GameSession layout has Level* at +0x40 and two readiness checks at +0x28/+0x30.
$gameSession = $null
$levelRefs = Find-PointerRefs $level 256 'reverse chain: references to verified Level'

"`n===== GameSession candidates from Level refs =====" | Add-Content $report
Write-Host "`n[+] Testing Level references as GameSession+0x40 candidates..." -ForegroundColor Cyan
foreach ($ref in $levelRefs) {
    if ($ref -lt 0x40) { continue }
    $candidate = [UInt64]($ref - 0x40)
    $at40 = Read-RemotePtr ($candidate + 0x40)
    if ($null -eq $at40 -or $at40 -ne $level) { continue }

    $ready = Read-RemoteByte ($candidate + 0x28)
    $control = Read-RemotePtr ($candidate + 0x30)
    $controlReady = $null
    if ($control -and $control -ne 0) { $controlReady = Read-RemoteByte $control }

    $line = "[+] GameSession candidate=$(Hex $candidate) ref=$(Hex $ref) ready=$ready control=$(if ($control) { Hex $control } else { '<none>' }) controlReady=$controlReady"
    Write-Host $line
    $line | Add-Content $report

    if ($ready -eq 1 -and $control -and $controlReady -eq 1) {
        $gameSession = $candidate
        $pass = "[+] PASS: validated GameSession=$(Hex $gameSession) using +0x28/+0x30/+0x40 invariants."
        Write-Host $pass -ForegroundColor Green
        $pass | Add-Content $report
        break
    }
}

$minecraft = $null
$minecraftRefInClient = $null
$minecraftClientOffset = $null

if ($gameSession) {
    $sessionRefs = Find-PointerRefs $gameSession 256 'reverse chain: references to validated GameSession'
    "`n===== Minecraft candidates from GameSession refs =====" | Add-Content $report
    Write-Host "`n[+] Testing GameSession references as Minecraft+0xC0 candidates..." -ForegroundColor Cyan

    foreach ($ref in $sessionRefs) {
        if ($ref -lt 0xC0) { continue }
        $candidate = [UInt64]($ref - 0xC0)
        $atC0 = Read-RemotePtr ($candidate + 0xC0)
        if ($null -eq $atC0 -or $atC0 -ne $gameSession) { continue }
        if (-not (Is-ReadableAddress $candidate)) { continue }

        $line = "[+] Minecraft candidate=$(Hex $candidate) via field ref=$(Hex $ref)"
        Write-Host $line
        $line | Add-Content $report

        $candidateRefs = Find-PointerRefs $candidate 256 "references to Minecraft candidate $(Hex $candidate)"
        foreach ($cr in $candidateRefs) {
            if ($cr -ge $client -and $cr -lt ($client + 0x4000)) {
                $off = [UInt64]($cr - $client)
                $minecraft = $candidate
                $minecraftRefInClient = $cr
                $minecraftClientOffset = $off
                $pass = "[+] PASS: Minecraft=$(Hex $minecraft) is referenced inside ClientInstance at +0x$('{0:X}' -f $off) (field=$(Hex $cr))."
                Write-Host $pass -ForegroundColor Green
                $pass | Add-Content $report
                break
            }
        }
        if ($minecraft) { break }
    }
}

# If the exact GameSession readiness layout changed, still retain the strongest Level reference candidates for review.
if (-not $gameSession) {
    $warn = '[!] No strict GameSession candidate passed the current +0x28/+0x30/+0x40 validation.'
    Write-Host $warn -ForegroundColor Yellow
    $warn | Add-Content $report
}

if ($localVtable) {
    Find-PointerRefs $localVtable 64 'exact LocalPlayer-vtable objects (informational)' | Out-Null
}

Find-PointerRefs $client 256 'references to ClientInstance object' | Out-Null

"`n===== v4 summary =====" | Add-Content $report
$summary = @(
    "ClientInstance_vtable=$(Hex $clientVtable)",
    "ClientInstance=$(Hex $client)",
    "Level_vtable=$(Hex $levelVtable)",
    "Level=$(Hex $level)",
    "LocalPlayer_vtable=$(if ($localVtable) { Hex $localVtable } else { '<none>' })",
    "GameSession=$(if ($gameSession) { Hex $gameSession } else { '<none>' })",
    "Minecraft=$(if ($minecraft) { Hex $minecraft } else { '<none>' })",
    "Minecraft_ref_in_ClientInstance=$(if ($minecraftRefInClient) { Hex $minecraftRefInClient } else { '<none>' })",
    "ClientInstance_Minecraft_offset=$(if ($null -ne $minecraftClientOffset) { '0x{0:X}' -f $minecraftClientOffset } else { '<none>' })",
    "ClientInstance_vslot_0x1E=getRegion/BlockSource candidate",
    "ClientInstance_vslot_0x1F=getLocalPlayer candidate"
)
$summary | ForEach-Object { Write-Host "[+] $_"; $_ | Add-Content $report }

Write-Host "`n[+] Finished. Report: $report" -ForegroundColor Green
Write-Host "Send scan-report-v26.45-v4.txt back. The most important lines are PASS, GameSession, Minecraft and ClientInstance_Minecraft_offset."
