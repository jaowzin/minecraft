$ErrorActionPreference = 'Continue'

$scanner = Join-Path $PSScriptRoot 'BedrockScanner.exe'
if (-not (Test-Path $scanner)) {
    Write-Host "BedrockScanner.exe must be in the same folder as this script." -ForegroundColor Red
    exit 1
}

$report = Join-Path $PSScriptRoot 'scan-report-v26.45-v3.txt'
"Bedrock v26.45 discovery report v3 - $(Get-Date -Format o)" | Set-Content $report

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
    param(
        [string]$Name,
        [string]$Pattern
    )

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

function Find-LiveObject {
    param(
        [string]$Name,
        [UInt64]$VTable
    )

    $header = "`n===== live $Name objects ====="
    Write-Host $header -ForegroundColor Cyan
    $header | Add-Content $report

    $output = Run-Scanner @('--pointer', (Hex $VTable), '--limit', '64')
    $matches = [regex]::Matches($output, '(?m)^\s+\[\d+\]\s+(0x[0-9A-Fa-f]+)\s*$')
    if ($matches.Count -eq 0) {
        Write-Host "[-] No live $Name object found by first-vtable-pointer scan." -ForegroundColor Yellow
        return $null
    }

    $value = [Convert]::ToUInt64($matches[0].Groups[1].Value.Substring(2), 16)
    Write-Host "[+] $Name object = $(Hex $value)" -ForegroundColor Green
    return $value
}

function Read-RemoteBytes {
    param(
        [UInt64]$Address,
        [int]$Count
    )

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

function Print-PtrField {
    param(
        [string]$Owner,
        [UInt64]$Base,
        [UInt64]$Offset,
        [string]$Name
    )

    $address = $Base + $Offset
    $value = Read-RemotePtr $address
    if ($null -eq $value) {
        $line = "[-] $Owner+$('{0:X}' -f $Offset) $Name = <read failed>"
    } else {
        $line = "[+] $Owner+$('{0:X}' -f $Offset) $Name = $(Hex $value)"
    }
    Write-Host $line
    $line | Add-Content $report
    return $value
}

Write-Host "[+] Capturing module/section fingerprint..."
Run-Scanner @() | Out-Null

# Anchors verified to match the user's 1.26.4501.0 build in the v2 run.
$clientVtablePattern = '48 8D 05 ?? ?? ?? ?? 49 89 45 00 48 8D 05 ?? ?? ?? ?? 49 89 45 18 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 49 89 85 ?? ?? ?? ??'
$levelVtablePattern  = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 05 ?? ?? ?? ?? 48 89 47 18 48 8D 05 ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 89 47 20'
$localVtablePattern  = '48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 87 08 0F 00 00 48 89 85 ?? ?? ?? ?? C6 87 30 0F 00 00 00 C6 87 39 0F 00 00 00'

$clientVtable = Resolve-VTable 'ClientInstance_vtable' $clientVtablePattern
$levelVtable  = Resolve-VTable 'Level_vtable' $levelVtablePattern
$localVtable  = Resolve-VTable 'LocalPlayer_vtable' $localVtablePattern

if ($null -eq $clientVtable -or $null -eq $levelVtable) {
    Write-Host "[-] Required vtable anchors were not found; stopping v3 chain validation." -ForegroundColor Red
    exit 2
}

$client = Find-LiveObject 'ClientInstance' $clientVtable
$levelByVtable = Find-LiveObject 'Level' $levelVtable

if ($null -eq $client) {
    Write-Host "[-] No ClientInstance object was found; make sure you are already inside a world." -ForegroundColor Red
    exit 3
}

"`n===== ClientInstance vtable slots =====" | Add-Content $report
Write-Host "`n[+] Dumping ClientInstance vslot 0x1E (getRegion / BlockSource candidate)" -ForegroundColor Cyan
Run-Scanner @('--vslot', (Hex $clientVtable), '0x1E') | Out-Null
Write-Host "[+] Dumping ClientInstance vslot 0x1F (getLocalPlayer candidate)" -ForegroundColor Cyan
Run-Scanner @('--vslot', (Hex $clientVtable), '0x1F') | Out-Null

"`n===== ClientInstance known-field probe =====" | Add-Content $report
Write-Host "`n[+] Reading current 1.26.x ClientInstance field candidates..." -ForegroundColor Cyan
$mcGame       = Print-PtrField 'ClientInstance' $client 0x1A0 'MinecraftGame*'
$minecraft    = Print-PtrField 'ClientInstance' $client 0x1A8 'Minecraft*'
$levelRenderer= Print-PtrField 'ClientInstance' $client 0x1B8 'LevelRenderer*'
$packetSender = Print-PtrField 'ClientInstance' $client 0x1C8 'PacketSender*'
$inputHandler = Print-PtrField 'ClientInstance' $client 0x1D8 'InputHandler*'

Write-Host "`n[+] Dumping ClientInstance range 0x180..0x1FF" -ForegroundColor Cyan
"`n===== ClientInstance +0x180 dump =====" | Add-Content $report
Run-Scanner @('--dump', (Hex ($client + 0x180)), '128') | Out-Null

# Current Necromancer 1.26.x layout:
# Minecraft+0xC0 -> GameSession*
# Minecraft+0xD8 -> Timer*
# GameSession+0x28 == 1
# GameSession+0x30 -> control block whose first byte == 1
# GameSession+0x40 -> Level*
$levelFromChain = $null
if ($minecraft -and $minecraft -ne 0) {
    "`n===== Minecraft -> GameSession -> Level chain =====" | Add-Content $report
    Write-Host "`n[+] Following Minecraft -> GameSession -> Level..." -ForegroundColor Cyan

    $gameSession = Print-PtrField 'Minecraft' $minecraft 0xC0 'GameSession*'
    $timer       = Print-PtrField 'Minecraft' $minecraft 0xD8 'Timer*'

    if ($gameSession -and $gameSession -ne 0) {
        $ready = Read-RemoteByte ($gameSession + 0x28)
        $control = Read-RemotePtr ($gameSession + 0x30)
        $levelFromChain = Read-RemotePtr ($gameSession + 0x40)

        $readyText = if ($null -eq $ready) { '<read failed>' } else { $ready.ToString() }
        $controlText = if ($null -eq $control) { '<read failed>' } else { Hex $control }
        $levelText = if ($null -eq $levelFromChain) { '<read failed>' } else { Hex $levelFromChain }

        $line1 = "[+] GameSession+0x28 ready byte = $readyText"
        $line2 = "[+] GameSession+0x30 control block = $controlText"
        $line3 = "[+] GameSession+0x40 Level* = $levelText"
        Write-Host $line1; $line1 | Add-Content $report
        Write-Host $line2; $line2 | Add-Content $report
        Write-Host $line3; $line3 | Add-Content $report

        if ($control -and $control -ne 0) {
            $controlReady = Read-RemoteByte $control
            $controlReadyText = if ($null -eq $controlReady) { '<read failed>' } else { $controlReady.ToString() }
            $line = "[+] *controlBlock first byte = $controlReadyText"
            Write-Host $line
            $line | Add-Content $report
        }

        Write-Host "[+] Dumping first 128 bytes of GameSession" -ForegroundColor Cyan
        "`n===== GameSession first 128 bytes =====" | Add-Content $report
        Run-Scanner @('--dump', (Hex $gameSession), '128') | Out-Null
    }

    Write-Host "[+] Dumping first 256 bytes of Minecraft object" -ForegroundColor Cyan
    "`n===== Minecraft first 256 bytes =====" | Add-Content $report
    Run-Scanner @('--dump', (Hex $minecraft), '256') | Out-Null
}

"`n===== Level validation =====" | Add-Content $report
if ($levelFromChain -and $levelFromChain -ne 0) {
    $levelFirstPtr = Read-RemotePtr $levelFromChain
    $line = "[+] Level from chain = $(Hex $levelFromChain), first pointer/vtable = $(if ($null -eq $levelFirstPtr) {'<read failed>'} else {Hex $levelFirstPtr})"
    Write-Host $line
    $line | Add-Content $report

    if ($levelByVtable -and $levelFromChain -eq $levelByVtable) {
        $line = '[+] PASS: Minecraft->GameSession->Level matches the independently located live Level object.'
        Write-Host $line -ForegroundColor Green
        $line | Add-Content $report
    } elseif ($levelFirstPtr -and $levelFirstPtr -eq $levelVtable) {
        $line = '[+] PASS: Level from the object chain has the resolved Level vtable.'
        Write-Host $line -ForegroundColor Green
        $line | Add-Content $report
    } else {
        $line = '[!] Level chain did not exactly match the independent vtable object; keep it as a candidate until reviewed.'
        Write-Host $line -ForegroundColor Yellow
        $line | Add-Content $report
    }

    Write-Host "[+] Finding writable references to the live Level object..." -ForegroundColor Cyan
    "`n===== references to Level object =====" | Add-Content $report
    Run-Scanner @('--pointer', (Hex $levelFromChain), '--limit', '128') | Out-Null

    Write-Host "[+] Dumping first 256 bytes of Level" -ForegroundColor Cyan
    "`n===== Level first 256 bytes =====" | Add-Content $report
    Run-Scanner @('--dump', (Hex $levelFromChain), '256') | Out-Null
}

if ($localVtable) {
    Write-Host "`n[+] Checking for exact LocalPlayer-vtable objects again (informational only)..." -ForegroundColor Cyan
    "`n===== LocalPlayer exact-vtable pointer scan =====" | Add-Content $report
    Run-Scanner @('--pointer', (Hex $localVtable), '--limit', '64') | Out-Null
}

Write-Host "`n[+] Finding references to the ClientInstance object itself..." -ForegroundColor Cyan
"`n===== references to ClientInstance object =====" | Add-Content $report
Run-Scanner @('--pointer', (Hex $client), '--limit', '128') | Out-Null

"`n===== v3 summary =====" | Add-Content $report
$summary = @(
    "ClientInstance_vtable=$(Hex $clientVtable)",
    "ClientInstance=$(Hex $client)",
    "Level_vtable=$(Hex $levelVtable)",
    "Level_by_vtable=$(if ($levelByVtable) { Hex $levelByVtable } else { '<none>' })",
    "Minecraft=$(if ($minecraft) { Hex $minecraft } else { '<none>' })",
    "Level_from_chain=$(if ($levelFromChain) { Hex $levelFromChain } else { '<none>' })",
    "ClientInstance_vslot_0x1E=getRegion/BlockSource candidate",
    "ClientInstance_vslot_0x1F=getLocalPlayer candidate"
)
$summary | ForEach-Object { Write-Host "[+] $_"; $_ | Add-Content $report }

Write-Host "`n[+] Finished. Report: $report" -ForegroundColor Green
Write-Host "Send scan-report-v26.45-v3.txt back. The key lines are the known-field probe, Minecraft->GameSession->Level chain, PASS/FAIL validation, and the summary."
