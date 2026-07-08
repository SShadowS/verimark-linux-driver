<#
.SYNOPSIS
    Unpair / de-provision the Kensington VeriMark Desktop (USB 047d:00f2) on Windows so the
    NEXT "set up fingerprint" runs a FULL fresh pairing + host-authorization from scratch.

.DESCRIPTION
    The Synaptics WUDF driver pairs the sensor ONCE (VCSFW 0x93) and persists the pairing data
    to the registry (HKU\...\Software\Synaptics\PairingData\<sensorId>). On every later boot it
    reuses that stored data and SKIPS pairing — which is why our USB captures never contained the
    pairing/authorization exchange.

    This script wipes that stored pairing state (plus the Windows Hello biometric DB and the PnP
    device instance) so that the next Hello "Add fingerprint" makes this machine look like a
    brand-new host to the sensor. The sensor then re-runs the additive per-host authorization —
    exactly the step we need to capture (USBPcap + Frida CNG hook) to reproduce on Linux.

    Everything it deletes is either re-created by Windows on re-setup or backed up first. Intended
    for a DEBUG Windows box where losing the fingerprint setup is acceptable.

.NOTES
    Run in an elevated PowerShell (it self-elevates). After it finishes: unplug/replug the reader,
    start your capture, then go to Settings > Accounts > Sign-in options > Fingerprint > Set up.
#>

[CmdletBinding()]
param(
    [switch]$KeepHelloDb,     # skip clearing the WinBio biometric database
    [switch]$KeepDevice,      # skip removing the PnP device instance
    [string]$BackupDir = "$env:USERPROFILE\Desktop\verimark-unpair-backup"
)

# ---- self-elevate ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v) { $psi += " -$k" } } else { $psi += " -$k `"$v`"" }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $psi
    return
}

$VID_PID = "VID_047D&PID_00F2"
function Log($m, $c = "Gray") { Write-Host "[*] $m" -ForegroundColor $c }
function Ok($m)  { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

Write-Host "`n=== VeriMark Desktop (047d:00f2) unpair / de-provision ===`n" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
Log "Backups -> $BackupDir"

# ------------------------------------------------------------------
# 1. Delete the Synaptics pairing data from EVERY user hive (the key step)
# ------------------------------------------------------------------
Write-Host "`n--- 1. Synaptics pairing registry ---" -ForegroundColor Cyan

# Ensure all user hives are mounted under HKEY_USERS, then walk them + HKLM.
$hiveRoots = @()
Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -notmatch '_Classes$' } |
    ForEach-Object { $hiveRoots += "Registry::HKEY_USERS\$($_.PSChildName)" }
$hiveRoots += "Registry::HKEY_LOCAL_MACHINE"

$found = $false
foreach ($root in $hiveRoots) {
    foreach ($sub in @("Software\Synaptics\PairingData",
                       "Software\WOW6432Node\Synaptics\PairingData",
                       "Software\Synaptics")) {
        $key = Join-Path $root $sub
        if (Test-Path $key) {
            $found = $true
            $safe  = ($key -replace 'Registry::','' -replace '[\\:]','_')
            $bkp   = Join-Path $BackupDir "$safe.reg"
            # export via reg.exe (needs the non-Registry:: form)
            $regPath = $key -replace 'Registry::',''
            & reg.exe export "$regPath" "$bkp" /y 2>$null | Out-Null
            Log "  backing up + deleting: $regPath"
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $key)) { Ok "  deleted $sub" } else { Warn "  could NOT delete $key (in use?)" }
        }
    }
}
if (-not $found) { Warn "  No Synaptics PairingData keys found (already unpaired, or driver stores elsewhere)." }

# Also drop the WUDF-side failure counters / provisioning bookkeeping if present.
foreach ($root in $hiveRoots) {
    $k = Join-Path $root "Software\Synaptics"
    if (Test-Path $k) {
        Get-ChildItem $k -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($vn in @("SetOwnershipFailureCount","IptProvisionFailureCount",
                              "DeviceInitializeFailures","PairingInProcess","PairingContext")) {
                if ($null -ne (Get-ItemProperty -Path $_.PSPath -Name $vn -ErrorAction SilentlyContinue)) {
                    Remove-ItemProperty -Path $_.PSPath -Name $vn -Force -ErrorAction SilentlyContinue
                    Log "  cleared value $vn under $($_.PSChildName)"
                }
            }
        }
    }
}

# ------------------------------------------------------------------
# 2. Clear the Windows Hello biometric database (all users)
# ------------------------------------------------------------------
if (-not $KeepHelloDb) {
    Write-Host "`n--- 2. Windows Hello biometric database ---" -ForegroundColor Cyan
    $dbDir = "$env:WINDIR\System32\WinBioDatabase"
    try {
        Log "  stopping WbioSrvc..."
        Stop-Service WbioSrvc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        if (Test-Path $dbDir) {
            $files = Get-ChildItem $dbDir -File -ErrorAction SilentlyContinue
            if ($files) {
                Copy-Item $dbDir -Destination (Join-Path $BackupDir "WinBioDatabase") -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    & takeown.exe /f "$($f.FullName)" 2>$null | Out-Null
                    & icacls.exe "$($f.FullName)" /grant "Administrators:F" 2>$null | Out-Null
                    Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                }
                Ok "  cleared $($files.Count) biometric DB file(s)"
            } else { Log "  DB dir empty" }
        } else { Log "  no WinBioDatabase dir (MOC device keeps templates on-chip)" }
    } finally {
        Log "  starting WbioSrvc..."
        Start-Service WbioSrvc -ErrorAction SilentlyContinue
    }
} else { Warn "Skipping Hello DB clear (-KeepHelloDb)" }

# ------------------------------------------------------------------
# 3. Remove the PnP device instance so it re-enumerates + re-inits fresh
# ------------------------------------------------------------------
if (-not $KeepDevice) {
    Write-Host "`n--- 3. PnP device instance ---" -ForegroundColor Cyan
    $devs = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "*$VID_PID*" }
    if ($devs) {
        foreach ($d in $devs) {
            Log "  $($d.FriendlyName)  [$($d.Status)]  $($d.InstanceId)"
            & pnputil.exe /remove-device "$($d.InstanceId)" 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                # fallback to the cmdlet
                try { Remove-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop; Ok "  removed (cmdlet)" }
                catch { Warn "  remove failed: $_" }
            } else { Ok "  removed via pnputil" }
        }
        Log "  rescanning for hardware changes..."
        & pnputil.exe /scan-devices 2>$null | Out-Null
    } else {
        Warn "  Device $VID_PID not currently present. Plug it in, then it will re-enumerate clean."
    }
} else { Warn "Skipping device removal (-KeepDevice)" }

# ------------------------------------------------------------------
# done
# ------------------------------------------------------------------
Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host @"

Next steps to CAPTURE the fresh pairing + authorization:
  1. UNPLUG the VeriMark, wait 3s, PLUG it back in (forces a clean driver init).
  2. Start your USB capture (USBPcap / Wireshark on the reader's device) AND the Frida CNG
     hook against the WUDF host process (WUDFHost.exe) for the in-TLS plaintext.
  3. Settings > Accounts > Sign-in options > Fingerprint recognition > Set up  ->  enroll a finger.
     (This machine now has NO stored pairing, so the driver runs 0x93 pairing + the additive
      host-authorization from scratch — the exact sequence we need.)
  4. Stop captures; copy the pcap + Frida log back to Linux for diffing.

Backups saved in: $BackupDir  (registry .reg exports + WinBioDatabase copy)
"@ -ForegroundColor Cyan
