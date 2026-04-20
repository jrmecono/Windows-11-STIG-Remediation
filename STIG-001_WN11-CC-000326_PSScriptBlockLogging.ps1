<#
.SYNOPSIS
    STIG ID   : WN11-CC-000326
    Rule Title: PowerShell script block logging must be enabled on Windows 11
    Severity  : MEDIUM
    Author    : [Your Name]
    Tested On : Windows 11

.DESCRIPTION
    Script block logging captures the full decoded content of every PowerShell
    command — including obfuscated/encoded payloads used by attackers.
    Event ID 4104 is generated per script block.
    Required for SIEM detection of fileless malware, Empire, Cobalt Strike PS.

.NOTES
    Run as Administrator. No reboot required.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$modPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

Write-Host "`n======================================================" -ForegroundColor DarkCyan
Write-Host "  STIG WN11-CC-000326 | PS Script Block Logging" -ForegroundColor Cyan
Write-Host "======================================================`n" -ForegroundColor DarkCyan

# --- PRE-CHECK ---
Write-Host "[PRE-CHECK] Reading current Script Block Logging state..." -ForegroundColor Cyan
$pre = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
Write-Host "  EnableScriptBlockLogging           : $($pre.EnableScriptBlockLogging)"
Write-Host "  EnableScriptBlockInvocationLogging : $($pre.EnableScriptBlockInvocationLogging)"

# --- REMEDIATION ---
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging"           -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
Write-Host "[REMEDIATED] Script Block Logging enabled." -ForegroundColor Green

# Bonus: Module Logging
if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
Set-ItemProperty -Path $modPath -Name "EnableModuleLogging" -Value 1 -Type DWord
Write-Host "[REMEDIATED] Module Logging also enabled (bonus coverage)." -ForegroundColor Green

# --- VERIFICATION ---
$val = (Get-ItemProperty -Path $regPath).EnableScriptBlockLogging
if ($val -eq 1) {
    Write-Host "[VERIFIED] PASSED — Script Block Logging is ENABLED. Event ID 4104 active.`n" -ForegroundColor Green
} else {
    Write-Host "[VERIFIED] FAILED — Script Block Logging NOT enabled!`n" -ForegroundColor Red
    exit 1
}
